#include <locale.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "dm.h"
#include "verity_hash.h"
#include "crypt.h"
#include "mount.h"
#include "utils.h"

#include "common.h"

typedef struct {
	gchar *tmpdir;
} DMFixture;

typedef struct {
	uint64_t data_size;
	uint64_t combined_size;
} DMData;

static void dm_fixture_set_up(DMFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_test_message("dm tmpdir: %s\n", fixture->tmpdir);
}

static void dm_fixture_tear_down(DMFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static guint readable_sectors(int fd, GBytes *original)
{
	g_autofree guint8 *buf = NULL;
	ssize_t r;
	guint sectors = 0;

	/* O_DIRECT needs paged-aligned memory */
	buf = aligned_alloc(4096, 4096);

	lseek(fd, 0, SEEK_SET);

	for (guint sector = 0;; sector++) {
		r = pread(fd, buf, 4096, sector*4096);
		if (r == 0)
			break;
		else if (r == 4096) {
			gsize offset = sector*4096;
			sectors++;

			g_assert_cmpint(offset, <=, g_bytes_get_size(original));
			if (memcmp(buf, (guint8 *)(g_bytes_get_data(original, NULL))+offset, 4096) != 0) {
				g_test_message("modified data read via dm-verity at sector %u", sector);
			} else {
				g_test_message("correct data read via dm-verity at sector %u", sector);
			}
		}
	}
	return sectors;
}

static guint num_diff_sectors(int fd_a, int fd_b, guint sectors)
{
	g_autofree guint8 *buf_a = NULL;
	g_autofree guint8 *buf_b = NULL;
	guint diff_sectors = 0;

	/* O_DIRECT needs paged-aligned memory */
	buf_a = aligned_alloc(4096, 4096);
	buf_b = aligned_alloc(4096, 4096);

	lseek(fd_a, 0, SEEK_SET);
	lseek(fd_b, 0, SEEK_SET);

	for (guint sector = 0; sector < sectors; sector++) {
		ssize_t r_a, r_b;

		r_a = pread(fd_a, buf_a, 4096, sector*4096);
		r_b = pread(fd_b, buf_b, 4096, sector*4096);
		if (r_a != r_b)
			return sectors - sector;

		if (r_a == 0)
			return sectors - sector + diff_sectors;

		if (r_a != 4096)
			return sectors - sector + diff_sectors;

		if (memcmp(buf_a, buf_b, r_a) != 0)
			diff_sectors++;
	}

	return diff_sectors;
}

static int open_loop_verity(int bundlefd, off_t loop_size, off_t data_size, gchar *root_digest, gchar *salt, GError **error)
{
	GError *ierror = NULL;
	gboolean res;
	g_autoptr(RaucDM) dm_verity = NULL;
	int loopfd = -1;
	g_autofree gchar *loopname = NULL;
	int fd = -1;

	g_assert_cmpint(bundlefd, >, 0);

	res = r_setup_loop(bundlefd, &loopfd, &loopname, loop_size, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(loopname);

	dm_verity = r_dm_new_verity();
	dm_verity->lower_dev = g_strdup(loopname);
	dm_verity->data_size = data_size;
	dm_verity->root_digest = g_strdup(root_digest);
	dm_verity->salt = g_strdup(salt);

	res = r_dm_setup(dm_verity, &ierror);
	g_close(loopfd, NULL);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	g_assert_nonnull(dm_verity->upper_dev);

	fd = g_open(dm_verity->upper_dev, O_RDONLY|O_CLOEXEC|O_DIRECT, 0);
	g_assert_cmpint(fd, >, 0);

	res = r_dm_remove(dm_verity, TRUE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

out:
	return fd;
}

static int open_loop_crypt(int bundlefd, off_t loop_size, off_t data_size, const gchar *key, GError **error)
{
	GError *ierror = NULL;
	gboolean res;
	g_autoptr(RaucDM) dm_crypt = NULL;
	int loopfd = -1;
	g_autofree gchar *loopname = NULL;
	int fd = -1;

	g_assert_cmpint(bundlefd, >, 0);

	res = r_setup_loop(bundlefd, &loopfd, &loopname, loop_size, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(loopname);

	dm_crypt = r_dm_new_crypt();
	dm_crypt->lower_dev = g_strdup(loopname);
	dm_crypt->data_size = data_size;
	dm_crypt->key = g_strdup(key);

	res = r_dm_setup(dm_crypt, &ierror);
	g_close(loopfd, NULL);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	g_assert_nonnull(dm_crypt->upper_dev);

	fd = g_open(dm_crypt->upper_dev, O_RDONLY|O_CLOEXEC|O_DIRECT, 0);
	g_assert_cmpint(fd, >, 0);

	res = r_dm_remove(dm_crypt, TRUE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

out:
	return fd;
}

static void dm_verity_simple_test(void)
{
	GError *error = NULL;
	gboolean res;
	g_autoptr(RaucDM) dm_verity = NULL;
	int datafd = -1;
	int loopfd = -1;
	g_autofree gchar *loopname = NULL;
	int fd = -1;
	guchar buf[4096];

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	datafd = g_open("test/dummy.verity", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(datafd, >, 0);

	res = r_setup_loop(datafd, &loopfd, &loopname, 4096*132, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_nonnull(loopname);
	g_close(datafd, NULL);

	dm_verity = r_dm_new_verity();
	dm_verity->lower_dev = g_strdup(loopname);
	dm_verity->data_size = 4096*129;
	dm_verity->root_digest = g_strdup("3049cbffaa49c6dc12e9cd1dd4604ef5a290e3d13b379c5a50d356e68423de23");
	dm_verity->salt = g_strdup("799ea94008bbdc6555d7895d1b647e2abfd213171f0e8b670e1da951406f4691");

	res = r_dm_setup(dm_verity, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_close(loopfd, NULL);

	g_assert_nonnull(dm_verity->upper_dev);

	fd = g_open(dm_verity->upper_dev, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >, 0);

	res = r_dm_remove(dm_verity, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	for (int i = 0; i < 129; i++) {
		int r = read(fd, buf, sizeof(buf));
		g_assert_cmpint(r, ==, 4096);
		g_assert_cmpint(buf[0], ==, 0);
		g_assert_cmpint(buf[1], ==, 0);
		g_assert_cmpint(buf[2], ==, 0);
		g_assert_cmpint(buf[3], ==, i);
	}

	g_close(fd, NULL);
}

static void verity_hash_test(void)
{
	int ret, bundlefd;
	g_autofree guint8 *root_hash = r_hex_decode("3049cbffaa49c6dc12e9cd1dd4604ef5a290e3d13b379c5a50d356e68423de23", 32);
	g_autofree guint8 *salt = r_hex_decode("799ea94008bbdc6555d7895d1b647e2abfd213171f0e8b670e1da951406f4691", 32);

	bundlefd = g_open("test/dummy.verity", O_RDONLY);
	g_assert_cmpint(bundlefd, >, 0);

	ret = r_verity_hash_verify(bundlefd, 129, root_hash, salt);
	g_assert_cmpint(ret, ==, 0);

	g_close(bundlefd, NULL);
}

/* Tests encrypting the known payload 'dummy.unencrypted' with
 * r_crypt_encrypt() by comparing the result against the manually generated
 * encrypted version 'dummy.encrypted'.
 */
static void crypt_encrypt_test(DMFixture *fixture,
		gconstpointer user_data)
{
	gboolean *valid_key = (gboolean *)user_data;
	gboolean ret = FALSE;
	g_autofree guint8 *key = NULL;
	g_autofree gchar *encrypted = NULL;
	GError *error = NULL;
	int fd = -1, fd_comp = -1;

	if (*valid_key)
		key = r_hex_decode("761305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab5", 32);
	else
		key = r_hex_decode("61305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab57", 32);

	encrypted = g_build_filename(fixture->tmpdir, "encrypted", NULL);
	g_assert_nonnull(encrypted);

	ret = r_crypt_encrypt("test/dummy.unencrypted", encrypted, key, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	fd = g_open(encrypted, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >, 0);

	fd_comp = g_open("test/dummy.encrypted", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd_comp, >, 0);

	if (*valid_key)
		g_assert_cmpint(num_diff_sectors(fd, fd_comp, 3), ==, 0);
	else
		g_assert_cmpint(num_diff_sectors(fd, fd_comp, 3), ==, 3);

	g_close(fd, NULL);
	g_close(fd_comp, NULL);
}

/* Tests decrypting the known encrypted payload 'dummy.encrypted' with
 * r_crypt_decrypt() by comparing the result against the known scheme of the
 * source data.
 */
static void crypt_decrypt_test(DMFixture *fixture,
		gconstpointer user_data)
{
	gboolean *valid_key = (gboolean *)user_data;
	gboolean ret = FALSE;
	g_autofree guint8 *key = NULL;
	g_autofree gchar *decrypted = NULL;
	GError *error = NULL;
	int fd = -1, fd_comp = -1;

	if (*valid_key)
		key = r_hex_decode("761305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab5", 32);
	else
		key = r_hex_decode("61305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab57", 32);

	decrypted = g_build_filename(fixture->tmpdir, "decrypted", NULL);
	g_assert_nonnull(decrypted);

	ret = r_crypt_decrypt("test/dummy.encrypted", decrypted, key, 0, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	fd = g_open(decrypted, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >, 0);

	fd_comp = g_open("test/dummy.unencrypted", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd_comp, >, 0);

	if (*valid_key)
		g_assert_cmpint(num_diff_sectors(fd, fd_comp, 3), ==, 0);
	else
		g_assert_cmpint(num_diff_sectors(fd, fd_comp, 3), ==, 3);

	g_close(fd, NULL);
}

static void verity_hash_create(DMFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	const DMData *dm_data = user_data;
	g_autoptr(GBytes) data = NULL;
	int ret, bundlefd;
	guint8 root_hash[32] = {0};
	g_autofree gchar *filename = NULL;
	g_autofree gchar *root_hash_hex = NULL;
	g_autofree guint8 *salt = random_bytes(32, 0xd6368505);
	g_autofree gchar *salt_hex = r_hex_encode(salt, 32);
	uint64_t combined_size;
	int dmfd = -1;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	filename = write_random_file(fixture->tmpdir, "data", 4096*dm_data->data_size, 0x0fdfc761);
	g_assert_nonnull(filename);

	data = read_file(filename, &error);
	g_assert_no_error(error);
	g_assert_nonnull(data);

	bundlefd = g_open(filename, O_RDWR);
	g_assert_cmpint(bundlefd, >, 0);

	/* create verity file */
	ret = r_verity_hash_create(bundlefd, dm_data->data_size, &combined_size, root_hash, salt);
	g_assert_cmpint(ret, ==, 0);
	g_assert_cmpint(combined_size, ==, dm_data->combined_size);
	root_hash_hex = r_hex_encode(root_hash, 32);

	/* check unmodified verity file */
	ret = r_verity_hash_verify(bundlefd, dm_data->data_size, root_hash, salt);
	g_assert_cmpint(ret, ==, 0);

	/* open via kernel loopback device and dm-verity */
	dmfd = open_loop_verity(bundlefd, 4096*dm_data->combined_size, 4096*dm_data->data_size, root_hash_hex, salt_hex, &error);
	g_assert_no_error(error);
	g_assert_cmpint(dmfd, >=, 0);

	/* check that everything is readable */
	g_assert_cmpint(readable_sectors(dmfd, data), ==, dm_data->data_size);

	g_test_message("checking error detection in the first sector");
	/* flip one bit in the first sector */
	flip_bits_filename(filename, 0, 0x01);

	/* check that the bit flip in the first sector is detected by the userspace check */
	ret = r_verity_hash_verify(bundlefd, dm_data->data_size, root_hash, salt);
	g_assert_cmpint(ret, !=, 0);

	/* check that only the affected sector is unreadable */
	g_assert_cmpint(readable_sectors(dmfd, data), ==, dm_data->data_size - 1);

	g_close(dmfd, NULL);

	/* retry opening the modified verity file */
	dmfd = open_loop_verity(bundlefd, 4096*dm_data->combined_size, 4096*dm_data->data_size, root_hash_hex, salt_hex, &error);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_IO);
	g_assert_cmpstr(error->message, ==, "Check read from dm-verity device failed: Input/output error");
	g_assert_cmpint(dmfd, ==, -1);
	g_clear_error(&error);

	/* restore the first sector */
	flip_bits_filename(filename, 0, 0x01);

	if (dm_data->data_size >= 128) {
		g_test_message("checking error detection in another sector");

		/* flip one bit */
		flip_bits_filename(filename, 4096*127, 0x01);

		/* open via kernel loopback device and dm-verity */
		dmfd = open_loop_verity(bundlefd, 4096*dm_data->combined_size, 4096*dm_data->data_size, root_hash_hex, salt_hex, &error);
		g_assert_no_error(error);
		g_assert_cmpint(dmfd, >=, 0);

		/* check that only the affected sector is unreadable */
		g_assert_cmpint(readable_sectors(dmfd, data), ==, dm_data->data_size - 1);

		/* check that the bit flip is detected by the userspace check */
		ret = r_verity_hash_verify(bundlefd, dm_data->data_size, root_hash, salt);
		g_assert_cmpint(ret, !=, 0);

		g_close(dmfd, NULL);
	}

	g_close(bundlefd, NULL);
}

static void crypt_create(DMFixture *fixture,
		gconstpointer user_data)
{
	int bundlefd = -1;
	int enc_bundlefd = -1;
	g_autoptr(GError) error = NULL;
	g_autofree gchar *filename = NULL;
	g_autofree gchar *enc_filename = NULL;
	const gchar *key = "761305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab5";
	const gchar *invalid_key = "161305cf2de9a8ff1708eac74676c606630425b22bb8212e5e2314e3e61e8ab5";
	g_autofree guint8 *key_bin = NULL;
	gboolean res = FALSE;
	int dmfd = -1;
	guint64 data_size = 50*4096;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	filename = write_random_file(fixture->tmpdir, "data", data_size, 0x0fdfc761);
	g_assert_nonnull(filename);

	enc_filename = g_build_filename(fixture->tmpdir, "encrypt", NULL);
	g_assert_nonnull(enc_filename);

	key_bin = r_hex_decode(key, 32);
	res = r_crypt_encrypt(filename, enc_filename, key_bin, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	bundlefd = g_open(filename, O_RDWR);
	g_assert_cmpint(bundlefd, >, 0);

	enc_bundlefd = g_open(enc_filename, O_RDWR);
	g_assert_cmpint(enc_bundlefd, >, 0);

	dmfd = open_loop_crypt(enc_bundlefd, data_size, data_size, key, &error);
	g_assert_no_error(error);
	g_assert_cmpint(dmfd, >=, 0);

	/* check that everything decrypted is valid */
	g_assert_cmpint(num_diff_sectors(dmfd, bundlefd, 50), ==, 0);

	g_test_message("checking wrong encryption data error in the first sector");
	/* flip one bit in the first sector */
	flip_bits_filename(enc_filename, 0, 0x01);

	g_close(dmfd, NULL);

	dmfd = open_loop_crypt(enc_bundlefd, data_size, data_size, key, &error);
	g_assert_no_error(error);
	g_assert_cmpint(dmfd, >=, 0);

	/* check that different sector is invalid */
	g_assert_cmpint(num_diff_sectors(dmfd, bundlefd, 50), ==, 1);

	g_close(dmfd, NULL);

	/* restore one bit in the first sector */
	flip_bits_filename(enc_filename, 0, 0x01);

	dmfd = open_loop_crypt(enc_bundlefd, data_size, data_size, invalid_key, &error);
	g_assert_no_error(error);
	g_assert_cmpint(dmfd, >=, 0);

	/* check that decrypted is invalid */
	g_assert_cmpint(num_diff_sectors(dmfd, bundlefd, 50), ==, 50);

	g_close(dmfd, NULL);
}

int main(int argc, char *argv[])
{
	DMData *dm_data;
	gboolean valid_key;

	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/dm/verity_simple", dm_verity_simple_test);
	g_test_add_func("/dm/verity_hash", verity_hash_test);

	dm_data = &(DMData) {
		.data_size = 1,
		.combined_size = 1,
	};
	g_test_add("/dm/create_1", DMFixture, dm_data, dm_fixture_set_up, verity_hash_create, dm_fixture_tear_down);

	dm_data = &(DMData) {
		.data_size = 2,
		.combined_size = 2+1,
	};
	g_test_add("/dm/create_2", DMFixture, dm_data, dm_fixture_set_up, verity_hash_create, dm_fixture_tear_down);

	dm_data = &(DMData) {
		.data_size = 128,
		.combined_size = 128+1,
	};
	g_test_add("/dm/create_128", DMFixture, dm_data, dm_fixture_set_up, verity_hash_create, dm_fixture_tear_down);

	dm_data = &(DMData) {
		.data_size = 257,
		.combined_size = 257+3+1,
	};
	g_test_add("/dm/create_257", DMFixture, dm_data, dm_fixture_set_up, verity_hash_create, dm_fixture_tear_down);

	valid_key = TRUE;
	g_test_add("/dm/crypt_decrypt/valid_key", DMFixture, &valid_key, dm_fixture_set_up, crypt_decrypt_test, dm_fixture_tear_down);
	valid_key = FALSE;
	g_test_add("/dm/crypt_decrypt/invalid_key", DMFixture, &valid_key, dm_fixture_set_up, crypt_decrypt_test, dm_fixture_tear_down);

	valid_key = TRUE;
	g_test_add("/dm/crypt_encrypt/valid_key", DMFixture, &valid_key, dm_fixture_set_up, crypt_encrypt_test, dm_fixture_tear_down);
	valid_key = FALSE;
	g_test_add("/dm/crypt_encrypt/invalid_key", DMFixture, &valid_key, dm_fixture_set_up, crypt_encrypt_test, dm_fixture_tear_down);

	g_test_add("/dm/crypt_create", DMFixture, NULL, dm_fixture_set_up, crypt_create, dm_fixture_tear_down);

	return g_test_run();
}
