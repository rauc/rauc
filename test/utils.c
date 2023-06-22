#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

static void whitespace_removed_test(void)
{
	gchar *str;

	str = g_strdup("foo");
	g_assert_false(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("\r\n\t  foo  \t\r\n");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);
}

static void get_sectorsize_test(void)
{
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	guint size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_sectorsize(fd);
	g_assert_cmpint(size, ==, 512);

	if (fd >= 0)
		g_close(fd, NULL);
}

static void get_device_size_test(void)
{
	GError *error = NULL;
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	goffset size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_device_size(fd, &error);
	g_assert_no_error(error);
	g_assert_cmpint(size, ==, 64<<20); /* 64MiB */

	if (fd >= 0)
		g_close(fd, NULL);
}

static void update_symlink_test(void)
{
	g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_autoptr(GError) error = NULL;
	g_autofree gchar *name_bad = g_build_filename(tmpdir, "missing/s0", NULL);
	g_autofree gchar *name_s1 = g_build_filename(tmpdir, "s1", NULL);
	g_autofree gchar *name_s1_tmp = g_build_filename(tmpdir, "s1.tmp-link", NULL);
	g_autofree gchar *target = NULL;
	struct stat stat_orig = {}, stat_new = {};
	gboolean res = FALSE;

	/* test invalid name */
	res = r_update_symlink("target", name_bad, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_clear_error(&error);

	/* test with directory blocking the symlink name */
	g_assert_cmpint(mkdir(name_s1, 0), ==, 0);

	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_INVAL);
	g_clear_error(&error);

	g_assert_true(g_file_test(name_s1, G_FILE_TEST_IS_DIR));

	g_assert_cmpint(rmdir(name_s1), ==, 0);

	/* test nonexistent symlink */
	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_0");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_orig), ==, 0);

	/* test update with same target */
	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_0");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_new), ==, 0);
	g_assert_cmpuint(stat_orig.st_ino, ==, stat_new.st_ino);

	/* test update with different target */
	res = r_update_symlink("target_1", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_1");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_new), ==, 0);
	g_assert_cmpuint(stat_orig.st_ino, !=, stat_new.st_ino);

	/* test with a directory blocking the tmp name */
	g_assert_cmpint(mkdir(name_s1_tmp, 0), ==, 0);

	res = r_update_symlink("target_2", name_s1, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST);
	g_assert_cmpstr(error->message, ==, "Failed to create symlink: File exists");
	g_clear_error(&error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_1");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/utils/whitespace_removed", whitespace_removed_test);
	g_test_add_func("/utils/get_sectorsize", get_sectorsize_test);
	g_test_add_func("/utils/get_device_size", get_device_size_test);
	g_test_add_func("/utils/update_symlink", update_symlink_test);

	return g_test_run();
}
