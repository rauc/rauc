#include "common.h"

#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <fcntl.h>

#include <bundle.h>
#include <manifest.h>
#include <mount.h>
#include <utils.h>

typedef struct {
	gchar *tmpdir;
} InstallFixture;

guint8* random_bytes(gsize size, guint32 seed)
{
	guint8 *bytes = g_malloc0(size);
	g_autoptr(GRand) rand = g_rand_new_with_seed(seed);
	for (gsize i = 0; i < size; i++) {
		bytes[i] = g_rand_int(rand) & 0xFF;
	}
	return bytes;
}

gchar* write_random_file(const gchar *tmpdir, const gchar *filename,
		gsize size, const guint32 seed)
{
	g_autofree gchar *pathname = NULL;
	g_autofree guint8 *content = NULL;

	pathname = g_build_filename(tmpdir, filename, NULL);
	g_assert_nonnull(pathname);

	content = random_bytes(size, seed);

	if (!g_file_set_contents(pathname, (gchar *)content, size, NULL)) {
		return NULL;
	}

	return g_steal_pointer(&pathname);
}

/* Helper that writes string to new file in tmpdir/filename, returns entire
 * pathname if successful. */
gchar* write_tmp_file(
		const gchar* tmpdir,
		const gchar* filename,
		const gchar* content,
		GError **error)
{
	g_autofree gchar *pathname = NULL;
	GError *ierror = NULL;

	pathname = g_build_filename(tmpdir, filename, NULL);
	g_assert_nonnull(pathname);

	if (!g_file_set_contents(pathname, content, -1, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return g_steal_pointer(&pathname);
}

int test_prepare_dummy_file(const gchar *dirname, const gchar *filename,
		gsize size, const gchar *source)
{
	GIOChannel *input, *output;
	GIOStatus status;
	gchar *path;

	input = g_io_channel_new_file(source, "r", NULL);
	g_assert_nonnull(input);
	status = g_io_channel_set_encoding(input, NULL, NULL);
	g_assert(status == G_IO_STATUS_NORMAL);

	path = g_build_filename(dirname, filename, NULL);
	g_assert_nonnull(path);

	output = g_io_channel_new_file(path, "w+", NULL);
	g_assert_nonnull(output);
	status = g_io_channel_set_encoding(output, NULL, NULL);
	g_assert(status == G_IO_STATUS_NORMAL);
	g_free(path);

	while (size) {
		gchar buf[4096];
		gsize bytes_to_read = size < sizeof(buf) ? size : sizeof(buf);
		gsize bytes_read, bytes_written;
		GError *error = NULL;

		status = g_io_channel_read_chars(input, buf, bytes_to_read,
				&bytes_read, &error);
		g_assert_no_error(error);
		g_assert(status == G_IO_STATUS_NORMAL);

		status = g_io_channel_write_chars(output, buf, bytes_read,
				&bytes_written, &error);
		g_assert_no_error(error);
		g_assert(status == G_IO_STATUS_NORMAL);
		g_assert(bytes_read == bytes_written);

		size -= bytes_read;
	}

	g_io_channel_unref(input);
	g_io_channel_unref(output);
	return 0;
}

int test_mkdir_relative(const gchar *dirname, const gchar *filename, int mode)
{
	g_autofree gchar *path = NULL;
	int res;

	path = g_strdup_printf("%s/%s", dirname, filename);
	g_assert_nonnull(path);

	res = g_mkdir(path, mode);

	return res;
}

int test_rmdir(const gchar *dirname, const gchar *filename)
{
	g_autofree gchar *path = NULL;
	int res;

	path = g_build_filename(dirname, filename, NULL);
	g_assert_nonnull(path);

	res = g_rmdir(path);

	return res;
}

int test_remove(const gchar *dirname, const gchar *filename)
{
	g_autofree gchar *path = NULL;
	int res;

	path = g_build_filename(dirname, filename, NULL);
	g_assert_nonnull(path);

	res = g_remove(path);

	return res;
}

int test_lstat(const gchar *dirname, const gchar *filename, GStatBuf *buf)
{
	g_autofree gchar *path = NULL;
	int res;

	path = g_build_filename(dirname, filename, NULL);
	g_assert_nonnull(path);

	res = g_lstat(path, buf);

	return res;
}

gboolean test_rm_tree(const gchar *dirname, const gchar *filename)
{
	g_autofree gchar *path = NULL;
	gboolean res;

	path = g_build_filename(dirname, filename, NULL);
	g_assert_nonnull(path);

	res = rm_tree(path, NULL);

	return res;
}

int test_prepare_manifest_file(const gchar *dirname, const gchar *filename, const ManifestTestOptions *options)
{
	g_autofree gchar *path = g_build_filename(dirname, filename, NULL);
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucImage *img;

	rm->update_compatible = g_strdup("Test Config");
	rm->update_version = g_strdup("2011.03-2");

	rm->bundle_format = options->format;

	if (options->custom_handler)
		rm->handler_name = g_strdup("custom_handler.sh");

	if (options->hooks) {
		rm->hook_name = g_strdup("hook.sh");
	}

	if (options->slots) {
		img = g_new0(RaucImage, 1);
		img->slotclass = g_strdup("rootfs");
		img->filename = g_strdup("rootfs.ext4");
		if (options->hooks)
			img->hooks.post_install = TRUE;
		rm->images = g_list_append(rm->images, img);

		img = g_new0(RaucImage, 1);
		img->slotclass = g_strdup("appfs");
		img->filename = g_strdup("appfs.ext4");
		rm->images = g_list_append(rm->images, img);
	}

	g_assert_true(save_manifest_file(path, rm, NULL));

	free_manifest(rm);
	return 0;
}

gboolean test_make_filesystem(const gchar *dirname, const gchar *filename)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *error = NULL;
	g_autofree gchar *path = NULL;
	gboolean res = FALSE;

	path = g_build_filename(dirname, filename, NULL);
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"/sbin/mkfs.ext4",
			"-F",
			"-I256",
			path,
			NULL);

	if (!sub) {
		g_warning("Making filesystem failed: %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("mkfs failed: %s", error->message);
		g_clear_error(&error);
	}

	return TRUE;
}

gboolean test_mount(const gchar *src, const gchar *dest)
{
	return r_mount_full(src, dest, NULL, NULL, NULL);
}

gboolean test_do_chmod(const gchar *path)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *error = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);

	g_ptr_array_add(args, g_strdup("chmod"));
	g_ptr_array_add(args, g_strdup("777"));
	g_ptr_array_add(args, g_strdup(path));
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &error);
	if (!sub) {
		g_warning("chmod failed: %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &error)) {
		g_warning("chmod failed: %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}

	return TRUE;
}

gboolean test_umount(const gchar *dirname, const gchar *mountpoint)
{
	g_autofree gchar *path = NULL;
	gboolean res;

	path = g_build_filename(dirname, mountpoint, NULL);
	g_assert_nonnull(path);

	res = r_umount(path, NULL);

	return res;
}

gboolean test_copy_file(const gchar *srcprefix, const gchar *srcfile, const gchar *dstprefix, const gchar *dstfile)
{
	return copy_file(srcprefix, srcfile, dstprefix, dstfile, NULL);
}

gboolean test_make_slot_user_writable(const gchar* path, const gchar* file)
{
	gboolean res = FALSE;
	g_autofree gchar *slotpath = NULL;
	g_autofree gchar *mountpath = NULL;

	slotpath = g_build_filename(path, file, NULL);
	g_assert_nonnull(slotpath);

	mountpath = g_build_filename(path, "tmpmount", NULL);
	g_assert_nonnull(mountpath);

	if (!g_file_test(mountpath, G_FILE_TEST_IS_DIR)) {
		g_assert(test_mkdir_relative(path, "tmpmount", 0777) == 0);
	}

	test_mount(slotpath, mountpath);

	test_do_chmod(mountpath);

	g_assert_true(r_umount(mountpath, NULL));

	res = TRUE;

	return res;
}

void test_create_content(gchar *contentdir, const ManifestTestOptions *options)
{
	g_assert(g_mkdir(contentdir, 0777) == 0);
	g_assert(test_prepare_dummy_file(contentdir, "rootfs.ext4",
			1024*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_dummy_file(contentdir, "appfs.ext4",
			64*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_manifest_file(contentdir, "manifest.raucm",
			options) == 0);
}

void test_create_bundle(gchar *contentdir, gchar *bundlename)
{
	GError *error = NULL;
	gboolean res = FALSE;

	res = create_bundle(bundlename, contentdir, &error);
	g_assert_no_error(error);
	g_assert_true(res);
}

gboolean test_running_as_root(void)
{
	uid_t uid = getuid();
	uid_t euid = geteuid();

	if (uid == 0 && euid == 0)
		return TRUE;

	g_test_message("not running as root (uid=%lu euid=%lu)",
			(unsigned long) uid, (unsigned long) euid);
	g_test_skip("not running as root");
	return FALSE;
}

gsize get_file_size(gchar* filename, GError **error)
{
	GError *ierror = NULL;
	GFile *file = NULL;
	GFileInputStream *filestream = NULL;
	gsize size = 0;
	gboolean res = FALSE;

	file = g_file_new_for_path(filename);
	filestream = g_file_read(file, NULL, &ierror);
	if (filestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for reading: ");
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(filestream),
			0, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		goto out;
	}

	size = g_seekable_tell(G_SEEKABLE(filestream));

out:
	g_clear_object(&filestream);
	g_clear_object(&file);

	return size;
}

void flip_bits_fd(int fd, off_t offset, guint8 mask)
{
	guint8 buf;
	g_assert_cmpint(fd, >, 0);
	g_assert_cmphex(mask, !=, 0);
	g_assert(pread(fd, &buf, 1, offset) == 1);
	buf = buf ^ mask;
	g_assert(pwrite(fd, &buf, 1, offset) == 1);
}

void flip_bits_filename(gchar *filename, off_t offset, guint8 mask)
{
	int fd = g_open(filename, O_RDWR|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >, 0);
	flip_bits_fd(fd, offset, mask);
	g_assert(fsync(fd) == 0);
	g_close(fd, NULL);
}

void replace_strdup(gchar **dst, const gchar *src)
{
	r_replace_strdup(dst, src);
}

GPtrArray *test_ptr_array_from_strsplit(const gchar *input)
{
	GPtrArray *result = g_ptr_array_new_with_free_func(g_free);
	/* The strings will be owned by the returned GPtrArray, so we don't
	 * want to free them via g_auto(GStrv). */
	g_autofree GStrv strv = g_strsplit(input, ";", 0);

	r_ptr_array_addv(result, strv, FALSE);

	return result;
}

void* dup_test_mem(GPtrArray *ptrs, const void *mem, gsize len)
{
	void *result = g_memdup(mem, len);

	g_ptr_array_add(ptrs, result);

	return result;
}

void* dup_test_printf(GPtrArray *ptrs, const gchar *format, ...)
{
	gchar *result;
	va_list args;

	va_start(args, format);
	result = g_strdup_vprintf(format, args);
	va_end(args);

	g_ptr_array_add(ptrs, result);

	return result;
}
