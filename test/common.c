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

int test_prepare_system_conf(const gchar *dirname, const gchar *filename, const SystemTestOptions *options)
{
	g_autofree gchar *path = g_build_filename(dirname, filename, NULL);
	g_autoptr(GString) config = g_string_sized_new(1024);

	g_string_append(config, "[system]\n\
compatible=Test Config\n\
bootloader=grub\n\
grubenv=grubenv.test\n\
variant-name=Default Variant\n\
");
	if (options && options->min_bundle_version)
		g_string_append_printf(config, "min-bundle-version=%s\n", options->min_bundle_version);
	g_string_append(config, "\n");

	g_string_append(config, "[handlers]\n\
system-info=bin/systeminfo.sh\n\
pre-install=bin/preinstall.sh\n\
post-install=bin/postinstall.sh\n\
\n\
[keyring]\n\
path=openssl-ca/dev-ca.pem\n\
check-crl=true\n\
\n\
[slot.rescue.0]\n\
device=images/rescue-0\n\
type=ext4\n\
bootname=factory0\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=images/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=images/rootfs-1\n\
type=ext4\n\
bootname=system1\n\
\n\
[slot.appfs.0]\n\
device=images/appfs-0\n\
type=ext4\n\
parent=rootfs.0\n\
\n\
[slot.appfs.1]\n\
device=images/appfs-1\n\
type=ext4\n\
parent=rootfs.1\n\
\n\
[slot.bootloader.0]\n\
device=images/bootloader-0\n\
type=ext4\n\
allow-mounted=true\n\
");

	if (options && options->artifact_repos) {
		g_string_append(config, "\n\
[artifacts.files]\n\
path=repos/files\n\
type=files\n\
\n\
[artifacts.trees]\n\
path=repos/trees\n\
type=trees\n\
");
		if (ENABLE_COMPOSEFS)
			g_string_append(config, "\n\
[artifacts.composefs]\n\
path=repos/composefs\n\
type=composefs\n\
");
	}

	g_assert_true(g_file_set_contents(path, config->str, config->len, NULL));

	return 0;
}

int test_prepare_manifest_file(const gchar *dirname, const gchar *filename, const ManifestTestOptions *options)
{
	g_autofree gchar *path = g_build_filename(dirname, filename, NULL);
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucImage *img;

	g_assert_nonnull(options);

	rm->update_compatible = g_strdup("Test Config");
	if (options->bundle_version)
		rm->update_version = g_strdup(options->bundle_version);
	else if (!options->no_bundle_version)
		rm->update_version = g_strdup("2011.03-2");

	rm->bundle_format = options->format;

	if (options->custom_handler)
		rm->handler_name = g_strdup("custom_handler.sh");

	if (options->preinstall_handler)
		rm->preinstall_handler = g_strdup("preinstall.sh");

	if (options->postinstall_handler)
		rm->postinstall_handler = g_strdup("postinstall.sh");

	if (options->hooks) {
		rm->hook_name = g_strdup("hook.sh");
	}

	if (options->slots) {
		img = r_new_image();
		img->slotclass = g_strdup("rootfs");
		img->filename = g_strdup("rootfs.ext4");
		img->type = g_strdup("ext4");
		if (options->hooks)
			img->hooks.post_install = TRUE;
		rm->images = g_list_append(rm->images, img);

		img = r_new_image();
		img->slotclass = g_strdup("appfs");
		img->filename = g_strdup("appfs.ext4");
		img->type = g_strdup("ext4");
		rm->images = g_list_append(rm->images, img);
	}

	if (options->artifact_file) {
		g_assert_nonnull(options->artifact_slotclass);

		img = r_new_image();
		img->slotclass = g_strdup(options->artifact_slotclass);
		img->filename = g_strdup(options->artifact_file);
		if (g_strcmp0(options->artifact_file, "artifact-1.file") == 0) {
			img->artifact = g_strdup("artifact-1");
			if (options->hooks)
				img->hooks.post_install = TRUE;
		} else if (g_strcmp0(options->artifact_file, "payload-common.tar") == 0) {
			img->artifact = g_strdup("common");
			if (options->hooks)
				img->hooks.post_install = TRUE;
		} else if (g_strcmp0(options->artifact_file, "payload-special.tar") == 0) {
			img->artifact = g_strdup("special");
			if (options->hooks)
				img->hooks.post_install = TRUE;
		} else if (g_strcmp0(options->artifact_file, "payload-medium-data-size-a.tar.gz") == 0 ||
		           g_strcmp0(options->artifact_file, "payload-medium-data-size-b.tar.gz") == 0) {
			img->artifact = g_strdup("medium-data-size");
			if (options->hooks)
				img->hooks.post_install = TRUE;
		} else {
			g_error("artifact_file %s not implemented", options->artifact_file);
		}
		if (options->artifact_convert) {
			GPtrArray *convert = g_ptr_array_new_with_free_func(g_free);
			g_ptr_array_add(convert, g_strdup(options->artifact_convert));
			g_ptr_array_add(convert, NULL);
			img->convert = (GStrv) g_ptr_array_free(convert, FALSE);
		}

		rm->images = g_list_append(rm->images, img);
	}

	g_assert_true(check_manifest_input(rm, NULL));

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
	g_autofree gchar *filename = NULL;

	g_assert(g_mkdir(contentdir, 0777) == 0);
	g_assert(test_prepare_dummy_file(contentdir, "rootfs.ext4",
			1024*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_dummy_file(contentdir, "appfs.ext4",
			64*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_manifest_file(contentdir, "manifest.raucm",
			options) == 0);

	filename = write_random_file(contentdir, "artifact-1.file", 16*1024, 0x34f474b1);
	g_assert_nonnull(filename);

	if (options->artifact_file) {
		g_assert_true(test_copy_file("test/install-content", "payload-common.tar", contentdir, "payload-common.tar"));
		g_assert_true(test_copy_file("test/install-content", "payload-special.tar", contentdir, "payload-special.tar"));
	}
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

void test_show_tree(const gchar *path, gboolean inodes)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(7, g_free);

	g_return_if_fail(path != NULL);

	g_ptr_array_add(args, g_strdup("tree"));
	g_ptr_array_add(args, g_strdup("--metafirst"));
	g_ptr_array_add(args, g_strdup("-ax")); // listing options
	g_ptr_array_add(args, g_strdup("-pugs")); // file options
	if (inodes)
		g_ptr_array_add(args, g_strdup("--inodes"));
	g_ptr_array_add(args, g_strdup(path));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
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
