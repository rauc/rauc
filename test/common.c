#include "common.h"

#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <manifest.h>
#include <mount.h>

typedef struct {
	gchar *tmpdir;
} InstallFixture;

int test_prepare_dummy_file(const gchar *dirname, const gchar *filename, gsize size) {
	GIOChannel *input, *output;
	GIOStatus status;
	gchar *path;

	input = g_io_channel_new_file("/dev/urandom", "r", NULL);
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

int test_mkdir_relative(const gchar *dirname, const gchar *filename, int mode) {
	gchar *path;
	int res;

	path = g_strdup_printf("%s/%s", dirname, filename);
	g_assert_nonnull(path);

	res = g_mkdir(path, mode);

	g_free(path);
	return res;
}

int test_prepare_manifest_file(const gchar *dirname, const gchar *filename) {
	gchar *path = g_build_filename(dirname, filename, NULL);
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucImage *img;

	rm->update_compatible = g_strdup("Test Config");
	rm->update_version = g_strdup("2011.03-2");

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("rootfs");
	img->filename = g_strdup("rootfs.img");
	rm->images = g_list_append(rm->images, img);

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("appfs");
	img->filename = g_strdup("appfs.img");
	rm->images = g_list_append(rm->images, img);

	g_assert_true(save_manifest_file(path, rm));

	free_manifest(rm);
	return 0;
}

gboolean test_make_filesystem(const gchar *dirname, const gchar *filename) {
	GSubprocess *sub;
	GError *error = NULL;
	gchar *path;
	gboolean res = FALSE;
	
	path = g_build_filename(dirname, filename, NULL);
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"/sbin/mkfs.ext4",
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

gboolean test_mount(const gchar *src, const gchar *dest) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"sudo",
			"--non-interactive",
			"mount",
			src,
			dest,
			NULL);

	if (!sub) {
		g_warning("mount failed: %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("mound failed: %s", error->message);
		g_clear_error(&error);
	}

	return TRUE;
}


gboolean test_do_chmod(const gchar *path) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"sudo",
			"--non-interactive",
			"chmod",
			"777",
			path,
			NULL);

	if (!sub) {
		g_warning("chmod failed: %s", error->message);
		g_clear_error(&error);
		return FALSE;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("chmod failed: %s", error->message);
		g_clear_error(&error);
	}

	return TRUE;
}

gboolean test_umount(const gchar *dirname, const gchar *mountpoint) {
	gchar *path;
	
	path = g_build_filename(dirname, mountpoint, NULL);

	g_assert_true(r_umount(path));

	return TRUE;
}

gboolean test_copy_file(const gchar *srcfile, const gchar *dstfile) {
	gboolean res = FALSE;
	GError *error = NULL;
	GFile *src;
	GFile *dst;

	src = g_file_new_for_path(srcfile);
	dst = g_file_new_for_path(dstfile);
	res = g_file_copy(
				src,
				dst,
				G_FILE_COPY_NONE,
				NULL,
				NULL,
				NULL,
				&error);

	if (!res) {
		g_warning("Copy failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:

	g_object_unref(src);
	g_object_unref(dst);

	return TRUE;
}

gboolean test_make_slot_user_writable(const gchar* path, const gchar* file) {
	gboolean res = FALSE;
	gchar *slotpath;
	gchar *mountpath;
	
	slotpath = g_build_filename(path, file, NULL);
	g_assert_nonnull(slotpath);

	mountpath = g_build_filename(path, "tmpmount", NULL);
	g_assert_nonnull(mountpath);

	if (!g_file_test(mountpath, G_FILE_TEST_IS_DIR)) {
		g_assert(test_mkdir_relative(path, "tmpmount", 0777) == 0);
	}

	test_mount(slotpath, mountpath);

	test_do_chmod(mountpath);

	r_umount(mountpath);

	res = TRUE;

	return res;
}

const gchar* test_bootname_provider(void) {
	return "system0";
}
