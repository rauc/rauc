#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <context.h>
#include <manifest.h>
#include "bundle.h"
#include <install.h>
#include "mount.h"

typedef struct {
	gchar *tmpdir;
} InstallFixture;

static int prepare_dummy_file(const gchar *dirname, const gchar *filename, gsize size) {
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

static int mkdir_relative(const gchar *dirname, const gchar *filename, int mode) {
	gchar *path;
	int res;

	path = g_strdup_printf("%s/%s", dirname, filename);
	g_assert_nonnull(path);

	res = g_mkdir(path, mode);

	g_free(path);
	return res;
}

static int prepare_manifest_file(const gchar *dirname, const gchar *filename) {
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

static gboolean make_filesystem(const gchar *dirname, const gchar *filename) {
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

static gboolean mount(const gchar *src, const gchar *dest) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"sudo",
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


static gboolean do_chmod(const gchar *path) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	
	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
			&error,
			"sudo",
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

/*
static gboolean umount(const gchar *dirname, const gchar *mountpoint) {
	gchar *path;
	
	path = g_build_filename(dirname, mountpoint, NULL);

	g_assert_true(r_umount(path));

	return TRUE;
}
*/

static gboolean copy_test_file(const gchar *srcfile, const gchar *dstfile) {
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

static gboolean make_slot_user_writable(const gchar* path, const gchar* file) {
	gboolean res = FALSE;
	gchar *slotpath;
	gchar *mountpath;
	
	slotpath = g_build_filename(path, file, NULL);
	g_assert_nonnull(slotpath);

	mountpath = g_build_filename(path, "tmpmount", NULL);
	g_assert_nonnull(mountpath);

	if (!g_file_test(mountpath, G_FILE_TEST_IS_DIR)) {
		g_assert(mkdir_relative(path, "tmpmount", 0777) == 0);
	}

	mount(slotpath, mountpath);

	do_chmod(mountpath);

	r_umount(mountpath);

	res = TRUE;

	return res;

}


static const gchar* dummy_provider(void) {
	return "system0";
}

static void install_fixture_set_up(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *contentdir;
	gchar *bundlepath;
	gchar *configpath;
	gchar *certpath;
	gchar *keypath;
	gchar *capath;

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);

	g_assert(mkdir_relative(fixture->tmpdir, "content", 0777) == 0);
	g_assert(mkdir_relative(fixture->tmpdir, "mount", 0777) == 0);
	g_assert(mkdir_relative(fixture->tmpdir, "images", 0777) == 0);
	g_assert(mkdir_relative(fixture->tmpdir, "openssl-ca", 0777) == 0);

	/* copy system config to temp dir*/
	configpath = g_build_filename(fixture->tmpdir, "system.conf", NULL);
	g_assert_nonnull(configpath);
	g_assert_true(copy_test_file("test/test.conf", configpath));
	r_context_conf()->configpath = g_strdup(configpath);

	/* copy cert */
	certpath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.cert.pem", NULL);
	g_assert_nonnull(certpath);
	g_assert_true(copy_test_file("test/openssl-ca/rel/release-1.cert.pem", certpath));
	r_context_conf()->certpath = g_strdup(certpath);

	/* copy key */
	keypath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.pem", NULL);
	g_assert_nonnull(keypath);
	g_assert_true(copy_test_file("test/openssl-ca/rel/private/release-1.pem", keypath));
	r_context_conf()->keypath = g_strdup(keypath);

	/* copy ca */
	capath = g_build_filename(fixture->tmpdir, "openssl-ca/dev-ca.pem", NULL);
	g_assert_nonnull(capath);
	g_assert_true(copy_test_file("test/openssl-ca/dev-ca.pem", capath));

	/* Setup pseudo devices */
	g_assert(prepare_dummy_file(fixture->tmpdir, "images/rootfs-1", 0) == 0);
	g_assert(prepare_dummy_file(fixture->tmpdir, "images/appfs-1", 0) == 0);

	/* Setup bundle content */
	g_assert(prepare_dummy_file(fixture->tmpdir, "content/rootfs.img", 10*1024*1024) == 0);
	g_assert(prepare_dummy_file(fixture->tmpdir, "content/appfs.img", 10*1024*1024) == 0);
	g_assert_true(make_filesystem(fixture->tmpdir, "content/rootfs.img"));
	g_assert_true(make_filesystem(fixture->tmpdir, "content/appfs.img"));
	g_assert(prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm") == 0);

	/* make images user-writable */
	make_slot_user_writable(fixture->tmpdir, "content/rootfs.img");
	make_slot_user_writable(fixture->tmpdir, "content/appfs.img");

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	g_assert_true(update_manifest(contentdir, FALSE));

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	/* Create bundle */
	g_assert_true(create_bundle(bundlepath, contentdir));

	/* Set dummy bootname provider */
	set_bootname_provider(dummy_provider);

	g_free(contentdir);
	g_free(bundlepath);
	g_free(configpath);
	g_free(certpath);
	g_free(keypath);
	g_free(capath);


}

static void install_fixture_tear_down(InstallFixture *fixture,
		gconstpointer user_data)
{
	//umount(fixture->tmpdir, "mount/bundle");
}

static const gchar* dummy_bootname_provider(void) {
	return "system0";
}

static void install_test1(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm;
	GHashTable *tgrp;

	g_assert_true(load_manifest_file("test/manifest.raucm", &rm));

	set_bootname_provider(dummy_bootname_provider);
	g_assert_true(determine_slot_states());

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rescue.0"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.1"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.1"))->state, ==, ST_INACTIVE);


	tgrp = determine_target_install_group(rm);

	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));
	g_assert_cmpstr(g_hash_table_lookup(tgrp, "rootfs"), ==, "rootfs.1");
	g_assert_cmpstr(g_hash_table_lookup(tgrp, "appfs"), ==, "appfs.1");
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);

}

static void install_test2(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath;
	gchar* mountdir;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = g_strdup(mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	g_assert_true(do_install_bundle(bundlepath));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");



	g_test_init(&argc, &argv, NULL);

	g_test_add("/install/test1", InstallFixture, NULL,
		   install_fixture_set_up, install_test1,
		   install_fixture_tear_down);

	g_test_add("/install/test2", InstallFixture, NULL,
		   install_fixture_set_up, install_test2,
		   install_fixture_tear_down);

	return g_test_run ();
}
