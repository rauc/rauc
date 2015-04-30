#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>
#include <manifest.h>
#include "bundle.h"

typedef struct {
	gchar *tmpdir;
} BundleFixture;

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

static int prepare_manifest_file(const gchar *dirname, const gchar *filename) {
	gchar *path = g_build_filename(dirname, filename, NULL);
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucImage *img;

	rm->update_compatible = g_strdup("Rauc Testsuite");
	rm->update_version = g_strdup("2011.03-2");

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("rootfs");
	img->filename = g_strdup("rootfs.img");
	rm->images = g_list_append(rm->images, img);

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("appfs");
	img->filename = g_strdup("appfs.img");
	rm->images = g_list_append(rm->images, img);

	g_assert_true(save_manifest(path, rm));

	free_manifest(rm);
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

static void bundle_fixture_set_up(BundleFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp(NULL, NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);
	g_assert(mkdir_relative(fixture->tmpdir, "content", 0777) == 0);
	g_assert(mkdir_relative(fixture->tmpdir, "mount", 0777) == 0);
	g_assert(prepare_dummy_file(fixture->tmpdir, "content/rootfs.img", 1024*1024) == 0);
	g_assert(prepare_dummy_file(fixture->tmpdir, "content/appfs.img", 64*1024) == 0);
	g_assert(prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm") == 0);
}

static void bundle_fixture_tear_down(BundleFixture *fixture,
		gconstpointer user_data)
{
	// FIXME remove tmpdir
	g_free(fixture->tmpdir);
}

static void bundle_test1(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *outputdir;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	g_assert_true(update_manifest(contentdir, FALSE));
	g_assert_true(create_bundle(bundlename, contentdir));
	g_assert_true(extract_bundle(bundlename, outputdir));
	g_assert_true(verify_manifest(outputdir, FALSE));
}

static void bundle_test2(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *mountpoint;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	mountpoint = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountpoint);

	g_assert_true(update_manifest(contentdir, FALSE));
	g_assert_true(create_bundle(bundlename, contentdir));
	g_assert_true(mount_bundle(bundlename, mountpoint));
	g_assert_true(verify_manifest(mountpoint, FALSE));
	g_assert_true(umount_bundle(bundlename));
}

static void bundle_test3(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *appfsimage;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	appfsimage = g_build_filename(fixture->tmpdir, "content", "appfs.img", NULL);
	g_assert_nonnull(appfsimage);

	g_assert_true(update_manifest(contentdir, TRUE));
	g_assert_true(verify_manifest(contentdir, FALSE));
	g_assert_true(verify_manifest(contentdir, TRUE));

	g_assert(prepare_dummy_file(fixture->tmpdir, "content/appfs.img", 64*1024) == 0);
	g_assert_false(verify_manifest(contentdir, FALSE));
	g_assert_false(verify_manifest(contentdir, TRUE));

	g_assert_cmpint(g_unlink(appfsimage), ==, 0);
	g_assert_false(verify_manifest(contentdir, FALSE));
	g_assert_false(verify_manifest(contentdir, TRUE));

	g_free(appfsimage);
	g_free(contentdir);
	g_free(bundlename);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	r_context_alloc();
	r_context()->configpath = g_strdup("test/test.conf");
	r_context()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context_init();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bundle/test1", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test1,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/test2", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test2,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/test3", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test3,
		   bundle_fixture_tear_down);

	return g_test_run ();
}
