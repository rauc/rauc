#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <manifest.h>
#include <utils.h>

#include "common.h"

typedef struct {
	gchar *tmpdir;
} BundleFixture;

static void bundle_fixture_set_up(BundleFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);
	g_assert(test_mkdir_relative(fixture->tmpdir, "content", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "mount", 0777) == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/rootfs.ext4",
					 1024*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/appfs.ext4",
				         64*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm", FALSE, FALSE) == 0);
}

static void bundle_fixture_tear_down(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void test_check_empty_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename;
	gsize size;
	GError *ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 0, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &size, TRUE, &ierror);
	g_assert_error(ierror, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	g_assert_false(res);

	g_free(bundlename);
}

static void test_check_invalid_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename;
	gsize size;
	GError *ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 1024, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &size, FALSE, &ierror);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE);
	g_assert_false(res);

	g_free(bundlename);
}

static void bundle_test_create_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *outputdir;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	g_assert_true(update_manifest(contentdir, FALSE, NULL));
	g_assert_true(create_bundle(bundlename, contentdir, NULL));
	g_assert_true(extract_bundle(bundlename, outputdir, TRUE, NULL));
	g_assert_true(verify_manifest(outputdir, NULL, FALSE, NULL));
}

static void bundle_test_create_mount_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *mountpoint;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	mountpoint = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountpoint);

	g_assert_true(update_manifest(contentdir, FALSE, NULL));
	g_assert_true(create_bundle(bundlename, contentdir, NULL));
	g_assert_true(mount_bundle(bundlename, mountpoint, FALSE, NULL));
	g_assert_true(verify_manifest(mountpoint, NULL, FALSE, NULL));
	g_assert_true(umount_bundle(bundlename, NULL));
}


static void bundle_test_extract_manifest(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *outputdir, *manifestpath;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	manifestpath = g_build_filename(fixture->tmpdir, "/output/manifest.raucm", NULL);
	g_assert_nonnull(manifestpath);

	g_assert_true(update_manifest(contentdir, FALSE, NULL));
	g_assert_true(create_bundle(bundlename, contentdir, NULL));
	g_assert_true(extract_file_from_bundle(bundlename, outputdir, "manifest.raucm", TRUE, NULL));
	g_assert_true(g_file_test(manifestpath, G_FILE_TEST_EXISTS));
}

static void bundle_test_verify_manifest(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *contentdir, *appfsimage;

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	appfsimage = g_build_filename(fixture->tmpdir, "content", "appfs.ext4", NULL);
	g_assert_nonnull(appfsimage);

	g_assert_true(update_manifest(contentdir, TRUE, NULL));
	g_assert_true(verify_manifest(contentdir, NULL, FALSE, NULL));
	g_assert_true(verify_manifest(contentdir, NULL, TRUE, NULL));

	/* Test with invalid checksum */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/appfs.ext4",
					 64*1024, "/dev/urandom") == 0);
	g_test_expect_message (G_LOG_DOMAIN,
			G_LOG_LEVEL_WARNING,
			"Failed verifying checksum: Digests do not match");
	g_assert_false(verify_manifest(contentdir, NULL, FALSE, NULL));
	g_test_expect_message (G_LOG_DOMAIN,
			G_LOG_LEVEL_WARNING,
			"Failed verifying checksum: Digests do not match");
	g_assert_false(verify_manifest(contentdir, NULL, TRUE, NULL));

	/* Test with non-existing image */
	g_assert_cmpint(g_unlink(appfsimage), ==, 0);

	g_test_expect_message (G_LOG_DOMAIN,
			G_LOG_LEVEL_WARNING,
			"Failed verifying checksum: Failed to open file * No such file or directory");
	g_assert_false(verify_manifest(contentdir, NULL, FALSE, NULL));
	g_test_expect_message (G_LOG_DOMAIN,
			G_LOG_LEVEL_WARNING,
			"Failed verifying checksum: Failed to open file * No such file or directory");
	g_assert_false(verify_manifest(contentdir, NULL, TRUE, NULL));
	g_test_assert_expected_messages();

	g_free(appfsimage);
	g_free(contentdir);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bundle/check/empty", BundleFixture, NULL,
		   bundle_fixture_set_up, test_check_empty_bundle,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/check/invalid", BundleFixture, NULL,
		   bundle_fixture_set_up, test_check_invalid_bundle,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/create_extract", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test_create_extract,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/create_mount_extract", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test_create_mount_extract,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/extract_manifest", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test_extract_manifest,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/verify_manifest", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test_verify_manifest,
		   bundle_fixture_tear_down);

	return g_test_run();
}
