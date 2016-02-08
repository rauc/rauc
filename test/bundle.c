#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

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
	g_assert(test_prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm", FALSE) == 0);
}

static void bundle_fixture_tear_down(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
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

	g_assert_true(update_manifest(contentdir, FALSE, NULL));
	g_assert_true(create_bundle(bundlename, contentdir, NULL));
	g_assert_true(extract_bundle(bundlename, outputdir, TRUE, NULL));
	g_assert_true(verify_manifest(outputdir, NULL, FALSE, NULL));
}

static void bundle_test2(BundleFixture *fixture,
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

static void bundle_test3(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename, *contentdir, *appfsimage;

	bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlename);

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
	g_free(bundlename);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bundle/test1", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test1,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/test2", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test2,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/test_extract_manifest", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test_extract_manifest,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/test3", BundleFixture, NULL,
		   bundle_fixture_set_up, bundle_test3,
		   bundle_fixture_tear_down);

	return g_test_run();
}
