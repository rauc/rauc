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
	gchar *bundlename;
	gchar *contentdir;
} BundleFixture;

static void bundle_fixture_set_up(BundleFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);
}

static void bundle_fixture_set_up_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	fixture->contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(fixture->contentdir);
	fixture->bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(fixture->bundlename);

	test_create_content(fixture->contentdir);

	test_create_bundle(fixture->contentdir, fixture->bundlename);
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
	gchar *outputdir;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	g_assert_true(extract_bundle(fixture->bundlename, outputdir, TRUE, NULL));
	g_assert_true(verify_manifest(outputdir, NULL, FALSE, NULL));
}

static void bundle_test_create_mount_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *mountpoint;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	mountpoint = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountpoint);
	g_assert(g_mkdir(mountpoint, 0777) == 0);

	g_assert_true(mount_bundle(fixture->bundlename, mountpoint, FALSE, NULL));
	g_assert_true(verify_manifest(mountpoint, NULL, FALSE, NULL));
	g_assert_true(umount_bundle(fixture->bundlename, NULL));
}


static void bundle_test_extract_manifest(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *outputdir, *manifestpath;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	manifestpath = g_build_filename(fixture->tmpdir, "/output/manifest.raucm", NULL);
	g_assert_nonnull(manifestpath);

	g_assert_true(extract_file_from_bundle(fixture->bundlename, outputdir, "manifest.raucm", TRUE, NULL));
	g_assert_true(g_file_test(manifestpath, G_FILE_TEST_EXISTS));
}

static void bundle_test_resign(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *resignbundle;
	gsize size;
	GError *ierror = NULL;
	gboolean res = FALSE;

	resignbundle = g_build_filename(fixture->tmpdir, "resigned-bundle.raucb", NULL);
	g_assert_nonnull(resignbundle);

	/* Switch to release key pair */
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");


	/* Verify input bundle with dev keyring */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-ca.pem");
	g_assert_true(check_bundle(fixture->bundlename, &size, TRUE, NULL));
	/* Verify input bundle with rel keyring */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/rel-ca.pem");
	g_assert_false(check_bundle(fixture->bundlename, &size, TRUE, NULL));

	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-ca.pem");
	res = resign_bundle(fixture->bundlename, resignbundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* Verify resigned bundle with dev keyring.
	 * Note that this evaluates to true as the dev-ca.pem keyring contains
	 * both the production and the development certificate to allow
	 * installing development bundles as well as moving to production
	 * bundles. */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-ca.pem");
	g_assert_true(check_bundle(resignbundle, &size, TRUE, NULL));
	/* Verify resigned bundle with rel keyring */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/rel-ca.pem");
	g_assert_true(check_bundle(resignbundle, &size, TRUE, NULL));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-1.pem");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bundle/check/empty", BundleFixture, NULL,
		   bundle_fixture_set_up, test_check_empty_bundle,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/check/invalid", BundleFixture, NULL,
		   bundle_fixture_set_up, test_check_invalid_bundle,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/create_extract", BundleFixture, NULL,
		   bundle_fixture_set_up_bundle, bundle_test_create_extract,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/create_mount_extract", BundleFixture, NULL,
		   bundle_fixture_set_up_bundle, bundle_test_create_mount_extract,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/extract_manifest", BundleFixture, NULL,
		   bundle_fixture_set_up_bundle, bundle_test_extract_manifest,
		   bundle_fixture_tear_down);

	g_test_add("/bundle/resign", BundleFixture, NULL,
		   bundle_fixture_set_up_bundle, bundle_test_resign,
		   bundle_fixture_tear_down);

	return g_test_run();
}
