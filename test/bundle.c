#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <manifest.h>
#include <signature.h>
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

static void bundle_fixture_set_up_bundle_autobuilder2(BundleFixture *fixture,
		gconstpointer user_data)
{
	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-2.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-2.pem");

	/* disable crl checking during bundle creation */
	r_context()->config->keyring_check_crl = FALSE;
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Detected CRL but CRL checking is disabled!");
	bundle_fixture_set_up_bundle(fixture, user_data);
	r_context()->config->keyring_check_crl = TRUE;
}

static void bundle_fixture_set_up_bundle_email(BundleFixture *fixture,
		gconstpointer user_data)
{
	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/xku-emailProtection.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/xku-emailProtection.pem");
	/* cert is already checked once during signing */
	r_context()->config->keyring_check_purpose = g_strdup("smimesign");

	bundle_fixture_set_up_bundle(fixture, user_data);
}

static void bundle_fixture_set_up_bundle_codesign(BundleFixture *fixture,
		gconstpointer user_data)
{
	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/xku-codeSigning.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/xku-codeSigning.pem");
	/* cert is already checked once during signing */
	r_context()->config->keyring_check_purpose = g_strdup("codesign");

	bundle_fixture_set_up_bundle(fixture, user_data);
}

static void bundle_fixture_tear_down(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void bundle_fixture_tear_down_autobuilder2(BundleFixture *fixture,
		gconstpointer user_data)
{
	/* restore old paths */
	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-1.pem");

	bundle_fixture_tear_down(fixture, user_data);
}

static void test_check_empty_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename;
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 0, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_false(res);
	g_assert_error(ierror, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT);
	g_assert_null(bundle);

	g_free(bundlename);
}

static void test_check_invalid_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlename;
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 1024, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, &ierror);
	g_assert_false(res);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_IDENTIFIER);
	g_assert_null(bundle);

	g_free(bundlename);
}

static void bundle_test_create_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *outputdir;
	RaucBundle *bundle = NULL;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	g_assert_true(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL));
	g_assert_nonnull(bundle);

	g_assert_true(extract_bundle(bundle, outputdir, NULL));

	free_bundle(bundle);
}

static void bundle_test_create_mount_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = mount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	res = umount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	free_bundle(bundle);
}

static void bundle_test_extract_manifest(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *outputdir, *manifestpath;
	RaucBundle *bundle = NULL;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	manifestpath = g_build_filename(fixture->tmpdir, "/output/manifest.raucm", NULL);
	g_assert_nonnull(manifestpath);

	g_assert_true(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL));
	g_assert_nonnull(bundle);

	g_assert_true(extract_file_from_bundle(bundle, outputdir, "manifest.raucm", NULL));
	g_assert_true(g_file_test(manifestpath, G_FILE_TEST_EXISTS));

	free_bundle(bundle);
}

// Hack to pull-in context for testing modification
extern RaucContext *context;

static void bundle_test_resign(BundleFixture *fixture,
		gconstpointer user_data)
{
	gchar *resignbundle;
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	resignbundle = g_build_filename(fixture->tmpdir, "resigned-bundle.raucb", NULL);
	g_assert_nonnull(resignbundle);

	/* Input bundle must *not* verify against 'rel' keyring.
	 * Note we have to use r_context() here as a hack to avoid re-setting
	 * the context's 'pending' flag which would cause a re-initialization
	 * of context and thus overwrite content of 'config' member. */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/rel-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify input bundle with 'dev' keyring */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* Use 'rel' key pair for resigning */
	context->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	context->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	context->signing_keyringpath = g_strdup("test/openssl-ca/rel-ca.pem");

	res = resign_bundle(bundle, resignbundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify resigned bundle with dev keyring.
	 * Note that this evaluates to true as the dev-ca.pem keyring contains
	 * both the production and the development certificate to allow
	 * installing development bundles as well as moving to production
	 * bundles. */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify resigned bundle with rel keyring */
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/rel-ca.pem");
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	// hacky restore of original signing_keyringpath
	context->signing_keyringpath = NULL;
	g_clear_pointer(&bundle, free_bundle);
}

static void bundle_test_wrong_capath(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	r_context()->config->keyring_path = g_strdup("does/not/exist.pem");

	g_assert_false(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror));
	g_assert_null(bundle);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_CA_LOAD);

	// hacky restore of original keyring_path
	r_context()->config->keyring_path = g_strdup("test/openssl-ca/dev-ca.pem");
}

/* Test that checking against a keyring that contains a CRL results in a
 * warning when check-crl is disabled */
static void bundle_test_verify_no_crl_warn(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	r_context()->config->keyring_check_crl = FALSE;

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Reading bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Detected CRL but CRL checking is disabled!");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	free_bundle(bundle);
}

/* Test that verification of a bundle signed with a revoked key actually fails
 */
static void bundle_test_verify_revoked(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;

	g_assert_false(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror));
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(bundle);
}

static void bundle_test_purpose_default(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies no purpose, everything except 'codesign' is allowed */

	g_message("testing default purpose with default cert");
	r_context()->config->keyring_check_purpose = NULL;
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'smimesign' with default cert");
	r_context()->config->keyring_check_purpose = g_strdup("smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'codesign' with default cert");
	r_context()->config->keyring_check_purpose = g_strdup("codesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_message("testing purpose 'any' with default cert");
	r_context()->config->keyring_check_purpose = g_strdup("any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	r_context()->config->keyring_check_purpose = NULL;
}

static void bundle_test_purpose_email(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies the 'smimesign' usage, only default and that is allowed */

	g_message("testing default purpose with 'smimesign' cert");
	r_context()->config->keyring_check_purpose = NULL;
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'smimesign' with 'smimesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'codesign' with 'smimesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("codesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'any' with 'smimesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	r_context()->config->keyring_check_purpose = NULL;
}

static void bundle_test_purpose_codesign(BundleFixture *fixture,
		gconstpointer user_data)
{
	RaucBundle *bundle = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies the 'codesign' usage, only that is allowed */

	g_message("testing default purpose with 'codesign' cert");
	r_context()->config->keyring_check_purpose = NULL;
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'smimesign' with 'codesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'codesign' with 'codesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("codesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'any' with 'codesign' cert");
	r_context()->config->keyring_check_purpose = g_strdup("any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	r_context()->config->keyring_check_purpose = NULL;
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

	g_test_add("/bundle/wrong_capath", BundleFixture, NULL,
			bundle_fixture_set_up_bundle, bundle_test_wrong_capath,
			bundle_fixture_tear_down);

	g_test_add("/bundle/verify_no_crl_warn", BundleFixture, NULL,
			bundle_fixture_set_up_bundle, bundle_test_verify_no_crl_warn,
			bundle_fixture_tear_down);

	g_test_add("/bundle/verify_revoked", BundleFixture, NULL,
			bundle_fixture_set_up_bundle_autobuilder2, bundle_test_verify_revoked,
			bundle_fixture_tear_down_autobuilder2);

	g_test_add("/bundle/purpose/default", BundleFixture, NULL,
			bundle_fixture_set_up_bundle, bundle_test_purpose_default,
			bundle_fixture_tear_down);

	g_test_add("/bundle/purpose/email", BundleFixture, NULL,
			bundle_fixture_set_up_bundle_email, bundle_test_purpose_email,
			bundle_fixture_tear_down);

	g_test_add("/bundle/purpose/codesign", BundleFixture, NULL,
			bundle_fixture_set_up_bundle_codesign, bundle_test_purpose_codesign,
			bundle_fixture_tear_down);

	return g_test_run();
}
