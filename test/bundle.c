#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <manifest.h>
#include <signature.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <utils.h>

#include "common.h"
#include "config.h"

typedef struct {
	gchar *tmpdir;
	gchar *bundlename;
	gchar *contentdir;
	gboolean codesign_compat;
} BundleFixture;

typedef struct {
	ManifestTestOptions manifest_test_options;
	const gchar *bundle_formats;
} BundleData;

static void bundle_fixture_set_up(BundleFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_test_message("bundle tmpdir: %s\n", fixture->tmpdir);
}

static void prepare_bundle(BundleFixture *fixture, gconstpointer user_data)
{
	BundleData *data = (BundleData*)user_data;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!ENABLE_COMPOSEFS && (g_strcmp0(data->manifest_test_options.artifact_slotclass, "composefs") == 0)) {
		g_test_skip("Test requires RAUC being configured with \"-Dcomposefs=true\".");
		return;
	}

	/* the context needs to be setup before calling this */
	r_context();

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	fixture->contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(fixture->contentdir);
	fixture->bundlename = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(fixture->bundlename);

	test_create_content(fixture->contentdir, &data->manifest_test_options);

	/* disable crl checking during bundle creation */
	r_context()->config->keyring_check_crl = FALSE;
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Detected CRL but CRL checking is disabled!");
	if (fixture->codesign_compat) {
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Keyring given, doing signature verification");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Signer certificate should specify 'Key Usage' and mark it 'critical' to be fully CAB Forum compliant.");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Verified * signature*");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Signer certificate should specify 'Key Usage' and mark it 'critical' to be fully CAB Forum compliant.");
	}
	test_create_bundle(fixture->contentdir, fixture->bundlename);
	r_context()->config->keyring_check_crl = TRUE;

	if (data->bundle_formats) {
		res = parse_bundle_formats(&r_context()->config->bundle_formats_mask, data->bundle_formats, &ierror);
		g_assert_no_error(ierror);
		g_assert_true(res);
	}
}

static void bundle_fixture_set_up_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	replace_strdup(&r_context_conf()->certpath, "test/openssl-ca/dev/autobuilder-1.cert.pem");
	replace_strdup(&r_context_conf()->keypath, "test/openssl-ca/dev/private/autobuilder-1.pem");

	prepare_bundle(fixture, user_data);
}

static void bundle_fixture_set_up_bundle_corrupt(BundleFixture *fixture,
		gconstpointer user_data)
{
	replace_strdup(&r_context_conf()->certpath, "test/openssl-ca/dev/autobuilder-1.cert.pem");
	replace_strdup(&r_context_conf()->keypath, "test/openssl-ca/dev/private/autobuilder-1.pem");

	prepare_bundle(fixture, user_data);
	flip_bits_filename(fixture->bundlename, 1024*1024+512, 0xff);
}

static void bundle_fixture_set_up_bundle_autobuilder2(BundleFixture *fixture,
		gconstpointer user_data)
{
	replace_strdup(&r_context_conf()->certpath, "test/openssl-ca/dev/autobuilder-2.cert.pem");
	replace_strdup(&r_context_conf()->keypath, "test/openssl-ca/dev/private/autobuilder-2.pem");

	prepare_bundle(fixture, user_data);
}

static void bundle_fixture_set_up_bundle_email(BundleFixture *fixture,
		gconstpointer user_data)
{
	replace_strdup(&r_context_conf()->certpath, "test/openssl-ca/dev/xku-emailProtection.cert.pem");
	replace_strdup(&r_context_conf()->keypath, "test/openssl-ca/dev/private/xku-emailProtection.pem");
	/* cert is already checked once during signing */
	g_free(r_context()->config->keyring_check_purpose);
	r_context()->config->keyring_check_purpose = g_strdup("smimesign");

	prepare_bundle(fixture, user_data);
}

static void bundle_fixture_set_up_bundle_codesign(BundleFixture *fixture,
		gconstpointer user_data)
{
	replace_strdup(&r_context_conf()->certpath, "test/openssl-ca/dev/xku-codeSigning.cert.pem");
	replace_strdup(&r_context_conf()->keypath, "test/openssl-ca/dev/private/xku-codeSigning.pem");
	/* cert is already checked once during signing */
	g_free(r_context()->config->keyring_check_purpose);
	r_context()->config->keyring_check_purpose = g_strdup("codesign-rauc");
	fixture->codesign_compat = TRUE;

	prepare_bundle(fixture, user_data);
}

static void bundle_fixture_tear_down(BundleFixture *fixture,
		gconstpointer user_data)
{
	if (fixture->tmpdir)
		g_assert_true(rm_tree(fixture->tmpdir, NULL));

	g_free(fixture->tmpdir);
	g_free(fixture->bundlename);
	g_free(fixture->contentdir);

	g_test_assert_expected_messages();
}

static void bundle_fixture_tear_down_autobuilder2(BundleFixture *fixture,
		gconstpointer user_data)
{
	bundle_fixture_tear_down(fixture, user_data);
}

static void test_check_empty_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlename = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 0, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_false(res);
	g_assert_error(ierror, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
	g_assert_null(bundle);
}

static void test_check_invalid_bundle(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlename = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	bundlename = write_random_file(fixture->tmpdir, "bundle.raucb", 1024, 1234);
	g_assert_nonnull(bundlename);

	res = check_bundle(bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &ierror);
	g_assert_false(res);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE);
	g_assert_null(bundle);
}

static void bundle_test_create_check_error(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_false(res);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT);
	g_assert_null(bundle);
}

static void bundle_test_create_extract(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *outputdir = NULL;
	g_autofree gchar *filepath = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = extract_bundle(bundle, outputdir, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	filepath = g_build_filename(outputdir, "manifest.raucm", NULL);
	g_assert_true(g_file_test(filepath, G_FILE_TEST_IS_REGULAR));
	g_clear_pointer(&filepath, g_free);

	filepath = g_build_filename(outputdir, "rootfs.ext4", NULL);
	g_assert_true(g_file_test(filepath, G_FILE_TEST_IS_REGULAR));
	g_clear_pointer(&filepath, g_free);

	filepath = g_build_filename(outputdir, "appfs.ext4", NULL);
	g_assert_true(g_file_test(filepath, G_FILE_TEST_IS_REGULAR));
	g_clear_pointer(&filepath, g_free);
}

static void check_artifacts(RaucBundle *bundle, BundleData *data)
{
	g_autofree gchar *imagefilepath = NULL;
	const RaucImage *image = NULL;
	GStatBuf buf = {};

	g_assert_nonnull(bundle->manifest);

	for (GList *elem = bundle->manifest->images; elem != NULL; elem = elem->next) {
		image = elem->data;
		if (image->artifact)
			break;
	}
	g_assert_nonnull(image);

	imagefilepath = g_build_filename(bundle->mount_point, image->filename, NULL);

	if (g_strcmp0(data->manifest_test_options.artifact_file, "artifact-1.file") == 0) {
		g_assert_cmpint(g_stat(imagefilepath, &buf), ==, 0);

		g_assert_true(S_ISREG(buf.st_mode));
		g_assert_cmpint(buf.st_uid, ==, 0);
		g_assert_cmpint(buf.st_gid, ==, 0);
		g_assert_cmpint(buf.st_size, ==, 16*1024);
	}

	if (g_strcmp0(data->manifest_test_options.artifact_file, "payload-common.tar") == 0) {
		if (g_strcmp0(data->manifest_test_options.artifact_convert, "tar-extract") == 0) {
			g_autofree gchar *extracted = g_strdup_printf("%s.extracted", imagefilepath);

			g_assert_cmpint(g_stat(extracted, &buf), ==, 0);

			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "file", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "file-contents", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 8);
			g_assert_cmpuint(buf.st_nlink, ==, 1);

			g_assert_cmpint(test_lstat(extracted, "file-user", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 1000);
			g_assert_cmpint(buf.st_gid, ==, 1000);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "file-mtime", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpuint(buf.st_mtim.tv_sec, ==, 1694006436);
			/* squashfs timestamps have second granularity */
			g_assert_cmpuint(buf.st_mtim.tv_nsec, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "file-user", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 1000);
			g_assert_cmpint(buf.st_gid, ==, 1000);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "executable", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0755);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "dir", &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));

			g_assert_cmpint(test_lstat(extracted, "dir/file", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));

			g_assert_cmpint(test_lstat(extracted, "symlink", &buf), ==, 0);
			g_assert_true(S_ISLNK(buf.st_mode));

			g_assert_cmpint(test_lstat(extracted, "hardlink", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpuint(buf.st_nlink, ==, 2);

			g_assert_cmpint(test_lstat(extracted, "devchr", &buf), ==, 0);
			g_assert_true(S_ISCHR(buf.st_mode));
			g_assert_cmpuint(major(buf.st_rdev), ==, 1);
			g_assert_cmpuint(minor(buf.st_rdev), ==, 3);

			g_assert_cmpint(test_lstat(extracted, "devblk", &buf), ==, 0);
			g_assert_true(S_ISBLK(buf.st_mode));
			g_assert_cmpuint(major(buf.st_rdev), ==, 253);
			g_assert_cmpuint(minor(buf.st_rdev), ==, 0);

			g_assert_cmpint(test_lstat(extracted, "fifo", &buf), ==, 0);
			g_assert_true(S_ISFIFO(buf.st_mode));
		} else if (g_strcmp0(data->manifest_test_options.artifact_convert, "composefs") == 0) {
			g_autofree gchar *composefs_dir = g_strdup_printf("%s.cfs", imagefilepath);
			g_autofree gchar *composefs_image = g_strdup_printf("%s.cfs/image.cfs", imagefilepath);
			g_autofree gchar *composefs_store = g_strdup_printf("%s/.rauc-cfs-store", bundle->mount_point);

			g_assert_cmpint(g_stat(composefs_dir, &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(g_stat(composefs_image, &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(g_stat(composefs_store, &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
		} else {
			g_test_incomplete("unknown convert option for payload-common.tar");
			test_show_tree(bundle->mount_point, FALSE);
		}

		g_assert_false(g_file_test(imagefilepath, G_FILE_TEST_EXISTS));
	}

	if (g_strcmp0(data->manifest_test_options.artifact_file, "payload-special.tar") == 0) {
		if (g_strcmp0(data->manifest_test_options.artifact_convert, "tar-extract") == 0) {
			g_autofree gchar *extracted = g_strdup_printf("%s.extracted", imagefilepath);

			g_assert_cmpint(g_stat(extracted, &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "file", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "acl", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "xattr", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);

			g_assert_cmpint(test_lstat(extracted, "selinux", &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
			g_assert_cmpint(buf.st_size, ==, 0);
		} else if (g_strcmp0(data->manifest_test_options.artifact_convert, "composefs") == 0) {
			g_autofree gchar *composefs_dir = g_strdup_printf("%s.cfs", imagefilepath);
			g_autofree gchar *composefs_image = g_strdup_printf("%s.cfs/image.cfs", imagefilepath);
			g_autofree gchar *composefs_store = g_strdup_printf("%s/.rauc-cfs-store", bundle->mount_point);

			g_assert_cmpint(g_stat(composefs_dir, &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(g_stat(composefs_image, &buf), ==, 0);
			g_assert_true(S_ISREG(buf.st_mode));
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);

			g_assert_cmpint(g_stat(composefs_store, &buf), ==, 0);
			g_assert_true(S_ISDIR(buf.st_mode));
			g_assert_true((buf.st_mode & 0777) == 0700);
			g_assert_cmpint(buf.st_uid, ==, 0);
			g_assert_cmpint(buf.st_gid, ==, 0);
		} else {
			g_test_incomplete("unknown convert option for payload-special.tar");
			test_show_tree(bundle->mount_point, FALSE);
		}

		g_assert_false(g_file_test(imagefilepath, G_FILE_TEST_EXISTS));
	}
}

static void bundle_test_create_mount(BundleFixture *fixture, gconstpointer user_data)
{
	BundleData *data = (BundleData*)user_data;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (g_test_failed())
		return;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = mount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	if (data->manifest_test_options.artifact_file)
		check_artifacts(bundle, data);

	res = umount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
}

static void bundle_test_create_mount_extract_with_pre_check(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	r_context()->config->perform_pre_check = TRUE;

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = mount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	res = umount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	r_context()->config->perform_pre_check = FALSE;
}

static void bundle_test_create_check_mount_with_pre_check_corrupt(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	r_context()->config->perform_pre_check = TRUE;

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = mount_bundle(bundle, &ierror);
	g_assert_error(ierror, G_FILE_ERROR, G_FILE_ERROR_IO);
	g_assert_false(res);
	g_assert_nonnull(strstr(ierror->message, "failed between 1048576 and 1114112 bytes with error: Input/output error"));
}

static void bundle_test_extract_signature(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *outputsig = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	outputsig = g_build_filename(fixture->tmpdir, "bundle.sig", NULL);
	g_assert_nonnull(outputsig);

	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = extract_signature(bundle, outputsig, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_assert_true(g_file_test(outputsig, G_FILE_TEST_IS_REGULAR));
	g_clear_pointer(&outputsig, g_free);
	r_context()->config->perform_pre_check = FALSE;
}

static void assert_casync_manifest(RaucManifest *rm)
{
	RaucImage *test_img = NULL;

	g_assert_cmpuint(g_list_length(rm->images), ==, 2);

	test_img = g_list_nth_data(rm->images, 0);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->filename, ==, "rootfs.img.caibx");
	g_assert_cmpstr(test_img->checksum.digest, ==, "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31");
	g_assert_cmpuint(test_img->checksum.size, ==, 65536);

	test_img = g_list_nth_data(rm->images, 1);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->filename, ==, "appfs.img.caibx");
	g_assert_cmpstr(test_img->checksum.digest, ==, "c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479");
	g_assert_cmpuint(test_img->checksum.size, ==, 32768);
}

static void bundle_test_check_casync_old(BundleFixture *fixture, gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_true(test_copy_file("test", "good-casync-bundle-1.4.raucb", fixture->tmpdir, "bundle.raucb"));

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Reading bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Payload size (5661) is not a multiple of 4KiB.*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Verifying bundle signature*");

	res = check_bundle(bundlepath, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = load_manifest_from_bundle(bundle, &bundle->manifest, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle->manifest);

	assert_casync_manifest(bundle->manifest);
}

static void bundle_test_check_casync_new(BundleFixture *fixture, gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_true(test_copy_file("test", "good-casync-bundle-1.5.1.raucb", fixture->tmpdir, "bundle.raucb"));

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Reading bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Verifying bundle signature*");

	res = check_bundle(bundlepath, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = load_manifest_from_bundle(bundle, &bundle->manifest, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle->manifest);

	assert_casync_manifest(bundle->manifest);
}

// Hack to pull-in context for testing modification
extern RaucContext *context;

static void bundle_test_replace_signature(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *resignbundle = NULL;
	g_autofree gchar *replacebundle = NULL;
	g_autofree gchar *sigpath = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	replacebundle = g_build_filename(fixture->tmpdir, "replaced-bundle.raucb", NULL);
	g_assert_nonnull(replacebundle);
	resignbundle = g_build_filename(fixture->tmpdir, "resigned-bundle.raucb", NULL);
	g_assert_nonnull(resignbundle);

	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_clear_pointer(&bundle, free_bundle);

	/* Verify input bundle with 'dev' keyring */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* Use 'rel' key pair for resigning */
	replace_strdup(&context->certpath, "test/openssl-ca/rel/release-1.cert.pem");
	replace_strdup(&context->keypath, "test/openssl-ca/rel/private/release-1.pem");
	replace_strdup(&context->signing_keyringpath, "test/openssl-ca/rel-ca.pem");

	/* Resign bundle with 'rel' key to extract the signature below */
	res = resign_bundle(bundle, resignbundle, FALSE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_clear_pointer(&bundle, free_bundle);

	/* Verify resigned bundle with old 'dev' key */
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	sigpath = g_build_filename(fixture->tmpdir, "bundle.sig", NULL);
	g_assert_nonnull(sigpath);

	/* Extract 'rel' signature to replace it in the bundle */
	res = extract_signature(bundle, sigpath, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_true(g_file_test(sigpath, G_FILE_TEST_IS_REGULAR));
	g_clear_pointer(&bundle, free_bundle);

	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	res = replace_signature(bundle, sigpath, replacebundle, CHECK_BUNDLE_TRUST_ENV, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_clear_pointer(&bundle, free_bundle);

	res = check_bundle(replacebundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_clear_pointer(&bundle, free_bundle);

	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(replacebundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_clear_pointer(&bundle, free_bundle);

	/* Test without verify */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* Test will fail as we trying to replace existing bundle */
	res = replace_signature(bundle, sigpath, replacebundle, CHECK_BUNDLE_NO_VERIFY, &ierror);
	g_assert_error(ierror, G_FILE_ERROR, G_FILE_ERROR_EXIST);
	g_clear_error(&ierror);
	g_assert_false(res);

	/* Now it should works */
	g_remove(replacebundle);
	res = replace_signature(bundle, sigpath, replacebundle, CHECK_BUNDLE_NO_VERIFY, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_clear_pointer(&bundle, free_bundle);
	g_clear_pointer(&sigpath, g_free);

	res = check_bundle(replacebundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_pointer(&bundle, free_bundle);
	g_clear_error(&ierror);
	g_assert_false(res);

	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(replacebundle, &bundle, CHECK_BUNDLE_TRUST_ENV, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	// hacky restore of original signing_keyringpath
	replace_strdup(&context->signing_keyringpath, NULL);
}

static void bundle_test_resign(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *resignbundle = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	resignbundle = g_build_filename(fixture->tmpdir, "resigned-bundle.raucb", NULL);
	g_assert_nonnull(resignbundle);

	/* Input bundle must *not* verify against 'rel' keyring.
	 * Note we have to use r_context() here as a hack to avoid re-setting
	 * the context's 'pending' flag which would cause a re-initialization
	 * of context and thus overwrite content of 'config' member. */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify input bundle with 'dev' keyring */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* Use 'rel' key pair for resigning */
	replace_strdup(&context->certpath, "test/openssl-ca/rel/release-1.cert.pem");
	replace_strdup(&context->keypath, "test/openssl-ca/rel/private/release-1.pem");
	replace_strdup(&context->signing_keyringpath, "test/openssl-ca/rel-ca.pem");

	res = resign_bundle(bundle, resignbundle, FALSE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify resigned bundle with dev keyring.
	 * Note that this evaluates to true as the dev-ca.pem keyring contains
	 * both the production and the development certificate to allow
	 * installing development bundles as well as moving to production
	 * bundles. */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-only-ca.pem");
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_clear_pointer(&bundle, free_bundle);

	/* Verify resigned bundle with rel keyring */
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/rel-ca.pem");
	res = check_bundle(resignbundle, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	// hacky restore of original signing_keyringpath
	replace_strdup(&context->signing_keyringpath, NULL);
}

static void bundle_test_wrong_capath(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	replace_strdup(&r_context()->config->keyring_path, "does/not/exist.pem");

	g_assert_false(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror));
	g_assert_null(bundle);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_CA_LOAD);

	// hacky restore of original keyring_path
	replace_strdup(&r_context()->config->keyring_path, "test/openssl-ca/dev-ca.pem");
}

/* Test that checking against a keyring that contains a CRL results in a
 * warning when check-crl is disabled */
static void bundle_test_verify_no_crl_warn(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	r_context()->config->keyring_check_crl = FALSE;

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"Reading bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Detected CRL but CRL checking is disabled!");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
}

/* Test that verification of a bundle signed with a revoked key actually fails
 */
static void bundle_test_verify_revoked(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;

	g_assert_false(check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror));
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(bundle);
}

static void bundle_test_purpose_default(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies no purpose, everything except 'codesign' is allowed */

	g_message("testing default purpose with default cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'smimesign' with default cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'codesign' with default cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "codesign-rauc");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);

	g_message("testing purpose 'any' with default cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
}

static void bundle_test_purpose_email(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies the 'smimesign' usage, only default and that is allowed */

	g_message("testing default purpose with 'smimesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'smimesign' with 'smimesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'codesign' with 'smimesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "codesign-rauc");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'any' with 'smimesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
}

static void bundle_test_purpose_codesign(BundleFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* When the cert specifies the 'codesign' usage, only that is allowed */

	g_message("testing default purpose with 'codesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'smimesign' with 'codesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "smimesign");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_clear_error(&ierror);
	g_assert_false(res);
	g_assert_null(bundle);

	g_message("testing purpose 'codesign' with 'codesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "codesign-rauc");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Reading bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Verifying bundle*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Signer certificate should specify 'Key Usage' and mark it 'critical' to be fully CAB Forum compliant.");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Verified * signature*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Signer certificate should specify 'Key Usage' and mark it 'critical' to be fully CAB Forum compliant.");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	g_message("testing purpose 'any' with 'codesign' cert");
	replace_strdup(&r_context()->config->keyring_check_purpose, "any");
	res = check_bundle(fixture->bundlename, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_clear_pointer(&bundle, free_bundle);

	replace_strdup(&r_context()->config->keyring_check_purpose, NULL);
}

int main(int argc, char *argv[])
{
	g_autoptr(GPtrArray) ptrs = g_ptr_array_new_with_free_func(g_free);
	BundleData *bundle_data;
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	replace_strdup(&r_context_conf()->configpath, "test/test.conf");
	r_context();

	g_test_init(&argc, &argv, NULL);

	for (RManifestBundleFormat format = R_MANIFEST_FORMAT_PLAIN; format <= R_MANIFEST_FORMAT_VERITY; format++) {
		const gchar *format_name = r_manifest_bundle_format_to_str(format);

		bundle_data = dup_test_data(ptrs, (&(BundleData) {
			.manifest_test_options = {
				.format = format,
			},
		}));

		g_test_add(dup_test_printf(ptrs, "/bundle/check/empty/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up, test_check_empty_bundle,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/check/invalid/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up, test_check_invalid_bundle,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/create_extract/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_create_extract,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/create_mount/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_create_mount,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/extract_signature/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_extract_signature,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/resign/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_resign,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/replace_signature/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_replace_signature,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/wrong_capath/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_wrong_capath,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/verify_no_crl_warn/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_verify_no_crl_warn,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/verify_revoked/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle_autobuilder2, bundle_test_verify_revoked,
				bundle_fixture_tear_down_autobuilder2);

		g_test_add(dup_test_printf(ptrs, "/bundle/purpose/default/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle, bundle_test_purpose_default,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/purpose/email/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle_email, bundle_test_purpose_email,
				bundle_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/bundle/purpose/codesign/%s", format_name),
				BundleFixture, bundle_data,
				bundle_fixture_set_up_bundle_codesign, bundle_test_purpose_codesign,
				bundle_fixture_tear_down);

		if (format != R_MANIFEST_FORMAT_PLAIN) {
			g_test_add(dup_test_printf(ptrs, "/bundle/create_mount_extract_with_pre_check/%s", format_name),
					BundleFixture, bundle_data,
					bundle_fixture_set_up_bundle, bundle_test_create_mount_extract_with_pre_check,
					bundle_fixture_tear_down);

			g_test_add(dup_test_printf(ptrs, "/bundle/create_mount_with_pre_check_corrupt/%s", format_name),
					BundleFixture, bundle_data,
					bundle_fixture_set_up_bundle_corrupt, bundle_test_create_check_mount_with_pre_check_corrupt,
					bundle_fixture_tear_down);
		}
	}

	/* test casync manifest contents */
	g_test_add("/bundle/check_casync/old",
			BundleFixture, NULL,
			bundle_fixture_set_up, bundle_test_check_casync_old,
			bundle_fixture_tear_down);

	g_test_add("/bundle/check_casync/new",
			BundleFixture, NULL,
			bundle_fixture_set_up, bundle_test_check_casync_new,
			bundle_fixture_tear_down);

	/* test plain bundles against possible masks */
	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_PLAIN,
		},
		.bundle_formats = "plain",
	}));
	g_test_add("/bundle/format/plain/set-plain",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_PLAIN,
		},
		.bundle_formats = "verity",
	}));
	g_test_add("/bundle/format/plain/set-verity",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_check_error,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_PLAIN,
		},
		.bundle_formats = "plain verity",
	}));
	g_test_add("/bundle/format/plain/set-both",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_PLAIN,
		},
		.bundle_formats = "-plain",
	}));
	g_test_add("/bundle/format/plain/deny-plain",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_check_error,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_PLAIN,
		},
		.bundle_formats = "-verity",
	}));
	g_test_add("/bundle/format/plain/deny-verity",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	/* test verity bundles against possible masks */
	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
		},
		.bundle_formats = "plain",
	}));
	g_test_add("/bundle/format/verity/set-plain",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_check_error,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
		},
		.bundle_formats = "verity",
	}));
	g_test_add("/bundle/format/verity/set-verity",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
		},
		.bundle_formats = "plain verity",
	}));
	g_test_add("/bundle/format/verity/set-both",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
		},
		.bundle_formats = "-plain",
	}));
	g_test_add("/bundle/format/verity/deny-plain",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_extract,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
		},
		.bundle_formats = "-verity",
	}));
	g_test_add("/bundle/format/verity/deny-verity",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_check_error,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "artifact-1.file",
			.artifact_slotclass = "files",
		},
	}));
	g_test_add("/bundle/artifact/file",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_mount,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-common.tar",
			.artifact_slotclass = "trees",
			.artifact_convert = "tar-extract",
		},
	}));
	g_test_add("/bundle/artifact/tree/common-tar",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_mount,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-special.tar",
			.artifact_slotclass = "trees",
			.artifact_convert = "tar-extract",
		},
	}));
	g_test_add("/bundle/artifact/tree/special-tar",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_mount,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-common.tar",
			.artifact_slotclass = "composefs",
			.artifact_convert = "composefs",
		},
	}));

	g_test_add("/bundle/artifact/composefs/common-tar",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_mount,
			bundle_fixture_tear_down);

	bundle_data = dup_test_data(ptrs, (&(BundleData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-special.tar",
			.artifact_slotclass = "composefs",
			.artifact_convert = "composefs",
		},
	}));
	g_test_add("/bundle/artifact/composefs/special-tar",
			BundleFixture, bundle_data,
			bundle_fixture_set_up_bundle, bundle_test_create_mount,
			bundle_fixture_tear_down);

	return g_test_run();
}
