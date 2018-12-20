#include <bundle.h>
#include <context.h>
#include <install.h>
#include <mount.h>

#include "install-fixtures.h"
#include "common.h"

void fixture_helper_fixture_set_up_system_user(gchar *tmpdir,
		const gchar *configname)
{
	gchar *configpath;
	gchar *certpath;
	gchar *keypath;
	gchar *capath;

	g_assert_nonnull(tmpdir);
	g_print("bundle tmpdir: %s\n", tmpdir);

	g_assert(test_mkdir_relative(tmpdir, "bin", 0777) == 0);
	g_assert(test_mkdir_relative(tmpdir, "content", 0777) == 0);
	g_assert(test_mkdir_relative(tmpdir, "mount", 0777) == 0);
	g_assert(test_mkdir_relative(tmpdir, "images", 0777) == 0);
	g_assert(test_mkdir_relative(tmpdir, "openssl-ca", 0777) == 0);
	g_assert(test_mkdir_relative(tmpdir, "slot", 0777) == 0);

	/* copy system config to temp dir*/
	if (!configname)
		configname = "test/test.conf";
	configpath = g_build_filename(tmpdir, "system.conf", NULL);
	g_assert_nonnull(configpath);
	g_assert_true(test_copy_file(configname, NULL, configpath, NULL));
	r_context_conf()->configpath = g_strdup(configpath);

	/* copy systeminfo, preinstall and postinstall handler to temp dir*/
	g_assert_true(test_copy_file("test/bin/systeminfo.sh", NULL,
			tmpdir, "bin/systeminfo.sh"));
	g_assert_true(test_copy_file("test/bin/preinstall.sh", NULL,
			tmpdir, "bin/preinstall.sh"));
	g_assert_true(test_copy_file("test/bin/postinstall.sh", NULL,
			tmpdir, "bin/postinstall.sh"));

	/* copy cert */
	certpath = g_build_filename(tmpdir, "openssl-ca/release-1.cert.pem", NULL);
	g_assert_nonnull(certpath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/release-1.cert.pem", NULL, certpath, NULL));
	r_context_conf()->certpath = g_strdup(certpath);

	/* copy key */
	keypath = g_build_filename(tmpdir, "openssl-ca/release-1.pem", NULL);
	g_assert_nonnull(keypath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/private/release-1.pem", NULL, keypath, NULL));
	r_context_conf()->keypath = g_strdup(keypath);

	/* copy ca */
	capath = g_build_filename(tmpdir, "openssl-ca/dev-ca.pem", NULL);
	g_assert_nonnull(capath);
	g_assert_true(test_copy_file("test/openssl-ca/dev-ca.pem", NULL,
			tmpdir, "openssl-ca/dev-ca.pem"));

	/* Setup pseudo devices */
	g_assert(test_prepare_dummy_file(tmpdir, "images/rootfs-0",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(tmpdir, "images/appfs-0",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(tmpdir, "images/rootfs-1",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(tmpdir, "images/appfs-1",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert_true(test_make_filesystem(tmpdir, "images/rootfs-0"));
	g_assert_true(test_make_filesystem(tmpdir, "images/appfs-0"));
	g_assert_true(test_make_filesystem(tmpdir, "images/rootfs-1"));
	g_assert_true(test_make_filesystem(tmpdir, "images/appfs-1"));

	/* Set dummy bootname provider */
	r_context_conf()->bootslot = g_strdup("system0");

	g_free(configpath);
	g_free(certpath);
	g_free(keypath);
	g_free(capath);
}

void fixture_helper_set_up_system(gchar *tmpdir,
		const gchar *configname)
{
	gchar *slotfile;
	gchar *slotpath;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	fixture_helper_fixture_set_up_system_user(tmpdir, configname);

	/* Make images user-writable */
	test_make_slot_user_writable(tmpdir, "images/rootfs-0");
	test_make_slot_user_writable(tmpdir, "images/appfs-0");
	test_make_slot_user_writable(tmpdir, "images/rootfs-1");
	test_make_slot_user_writable(tmpdir, "images/appfs-1");

	/* Provide active mounted slot */
	slotfile = g_build_filename(tmpdir, "images/rootfs-0", NULL);
	slotpath = g_build_filename(tmpdir, "slot", NULL);
	g_assert(test_mount(slotfile, slotpath));

	g_free(slotfile);
	g_free(slotpath);
}

void fixture_helper_set_up_bundle(gchar *tmpdir,
		const gchar* manifest_content,
		gboolean handler,
		gboolean hook)
{
	gchar *contentdir;
	gchar *bundlepath;
	gchar *mountdir;
	gchar *testfilepath;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	g_assert_nonnull(tmpdir);

	contentdir = g_build_filename(tmpdir, "content", NULL);
	bundlepath = g_build_filename(tmpdir, "bundle.raucb", NULL);
	mountdir = g_build_filename(tmpdir, "mnt", NULL);
	testfilepath = g_build_filename(mountdir, "verify.txt", NULL);

	/* Setup bundle content */
	g_assert(test_prepare_dummy_file(tmpdir, "content/rootfs.ext4",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(tmpdir, "content/appfs.ext4",
			SLOT_SIZE, "/dev/zero") == 0);
	g_assert_true(test_make_filesystem(tmpdir, "content/rootfs.ext4"));
	g_assert_true(test_make_filesystem(tmpdir, "content/appfs.ext4"));
	if (manifest_content) {
		g_assert_true(write_tmp_file(tmpdir, "content/manifest.raucm", manifest_content, NULL));
	} else {
		g_assert(test_prepare_manifest_file(tmpdir, "content/manifest.raucm", FALSE, hook) == 0);
	}

	/* Make images user-writable */
	test_make_slot_user_writable(tmpdir, "content/rootfs.ext4");
	test_make_slot_user_writable(tmpdir, "content/appfs.ext4");

	/* Write test file to slot */
	g_assert(test_mkdir_relative(tmpdir, "mnt", 0777) == 0);
	g_assert_true(test_mount(g_build_filename(tmpdir, "content/rootfs.ext4", NULL), mountdir));
	g_assert_true(g_file_set_contents(testfilepath, "0xdeadbeaf", -1, NULL));
	g_assert_true(r_umount(mountdir, NULL));
	g_assert(test_rmdir(tmpdir, "mnt") == 0);

	/* Copy custom handler */
	if (handler) {
		g_assert_true(test_copy_file("test/install-content/custom_handler.sh", NULL,
				tmpdir, "content/custom_handler.sh"));
	}

	/* Copy hook */
	if (hook) {
		g_assert_true(test_copy_file("test/install-content/hook.sh", NULL,
				tmpdir, "content/hook.sh"));
	}

	/* Update checksums in manifest */
	g_assert_true(update_manifest(contentdir, FALSE, NULL));

	/* Create bundle */
	g_assert_true(create_bundle(bundlepath, contentdir, NULL));

	g_free(bundlepath);
	g_free(contentdir);
	g_free(mountdir);
	g_free(testfilepath);
}

