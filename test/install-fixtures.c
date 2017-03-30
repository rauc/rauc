#include <bundle.h>
#include <context.h>
#include <install.h>
#include <mount.h>

#include "install-fixtures.h"
#include "common.h"

void install_fixture_set_up_user(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *configpath;
	gchar *certpath;
	gchar *keypath;
	gchar *capath;

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);

	g_assert(test_mkdir_relative(fixture->tmpdir, "bin", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "content", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "mount", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "images", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "openssl-ca", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "slot", 0777) == 0);

	/* copy system config to temp dir*/
	configpath = g_build_filename(fixture->tmpdir, "system.conf", NULL);
	g_assert_nonnull(configpath);
	g_assert_true(test_copy_file("test/test.conf", NULL, configpath, NULL));
	r_context_conf()->configpath = g_strdup(configpath);

	/* copy systeminfo, preinstall and postinstall handler to temp dir*/
	g_assert_true(test_copy_file("test/bin/systeminfo.sh", NULL,
				fixture->tmpdir, "bin/systeminfo.sh"));
	g_assert_true(test_copy_file("test/bin/preinstall.sh", NULL,
				fixture->tmpdir, "bin/preinstall.sh"));
	g_assert_true(test_copy_file("test/bin/postinstall.sh", NULL,
				fixture->tmpdir, "bin/postinstall.sh"));

	/* copy cert */
	certpath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.cert.pem", NULL);
	g_assert_nonnull(certpath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/release-1.cert.pem", NULL, certpath, NULL));
	r_context_conf()->certpath = g_strdup(certpath);

	/* copy key */
	keypath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.pem", NULL);
	g_assert_nonnull(keypath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/private/release-1.pem", NULL, keypath, NULL));
	r_context_conf()->keypath = g_strdup(keypath);

	/* copy ca */
	capath = g_build_filename(fixture->tmpdir, "openssl-ca/dev-ca.pem", NULL);
	g_assert_nonnull(capath);
	g_assert_true(test_copy_file("test/openssl-ca/dev-ca.pem", NULL,
				fixture->tmpdir, "openssl-ca/dev-ca.pem"));

	/* Setup pseudo devices */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rootfs-0",
				         SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/appfs-0",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rootfs-1",
				         SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/appfs-1",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert_true(test_make_filesystem(fixture->tmpdir, "images/rootfs-0"));
	g_assert_true(test_make_filesystem(fixture->tmpdir, "images/appfs-0"));
	g_assert_true(test_make_filesystem(fixture->tmpdir, "images/rootfs-1"));
	g_assert_true(test_make_filesystem(fixture->tmpdir, "images/appfs-1"));

	/* Set dummy bootname provider */
	set_bootname_provider(test_bootname_provider);

	g_free(configpath);
	g_free(certpath);
	g_free(keypath);
	g_free(capath);
}

void install_fixture_set_up(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *slotfile;
	gchar *slotpath;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	install_fixture_set_up_user(fixture, user_data);

	/* Make images user-writable */
	test_make_slot_user_writable(fixture->tmpdir, "images/rootfs-0");
	test_make_slot_user_writable(fixture->tmpdir, "images/appfs-0");
	test_make_slot_user_writable(fixture->tmpdir, "images/rootfs-1");
	test_make_slot_user_writable(fixture->tmpdir, "images/appfs-1");
	
	/* Provide active mounted slot */
	slotfile = g_build_filename(fixture->tmpdir, "images/rootfs-0", NULL);
	slotpath = g_build_filename(fixture->tmpdir, "slot", NULL);
	g_assert(test_mount(slotfile, slotpath));

	g_free(slotfile);
	g_free(slotpath);
}

void set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data,
		const gchar* manifest_content,
		gboolean handler,
		gboolean hook) {
	gchar *contentdir;
	gchar *bundlepath;
	gchar *mountdir;
	gchar *testfilepath;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	mountdir = g_build_filename(fixture->tmpdir, "mnt", NULL);
	testfilepath = g_build_filename(mountdir, "verify.txt", NULL);

	/* Setup bundle content */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/rootfs.ext4",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/appfs.ext4",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert_true(test_make_filesystem(fixture->tmpdir, "content/rootfs.ext4"));
	g_assert_true(test_make_filesystem(fixture->tmpdir, "content/appfs.ext4"));
	if (manifest_content) {
		g_assert_true(write_tmp_file(fixture->tmpdir, "content/manifest.raucm", manifest_content, NULL));
	} else {
		g_assert(test_prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm", FALSE, hook) == 0);
	}

	/* Make images user-writable */
	test_make_slot_user_writable(fixture->tmpdir, "content/rootfs.ext4");
	test_make_slot_user_writable(fixture->tmpdir, "content/appfs.ext4");

	/* Write test file to slot */
	g_assert(test_mkdir_relative(fixture->tmpdir, "mnt", 0777) == 0);
	g_assert_true(test_mount(g_build_filename(fixture->tmpdir, "content/rootfs.ext4", NULL), mountdir));
	g_assert_true(g_file_set_contents(testfilepath, "0xdeadbeaf", -1, NULL));
	g_assert_true(r_umount(mountdir, NULL));
	g_assert(test_rmdir(fixture->tmpdir, "mnt") == 0);

	/* Copy custom handler */
	if (handler) {
		g_assert_true(test_copy_file("test/install-content/custom_handler.sh", NULL,
					fixture->tmpdir, "content/custom_handler.sh"));
	}

	/* Copy hook */
	if (hook) {
		g_assert_true(test_copy_file("test/install-content/hook.sh", NULL,
					fixture->tmpdir, "content/hook.sh"));
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

