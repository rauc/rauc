#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <config.h>
#include <install.h>
#include <manifest.h>
#include <mount.h>

#include "common.h"

GMainLoop *r_loop = NULL;

typedef struct {
	gchar *tmpdir;
} InstallFixture;

#define SLOT_SIZE (10*1024*1024)

static void install_fixture_set_up_user(InstallFixture *fixture,
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
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rescue-0",
				         SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rootfs-0",
				         SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/appfs-0",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rootfs-1",
				         SLOT_SIZE, "/dev/zero") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/appfs-1",
					 SLOT_SIZE, "/dev/zero") == 0);
	g_assert_true(test_make_filesystem(fixture->tmpdir, "images/rescue-0"));
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

static void install_fixture_set_up(InstallFixture *fixture,
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

static void set_up_bundle(InstallFixture *fixture,
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

	install_fixture_set_up(fixture, user_data);

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

static void install_fixture_set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data) {
	set_up_bundle(fixture, user_data, NULL, FALSE, FALSE);
}

static void install_fixture_set_up_bundle_custom_handler(InstallFixture *fixture,
		gconstpointer user_data) {
	set_up_bundle(fixture, user_data, NULL, TRUE, FALSE);
}

static void install_fixture_set_up_bundle_install_check_hook(InstallFixture *fixture,
		gconstpointer user_data) {
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[hooks]\n\
filename=hook.sh\n\
hooks=install-check\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
\n\
[image.appfs]\n\
filename=rootfs.ext4";

	set_up_bundle(fixture, user_data, manifest_file, FALSE, TRUE);
}

static void install_fixture_set_up_bundle_install_hook(InstallFixture *fixture,
		gconstpointer user_data) {
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[hooks]\n\
filename=hook.sh\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
hooks=install\n\
\n\
[image.appfs]\n\
filename=rootfs.ext4\n\
hooks=install";

	set_up_bundle(fixture, user_data, manifest_file, FALSE, TRUE);
}

static void install_fixture_set_up_bundle_post_hook(InstallFixture *fixture,
		gconstpointer user_data) {
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[hooks]\n\
filename=hook.sh\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
hooks=post-install\n\
\n\
[image.appfs]\n\
filename=rootfs.ext4\n\
hooks=post-install";

	set_up_bundle(fixture, user_data, manifest_file, FALSE, TRUE);
}

static void install_fixture_set_up_system_conf(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar* pathname = NULL;
	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rescue.0]\n\
device=/path/to/rescue0\n\
type=raw\n\
bootname=factory0\n\
readonly=true\n\
\n\
[slot.rescue.1]\n\
device=/path/to/rescue1\n\
type=raw\n\
bootname=factory1\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/path/to/rootfs0\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/path/to/rootfs1\n\
bootname=system1\n\
\n\
[slot.rootfs.2]\n\
device=/path/to/rootfs2\n\
bootname=system2\n\
\n\
[slot.appfs.2]\n\
device=/path/to/appfs1\n\
parent=rootfs.2\n\
\n\
[slot.appfs.1]\n\
device=/path/to/appfs1\n\
parent=rootfs.1\n\
\n\
[slot.appfs.0]\n\
device=/path/to/appfs0\n\
parent=rootfs.0\n\
\n\
[slot.demofs.0]\n\
device=/path/to/demofs0\n\
parent=appfs.0\n\
\n\
[slot.demofs.1]\n\
device=/path/to/demofs1\n\
parent=appfs.1\n\
\n\
[slot.demofs.2]\n\
device=/path/to/demofs2\n\
parent=appfs.2\n\
\n\
[slot.bootloader.0]\n\
device=/path/to/bootloader\n\
\n\
[slot.prebootloader.0]\n\
device=/path/to/prebootloader";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("system conf tmpdir: %s\n", fixture->tmpdir);

	pathname = write_tmp_file(fixture->tmpdir, "system.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);
	r_context_conf()->configpath = g_strdup(pathname);

	g_free(pathname);
}

static void rename_manifest(const gchar *contentdir, const gchar *targetname) {
	gchar *manifestpath1 = g_strconcat(contentdir,
			"/manifest.raucm", NULL);
	gchar *manifestpath2 = g_strconcat(contentdir,
			"/", targetname, ".raucm", NULL);
	gchar *signaturepath1 = g_strconcat(contentdir,
			"/manifest.raucm.sig", NULL);
	gchar *signaturepath2 = g_strconcat(contentdir,
			"/", targetname, ".raucm.sig", NULL);

	g_assert(g_rename(manifestpath1, manifestpath2) == 0);
	g_assert(g_rename(signaturepath1, signaturepath2) == 0);

	g_free(manifestpath1);
	g_free(manifestpath2);
	g_free(signaturepath1);
	g_free(signaturepath2);
}

static void install_fixture_set_up_network(InstallFixture *fixture,
		gconstpointer user_data) {
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucFile *files;
	gchar *contentdir;
	gchar *manifestpath;

#if !ENABLE_NETWORK
	return;
#endif

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	install_fixture_set_up(fixture, user_data);

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	manifestpath = g_build_filename(fixture->tmpdir, "content/manifest.raucm", NULL);

	/* Setup bundle content */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/vmlinuz-1",
					 64*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/vmlinuz-2",
					 64*1024, "/dev/urandom") == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/initramfs-1",
					 32*1024, "/dev/urandom") == 0);

	g_assert_true(test_copy_file(fixture->tmpdir, "content/vmlinuz-2",
				fixture->tmpdir, "slot/vmlinuz"));

	/* Prepare manifest */
	rm->update_compatible = g_strdup("Test Config");
	rm->update_version = g_strdup("2011.03-2");

	files = g_new0(RaucFile, 2);

	files[0].slotclass = g_strdup("rootfs");
	files[0].filename = g_strdup("vmlinuz-1");
	files[0].destname = g_strdup("vmlinuz");
	rm->files = g_list_append(rm->files, &files[0]);

	files[1].slotclass = g_strdup("rootfs");
	files[1].filename = g_strdup("initramfs-1");
	files[1].destname = g_strdup("initramfs");
	rm->files = g_list_append(rm->files, &files[1]);

	/* Create signed manifest */
	g_assert_true(save_manifest_file(manifestpath, rm, NULL));
	g_assert_true(update_manifest(contentdir, TRUE, NULL));
	rename_manifest(contentdir, "manifest-1");

	/* Modify manifest vmlinuz-1 -> vmlinuz-2 */
	files[0].filename = g_strdup("vmlinuz-2");
	g_assert_true(save_manifest_file(manifestpath, rm, NULL));
	g_assert_true(update_manifest(contentdir, TRUE, NULL));
	rename_manifest(contentdir, "manifest-2");

	/* Modify manifest (no initramfs) */
	files[0].filename = g_strdup("vmlinuz-2");
	rm->files = g_list_remove(rm->files, &files[1]);
	g_assert_true(save_manifest_file(manifestpath, rm, NULL));
	g_assert_true(update_manifest(contentdir, TRUE, NULL));
	rename_manifest(contentdir, "manifest-3");

	free_manifest(rm);
	g_free(manifestpath);
	g_free(contentdir);
}

static void install_fixture_tear_down(InstallFixture *fixture,
		gconstpointer user_data)
{
	if (!fixture->tmpdir)
		return;

	test_umount(fixture->tmpdir, "slot");
	test_rm_tree(fixture->tmpdir, "");
}

static void install_test_bootname(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_assert_nonnull(get_bootname());
}

static void install_test_target(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm = NULL;
	GHashTable *tgrp;


	const gchar *manifest_file = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3\n\
filename=rootfs.ext4\n\
\n\
[image.appfs]\n\
sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca\n\
filename=appfs.ext4\n\
\n\
[image.demofs]\n\
sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca\n\
filename=appfs.ext4\n\
\n\
[file.rootfs/vmlinuz]\n\
sha256=5fb50868cd1f2e34ff531d6680c9b734ba35ed4944072f396a50871e9c2d5155\n\
filename=linux.img\n\
\n\
[file.rootfs/initramfs]\n\
sha256=d37328d0d80779573b204762ee8aa011c22a5c43088f7541a8c1f591f8e3be6a\n\
filename=initramfs.cpio.gz\n\
\n\
[image.bootloader]\n\
sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca\n\
filename=bootloader.img";
	gchar* pathname = write_tmp_file(fixture->tmpdir, "manifest.raucm", manifest_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_true(load_manifest_file(pathname, &rm, NULL));

	g_assert_true(determine_slot_states(NULL));

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rescue.0"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.0"))->state, ==, ST_BOOTED);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.1"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.1"))->state, ==, ST_INACTIVE);

	tgrp = determine_target_install_group(rm);

	g_assert_nonnull(tgrp);

	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.1");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.1");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "demofs"))->name, ==, "demofs.1");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "bootloader"))->name, ==, "bootloader.0");
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 4);
}

static gboolean r_quit(gpointer data) {
	g_assert_nonnull(r_loop);
	g_main_loop_quit(r_loop);

	return G_SOURCE_REMOVE;
}

static gboolean install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_assert_nonnull(args);

	return G_SOURCE_REMOVE;
}

static gboolean install_cleanup(gpointer data)
{
	RaucInstallArgs *args = data;

	g_assert_nonnull(args);
	g_assert_cmpint(args->status_result, ==, 0);
	g_assert_false(g_queue_is_empty(&args->status_messages));

	g_queue_clear(&args->status_messages);
	install_args_free(args);

	g_idle_add(r_quit, NULL);

	return G_SOURCE_REMOVE;
}

static void install_test_bundle(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath, *mountprefix, *slotfile, *testfilepath, *mountdir;
	RaucInstallArgs *args;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountprefix = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountprefix);
	r_context_conf()->mountprefix = mountprefix;
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	args = install_args_new();
	args->name = g_strdup(bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	g_assert_true(do_install_bundle(args, NULL));

	slotfile = g_build_filename(fixture->tmpdir, "images/rootfs-1", NULL);
	mountdir = g_build_filename(fixture->tmpdir, "mnt", NULL);
	g_assert(test_mkdir_relative(fixture->tmpdir, "mnt", 0777) == 0);
	testfilepath = g_build_filename(mountdir, "verify.txt", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert(g_file_test(testfilepath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mnt"));

	args->status_result = 0;

	g_free(bundlepath);
	g_free(slotfile);
	g_free(mountdir);
	g_free(testfilepath);
}

static void install_test_network(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *manifesturl, *mountdir;

#if !ENABLE_NETWORK
	g_test_skip("Compiled without network support");
	return;
#endif

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	manifesturl = g_strconcat("file://", fixture->tmpdir,
				  "/content/manifest-1.raucm", NULL);
	g_assert_true(do_install_network(manifesturl, NULL));
	g_free(manifesturl);

	manifesturl = g_strconcat("file://", fixture->tmpdir,
				  "/content/manifest-2.raucm", NULL);
	g_assert_true(do_install_network(manifesturl, NULL));
	g_free(manifesturl);

	manifesturl = g_strconcat("file://", fixture->tmpdir,
				  "/content/manifest-3.raucm", NULL);
	g_assert_true(do_install_network(manifesturl, NULL));
	g_free(manifesturl);
}

static void install_test_bundle_thread(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucInstallArgs *args = install_args_new();
	gchar *bundlepath, *mountdir;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	args->name = g_strdup(bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;

	r_loop = g_main_loop_new(NULL, FALSE);
	g_assert_true(install_run(args));
	g_main_loop_run(r_loop);
	g_clear_pointer(&r_loop, g_main_loop_unref);

	g_free(bundlepath);
}

static void install_test_network_thread(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucInstallArgs *args = install_args_new();
	gchar *manifesturl, *mountdir;

#if !ENABLE_NETWORK
	g_test_skip("Compiled without network support");
	return;
#endif

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	manifesturl = g_strconcat("file://", fixture->tmpdir,
				  "/content/manifest-1.raucm", NULL);
	g_assert_true(do_install_network(manifesturl, NULL));
	args->name = g_strdup(manifesturl);
	args->notify = install_notify;
	args->cleanup = install_cleanup;

	r_loop = g_main_loop_new(NULL, FALSE);
	g_assert_true(install_run(args));
	g_main_loop_run(r_loop);
	g_clear_pointer(&r_loop, g_main_loop_unref);
	g_free(manifesturl);
}

static void install_test_bundle_hook_install_check(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath, *mountdir;
	RaucInstallArgs *args;
	GError *ierror = NULL;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	args = install_args_new();
	args->name = g_strdup(bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	g_assert_false(do_install_bundle(args, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Handler error: Bundle rejected: Hook returned: No, I won't install this!");

	args->status_result = 0;

	g_free(bundlepath);
	g_free(mountdir);
}

static void install_test_bundle_hook_install(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath, *mountdir, *slotfile, *stamppath, *hookfilepath;
	RaucInstallArgs *args;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	args = install_args_new();
	args->name = g_strdup(bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	res = do_install_bundle(args, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	slotfile = g_build_filename(fixture->tmpdir, "images/rootfs-1", NULL);
	hookfilepath = g_build_filename(mountdir, "hook-install", NULL);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert_true(g_file_test(hookfilepath, G_FILE_TEST_IS_REGULAR));
	g_assert_false(g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));
	g_free(hookfilepath);
	g_free(stamppath);
	g_free(slotfile);

	slotfile = g_build_filename(fixture->tmpdir, "images/appfs-1", NULL);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert_false(g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));
	g_free(stamppath);
	g_free(slotfile);

	args->status_result = 0;

	g_free(bundlepath);
}

static void install_test_bundle_hook_post_install(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath, *mountdir, *slotfile, *testfilepath, *stamppath;
	RaucInstallArgs *args;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = mountdir;
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	args = install_args_new();
	args->name = g_strdup(bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	g_assert_true(do_install_bundle(args, NULL));

	slotfile = g_build_filename(fixture->tmpdir, "images/rootfs-1", NULL);
	testfilepath = g_build_filename(mountdir, "verify.txt", NULL);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert(g_file_test(testfilepath, G_FILE_TEST_IS_REGULAR));
	g_assert(g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));
	g_free(stamppath);
	g_free(slotfile);
	g_free(testfilepath);

	slotfile = g_build_filename(fixture->tmpdir, "images/appfs-1", NULL);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert(!g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));
	g_free(stamppath);
	g_free(slotfile);

	args->status_result = 0;

	g_free(bundlepath);
}

int main(int argc, char *argv[])
{
	gchar *path;
	setlocale(LC_ALL, "C");

	path = g_strdup_printf("%s:%s", g_getenv("PATH"), "test/bin");
	g_setenv("PATH", path, TRUE);
	g_free(path);

	g_test_init(&argc, &argv, NULL);

	g_test_add("/install/bootname", InstallFixture, NULL,
		   install_fixture_set_up_user, install_test_bootname,
		   install_fixture_tear_down);

	g_test_add("/install/target", InstallFixture, NULL,
		   install_fixture_set_up_system_conf, install_test_target,
		   install_fixture_tear_down);

	g_test_add("/install/bundle", InstallFixture, NULL,
		   install_fixture_set_up_bundle, install_test_bundle,
		   install_fixture_tear_down);

	g_test_add("/install/network", InstallFixture, NULL,
		   install_fixture_set_up_network, install_test_network,
		   install_fixture_tear_down);

	g_test_add("/install/bundle-thread", InstallFixture, NULL,
		   install_fixture_set_up_bundle, install_test_bundle_thread,
		   install_fixture_tear_down);

	g_test_add("/install/network-thread", InstallFixture, NULL,
		   install_fixture_set_up_network, install_test_network_thread,
		   install_fixture_tear_down);

	g_test_add("/install/bundle-custom-handler", InstallFixture, NULL,
		   install_fixture_set_up_bundle_custom_handler, install_test_bundle,
		   install_fixture_tear_down);

	g_test_add("/install/bundle-hook/install-check", InstallFixture, NULL,
		   install_fixture_set_up_bundle_install_check_hook, install_test_bundle_hook_install_check,
		   install_fixture_tear_down);

	g_test_add("/install/bundle-hook/slot-install", InstallFixture, NULL,
		   install_fixture_set_up_bundle_install_hook, install_test_bundle_hook_install,
		   install_fixture_tear_down);

	g_test_add("/install/bundle-hook/slot-post-install", InstallFixture, NULL,
		   install_fixture_set_up_bundle_post_hook, install_test_bundle_hook_post_install,
		   install_fixture_tear_down);

	return g_test_run();
}
