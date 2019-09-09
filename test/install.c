#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <context.h>
#include <install.h>
#include <manifest.h>
#include <mount.h>

#include "install-fixtures.h"
#include "common.h"

GMainLoop *r_loop = NULL;


static void install_fixture_set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL, FALSE, FALSE);
}

static void install_fixture_set_up_bundle_central_status(InstallFixture *fixture,
		gconstpointer user_data)
{

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, "test/test-global.conf");
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL, FALSE, FALSE);
}

static void install_fixture_set_up_bundle_custom_handler(InstallFixture *fixture,
		gconstpointer user_data)
{
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[handler]\n\
filename=custom_handler.sh\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, TRUE, FALSE);
}

static void install_fixture_set_up_bundle_install_check_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
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
filename=appfs.ext4";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, FALSE, TRUE);
}

static void install_fixture_set_up_bundle_install_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
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
filename=appfs.ext4\n\
hooks=install";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, FALSE, TRUE);
}

static void install_fixture_set_up_bundle_post_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
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
filename=appfs.ext4\n\
hooks=post-install";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, FALSE, TRUE);
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
	g_assert_nonnull(r_context()->bootslot);
}

static void install_test_target(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm = NULL;
	GHashTable *tgrp;
	GList *selected_images = NULL;
	GError *error = NULL;


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
filename=demofs.ext4\n\
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

	r_context_conf()->bootslot = g_strdup("system0");

	g_assert_true(determine_slot_states(NULL));

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rescue.0"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.0"))->state, ==, ST_BOOTED);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.1"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.1"))->state, ==, ST_INACTIVE);

	tgrp = determine_target_install_group();

	g_assert_nonnull(tgrp);

	g_assert_true(g_hash_table_contains(tgrp, "rescue"));
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));
	g_assert_true(g_hash_table_contains(tgrp, "demofs"));
	g_assert_true(g_hash_table_contains(tgrp, "bootloader"));
	g_assert_true(g_hash_table_contains(tgrp, "prebootloader"));
	//Deactivated check as the actual behavior is GHashTable-implementation-defined
	//g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rescue"))->name, ==, "rescue.0");
	/* We need to assure that the algorithm did not select the active group '0' */
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, !=, "rootfs.0");
	/* The algorithm could select either group '1' or group '2'. The actual
	 * selection is still GHashTable-implementation-defined.*/
	if (g_strcmp0(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, "rootfs.1") == 0) {
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.1");
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.1");
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "demofs"))->name, ==, "demofs.1");
	} else {
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.2");
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.2");
		g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "demofs"))->name, ==, "demofs.2");
	}
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "bootloader"))->name, ==, "bootloader.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "prebootloader"))->name, ==, "prebootloader.0");
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 6);

	selected_images = get_install_images(rm, tgrp, &error);
	g_assert_nonnull(selected_images);
	g_assert_no_error(error);

	g_assert_cmpint(g_list_length(selected_images), ==, 4);
	g_assert_cmpstr(((RaucImage*)g_list_nth_data(selected_images, 0))->filename, ==, "rootfs.ext4");
	g_assert_cmpstr(((RaucImage*)g_list_nth_data(selected_images, 1))->filename, ==, "appfs.ext4");
	g_assert_cmpstr(((RaucImage*)g_list_nth_data(selected_images, 2))->filename, ==, "demofs.ext4");
	g_assert_cmpstr(((RaucImage*)g_list_nth_data(selected_images, 3))->filename, ==, "bootloader.img");

	g_hash_table_unref(tgrp);
}

/* Test with image for non-redundant active target slot. */
static void test_install_determine_target_group_non_redundant(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GHashTable *tgrp = NULL;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);
	g_free(tmpdir);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system0");
	r_context();

	g_assert_true(determine_slot_states(NULL));

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* We must not have any updatable slot detected */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 0);

	g_hash_table_unref(tgrp);
}

/* Test a typical asynchronous slot setup (rootfs + rescuefs) with additional
 * childs */
static void test_install_target_group_async(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GHashTable *tgrp = NULL;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rescue.0]\n\
bootname=rescue\n\
device=/dev/null\n\
\n\
[slot.rescueapp.0]\n\
parent=rescue.0\n\
device=/dev/null\n\
\n\
[slot.rootfs.0]\n\
bootname=system\n\
device=/dev/null\n\
\n\
[slot.appfs.0]\n\
parent=rootfs.0\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);
	g_free(tmpdir);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("rescue");
	r_context();

	g_assert_true(determine_slot_states(NULL));

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.0");

	g_hash_table_unref(tgrp);
}

/* Test a typical synchronous slot setup (rootfs a + b) with appfs childs */
static void test_install_target_group_sync(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GHashTable *tgrp = NULL;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
\n\
[slot.appfs.1]\n\
parent=rootfs.1\n\
device=/dev/null\n\
\n\
[slot.appfs.0]\n\
parent=rootfs.0\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system1");
	r_context();

	g_assert_true(determine_slot_states(NULL));

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* First rootfs.0 and appfs.0 must be in target group, other not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.0");

	g_hash_table_unref(tgrp);
}

/* Test with extra loose (non-booted) groups in parent child relation */
static void test_install_target_group_loose(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GHashTable *tgrp = NULL;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.xloader.0]\n\
device=/dev/null\n\
\n\
[slot.bootloader.0]\n\
parent=xloader.0\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system0");
	r_context();

	g_assert_true(determine_slot_states(NULL));

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "xloader"));
	g_assert_true(g_hash_table_contains(tgrp, "bootloader"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "xloader"))->name, ==, "xloader.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "bootloader"))->name, ==, "bootloader.0");

	g_hash_table_unref(tgrp);
}

/* Test with 3 redundant slots */
static void test_install_target_group_n_redundant(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GHashTable *tgrp = NULL;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
\n\
[slot.rootfs.2]\n\
bootname=system2\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system1");
	r_context();

	g_assert_true(determine_slot_states(NULL));

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 1);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");

	g_hash_table_unref(tgrp);
}

/* Test image selection, default redundancy setup */
static void test_install_image_selection(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GBytes *data = NULL;
	RaucManifest *rm = NULL;
	GHashTable *tgrp = NULL;
	GError *error = NULL;
	GList *selected_images = NULL;
	RaucImage *image = NULL;

#define MANIFEST2 "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs]\n\
filename=rootfs.img\n\
\n\
[image.appfs]\n\
filename=appfs.img\n\
"

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
\n\
[slot.appfs.0]\n\
device=/dev/null\n\
\n\
[slot.appfs.1]\n\
device=/dev/null\n\
\n\
[slot.bootloader.0]\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system1");
	r_context();

	data = g_bytes_new_static(MANIFEST2, sizeof(MANIFEST2));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);

	determine_slot_states(&error);
	g_assert_no_error(error);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	selected_images = get_install_images(rm, tgrp, &error);
	g_assert_nonnull(selected_images);
	g_assert_no_error(error);

	/* We expecte the image selection to return both appfs.img and
	 * rootfs.img as we have matching slots for them. */
	g_assert_cmpint(g_list_length(selected_images), ==, 2);

	image = (RaucImage*) g_list_nth_data(selected_images, 0);
	g_assert_nonnull(image);
	g_assert_cmpstr(image->filename, ==, "rootfs.img");

	image = (RaucImage*) g_list_nth_data(selected_images, 1);
	g_assert_nonnull(image);
	g_assert_cmpstr(image->filename, ==, "appfs.img");

	g_hash_table_unref(tgrp);
}

static void test_install_image_selection_no_matching_slot(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GBytes *data = NULL;
	RaucManifest *rm = NULL;
	GHashTable *tgrp = NULL;
	GError *error = NULL;
	GList *selected_images = NULL;

#define MANIFEST2 "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs]\n\
filename=rootfs.img\n\
\n\
[image.appfs]\n\
filename=appfs.img\n\
"

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system1");
	r_context();

	data = g_bytes_new_static(MANIFEST2, sizeof(MANIFEST2));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);

	determine_slot_states(&error);
	g_assert_no_error(error);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* we expect the image mapping to fail as there is no slot candidate
	 * for image.appfs */
	selected_images = get_install_images(rm, tgrp, &error);
	g_assert_null(selected_images);
	g_assert_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED);

	g_hash_table_unref(tgrp);
}

static void test_install_image_readonly(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GBytes *data = NULL;
	RaucManifest *rm = NULL;
	GHashTable *tgrp = NULL;
	GError *error = NULL;
	GList *selected_images = NULL;

#define MANIFEST "\
[update]\n\
compatible=foo\n\
\n\
[image.rescuefs]\n\
filename=rootfs.img\n\
"

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rescuefs.0]\n\
device=/dev/null\n\
readonly=true\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system0");
	r_context();

	data = g_bytes_new_static(MANIFEST, sizeof(MANIFEST));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);

	determine_slot_states(&error);
	g_assert_no_error(error);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* we expect the image mapping to fail as there is an image for a
	 * readonly slot */
	selected_images = get_install_images(rm, tgrp, &error);
	g_assert_null(selected_images);
	g_assert_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED);

	g_hash_table_unref(tgrp);
}


static void test_install_image_variants(void)
{
	gchar *tmpdir = NULL;
	gchar* sysconfpath = NULL;
	GBytes *data = NULL;
	RaucManifest *rm = NULL;
	GHashTable *tgrp = NULL;
	GList *install_images = NULL;
	RaucImage *test_img = NULL;
	GError *error = NULL;

#define MANIFEST_VARIANT "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs.variant-1]\n\
filename=dummy\n\
\n\
[image.rootfs]\n\
filename=dummy\n\
"

#define MANIFEST_DEFAULT_VARIANT "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs]\n\
filename=dummy\n\
"

#define MANIFEST_OTHER_VARIANT "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs.variant-2]\n\
filename=dummy\n\
"

	const gchar *system_conf_variant = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
variant-name=variant-1\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=/dev/null\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf_variant, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	r_context_conf()->configpath = sysconfpath;
	r_context_conf()->bootslot = g_strdup("system1");
	r_context();

	determine_slot_states(&error);
	g_assert_no_error(error);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Test with manifest containing default and specific variant */
	data = g_bytes_new_static(MANIFEST_VARIANT, sizeof(MANIFEST_VARIANT));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_nonnull(rm);

	install_images = get_install_images(rm, tgrp, NULL);
	g_assert_nonnull(install_images);
	g_clear_pointer(&rm, free_manifest);

	g_assert_cmpint(g_list_length(install_images), ==, 1);

	test_img = (RaucImage*)g_list_nth_data(install_images, 0);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->variant, ==, "variant-1");

	/* Test with manifest containing only default variant */
	data = g_bytes_new_static(MANIFEST_DEFAULT_VARIANT, sizeof(MANIFEST_DEFAULT_VARIANT));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_nonnull(rm);

	install_images = get_install_images(rm, tgrp, NULL);
	g_assert_nonnull(install_images);
	g_clear_pointer(&rm, free_manifest);

	g_assert_cmpint(g_list_length(install_images), ==, 1);

	test_img = (RaucImage*)g_list_nth_data(install_images, 0);
	g_assert_nonnull(test_img);
	g_assert_null(test_img->variant);

	/* Test with manifest containing only non-matching specific variant (must fail) */
	data = g_bytes_new_static(MANIFEST_OTHER_VARIANT, sizeof(MANIFEST_OTHER_VARIANT));
	load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_nonnull(rm);

	install_images = get_install_images(rm, tgrp, NULL);
	g_assert_null(install_images);
	g_clear_pointer(&rm, free_manifest);

	g_hash_table_unref(tgrp);
}

static gboolean r_quit(gpointer data)
{
	g_assert_nonnull(r_loop);
	g_main_loop_quit(r_loop);

	return G_SOURCE_REMOVE;
}

static gboolean install_notify(gpointer data)
{
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
	GError *ierror = NULL;
	gboolean res;

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
	res = do_install_bundle(args, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

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
	g_assert_cmpstr(ierror->message, ==, "Installation error: Bundle rejected: Hook returned: No, I won't install this!");

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

static void install_fixture_set_up_system_user(InstallFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_fixture_set_up_system_user(fixture->tmpdir, NULL);
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
			install_fixture_set_up_system_user, install_test_bootname,
			install_fixture_tear_down);

	g_test_add("/install/target", InstallFixture, NULL,
			install_fixture_set_up_system_conf, install_test_target,
			install_fixture_tear_down);

	g_test_add_func("/install/target-group/non-redundant", test_install_determine_target_group_non_redundant);

	g_test_add_func("/install/target-group/async", test_install_target_group_async);

	g_test_add_func("/install/target-group/sync", test_install_target_group_sync);

	g_test_add_func("/install/target-group/loose", test_install_target_group_loose);

	g_test_add_func("/install/target-group/n-redundant", test_install_target_group_n_redundant);

	g_test_add_func("/install/image-selection/redundant", test_install_image_selection);

	g_test_add_func("/install/image-selection/non-matching", test_install_image_selection_no_matching_slot);

	g_test_add_func("/install/image-selection/readonly", test_install_image_readonly);

	g_test_add_func("/install/image-mapping/variants", test_install_image_variants);

	g_test_add("/install/bundle", InstallFixture, NULL,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	g_test_add("/install/bundle/central-status", InstallFixture, NULL,
			install_fixture_set_up_bundle_central_status, install_test_bundle,
			install_fixture_tear_down);

	g_test_add("/install/bundle-thread", InstallFixture, NULL,
			install_fixture_set_up_bundle, install_test_bundle_thread,
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
