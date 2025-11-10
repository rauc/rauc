#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <context.h>
#include <install.h>
#include <manifest.h>
#include <mount.h>

#include "install_fixtures.h"
#include "common.h"

GMainLoop *r_loop = NULL;

typedef struct {
	const gchar **message_needles;
	GQuark install_err_domain;
	gint install_err_code;
	SystemTestOptions system_test_options;
	ManifestTestOptions manifest_test_options;
} InstallData;

static void install_fixture_set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL, &data->system_test_options);
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_central_status(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, "test/test-global.conf", NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_already_mounted(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[hooks]\n\
filename=hook.sh\n\
\n\
[image.bootloader]\n\
filename=bootloader.ext4\n\
hooks=install\n\
";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_custom_handler(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[handler]\n\
filename=custom_handler.sh\n\
args=arg1 arg2\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_pre_post_install_handler(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[handler]\n\
pre-install=preinstall.sh\n\
post-install=postinstall.sh\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_install_check_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
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

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

/* Note: Also ensures having no image in a slot with an 'install' per-slot hook
 * is valid. */
static void install_fixture_set_up_bundle_install_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
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
hooks=install";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_post_hook(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
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

	fixture_helper_set_up_system(fixture->tmpdir, NULL, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_bundle_adaptive(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4\n\
adaptive=adaptive-test-method;block-hash-index";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, "test/test-datadir.conf", NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_slot_skipping(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	const gchar *manifest_file = "\
[update]\n\
compatible=Test Config\n\
\n\
[image.rootfs]\n\
filename=rootfs.ext4";

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, "test/test-install-same-false.conf", NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, manifest_file, &data->manifest_test_options);
}

static void install_fixture_set_up_system_conf(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar* pathname = NULL;
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
	g_test_message("system conf tmpdir: %s\n", fixture->tmpdir);

	pathname = write_tmp_file(fixture->tmpdir, "system.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);
	replace_strdup(&r_context_conf()->configpath, pathname);
}

static void install_fixture_tear_down(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;

	if (!fixture->tmpdir)
		return;

	if (data && data->manifest_test_options.artifact_file) {
		g_autofree gchar *tree_cmd = g_strdup_printf("tree -a %s/repos", fixture->tmpdir);
		system(tree_cmd);
	}

	test_umount(fixture->tmpdir, "slot");
	test_umount(fixture->tmpdir, "bootloader");
	test_rm_tree(fixture->tmpdir, "");
	g_free(fixture->tmpdir);
}

static void install_test_bootname(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_assert_nonnull(r_context()->bootslot);
}

static void install_test_target(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	g_autoptr(GError) error = NULL;
	gboolean result;

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
[image.bootloader]\n\
sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca\n\
filename=bootloader.img";
	g_autofree gchar* pathname = write_tmp_file(fixture->tmpdir, "manifest.raucm", manifest_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_true(load_manifest_file(pathname, &rm, NULL));

	replace_strdup(&r_context_conf()->bootslot, "system0");

	result = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(result);

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

	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_no_error(error);
	g_assert_nonnull(install_plans);

	g_assert_cmpint(install_plans->len, ==, 4);
	g_assert_cmpstr(((RImageInstallPlan*)g_ptr_array_index(install_plans, 0))->image->filename, ==, "rootfs.ext4");
	g_assert_cmpstr(((RImageInstallPlan*)g_ptr_array_index(install_plans, 1))->image->filename, ==, "appfs.ext4");
	g_assert_cmpstr(((RImageInstallPlan*)g_ptr_array_index(install_plans, 2))->image->filename, ==, "demofs.ext4");
	g_assert_cmpstr(((RImageInstallPlan*)g_ptr_array_index(install_plans, 3))->image->filename, ==, "bootloader.img");
}

/* Test with image for non-redundant active target slot. */
static void test_install_determine_target_group_non_redundant(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

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

	/* Set up context */
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system0");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* We must not have any updatable slot detected */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 0);
}

/* Test a typical asynchronous slot setup (rootfs + rescuefs) with additional
 * children */
static void test_install_target_group_async(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

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

	/* Set up context */
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "rescue");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.0");
}

/* Test a typical synchronous slot setup (rootfs a + b) with appfs children */
static void test_install_target_group_sync(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system1");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* First rootfs.0 and appfs.0 must be in target group, other not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "appfs"))->name, ==, "appfs.0");
}

/* Test with extra loose (non-booted) groups in parent child relation */
static void test_install_target_group_loose(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system0");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
	g_assert_true(g_hash_table_contains(tgrp, "xloader"));
	g_assert_true(g_hash_table_contains(tgrp, "bootloader"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "xloader"))->name, ==, "xloader.0");
	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "bootloader"))->name, ==, "bootloader.0");
}

/* Test with 3 redundant slots */
static void test_install_target_group_n_redundant(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system1");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Rootfs must be in target group, rescue not */
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 1);
	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));

	g_assert_cmpstr(((RaucSlot*)g_hash_table_lookup(tgrp, "rootfs"))->name, ==, "rootfs.0");
}

/* Test image selection, default redundancy setup */
static void test_install_image_selection(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	const RImageInstallPlan *plan = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system1");
	r_context();

	data = g_bytes_new_static(MANIFEST2, sizeof(MANIFEST2));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_no_error(error);
	g_assert_nonnull(install_plans);

	/* We expect the image selection to return both appfs.img and
	 * rootfs.img as we have matching slots for them. */
	g_assert_cmpint(install_plans->len, ==, 2);

	plan = g_ptr_array_index(install_plans, 0);
	g_assert_nonnull(plan->image);
	g_assert_cmpstr(plan->image->filename, ==, "rootfs.img");

	plan = g_ptr_array_index(install_plans, 1);
	g_assert_nonnull(plan->image);
	g_assert_cmpstr(plan->image->filename, ==, "appfs.img");
}

static void test_install_image_selection_no_matching_slot(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system1");
	r_context();

	data = g_bytes_new_static(MANIFEST2, sizeof(MANIFEST2));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* we expect the image mapping to fail as there is no slot candidate
	 * for image.appfs */
	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_null(install_plans);
	g_assert_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED);
}

/* Test that r_install_make_plans() returns non-NULL if there is no booted slot
 * but the boot was marked as 'external' explicitly */
static void test_install_image_selection_boot_external(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	const RImageInstallPlan *plan = NULL;
	gboolean res;

#define MANIFEST3 "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs]\n\
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
[slot.rootfs.1]\n\
bootname=system1\n\
device=/dev/null\n\
";
	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "_external_"); /* mark as external */
	r_context();

	g_message("Bootname is: %s", r_context()->bootslot);

	data = g_bytes_new_static(MANIFEST3, sizeof(MANIFEST3));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* we expect the image mapping to fail as there is no slot candidate
	 * for image.appfs */
	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_no_error(error);
	g_assert_nonnull(install_plans);

	/* We expect a single rootfs slot to match */
	g_assert_cmpint(install_plans->len, ==, 1);

	plan = g_ptr_array_index(install_plans, 0);
	g_assert_nonnull(plan->image);
	g_assert_cmpstr(plan->image->filename, ==, "rootfs.img");
}

static void test_install_image_readonly(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	gboolean res;

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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system0");
	r_context();

	data = g_bytes_new_static(MANIFEST, sizeof(MANIFEST));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* we expect the image mapping to fail as there is an image for a
	 * readonly slot */
	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_null(install_plans);
	g_assert_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED);
}

static void test_install_image_variants(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GHashTable) tgrp = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	const RImageInstallPlan *plan = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res;

	const gchar *manifest_variant = "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs.variant-1]\n\
filename=dummy.img\n\
\n\
[image.rootfs]\n\
filename=dummy.img\n\
";
	const gchar *manifest_default_variant = "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs]\n\
filename=dummy.img\n\
";
	const gchar *manifest_other_variant = "\
[update]\n\
compatible=foo\n\
\n\
[image.rootfs.variant-2]\n\
filename=dummy.img\n\
";
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
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system1");
	r_context();

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	tgrp = determine_target_install_group();
	g_assert_nonnull(tgrp);

	/* Test with manifest containing default and specific variant */
	data = g_bytes_new_static(manifest_variant, strlen(manifest_variant));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_nonnull(rm);

	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_no_error(error);
	g_assert_nonnull(install_plans);

	g_assert_cmpint(install_plans->len, ==, 1);

	plan = g_ptr_array_index(install_plans, 0);
	g_assert_nonnull(plan->image);
	g_assert_cmpstr(plan->image->variant, ==, "variant-1");

	g_clear_pointer(&rm, free_manifest);
	g_clear_pointer(&data, g_bytes_unref);
	g_clear_pointer(&install_plans, g_ptr_array_unref);

	/* Test with manifest containing only default variant */
	data = g_bytes_new_static(manifest_default_variant, strlen(manifest_default_variant));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_nonnull(rm);

	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_no_error(error);
	g_assert_nonnull(install_plans);

	g_assert_cmpint(install_plans->len, ==, 1);

	plan = g_ptr_array_index(install_plans, 0);
	g_assert_nonnull(plan->image);
	g_assert_null(plan->image->variant);

	g_clear_pointer(&rm, free_manifest);
	g_clear_pointer(&data, g_bytes_unref);
	g_clear_pointer(&install_plans, g_ptr_array_unref);

	/* Test with manifest containing only non-matching specific variant (must fail) */
	data = g_bytes_new_static(manifest_other_variant, strlen(manifest_other_variant));
	res = load_manifest_mem(data, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_nonnull(rm);

	install_plans = r_install_make_plans(rm, tgrp, &error);
	g_assert_null(install_plans);
	g_assert_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED);
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

	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_free(msg);
	}
	install_args_free(args);

	if (r_loop)
		g_main_loop_quit(r_loop);

	return G_SOURCE_REMOVE;
}

static gint find_str_custom(gconstpointer a, gconstpointer b)
{
	return g_strcmp0((const char*) a, (const char *) b);
}

static gboolean install_args_find_message(RaucInstallArgs *args, const gchar *needle)
{
	return g_queue_find_custom(&args->status_messages, needle, find_str_custom) != NULL;
}

static void install_test_bundle(InstallFixture *fixture,
		gconstpointer user_data)
{
	InstallData *data = (InstallData*) user_data;
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountprefix = NULL;
	g_autofree gchar *slotfile = NULL;
	g_autofree gchar *testfilepath = NULL;
	g_autofree gchar *mountdir = NULL;
	RaucInstallArgs *args;
	g_autoptr(GError) ierror = NULL;
	gboolean res;

	g_assert_nonnull(data);

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountprefix = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountprefix);
	replace_strdup(&r_context_conf()->mountprefix, mountprefix);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	res = determine_slot_states(&ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	res = do_install_bundle(args, &ierror);
	if (!data->install_err_domain) {
		g_assert_no_error(ierror);
		g_assert_true(res);
		if (data->manifest_test_options.slots) {
			slotfile = g_build_filename(fixture->tmpdir, "images/rootfs-1", NULL);
			mountdir = g_build_filename(fixture->tmpdir, "mnt", NULL);
			g_assert(test_mkdir_relative(fixture->tmpdir, "mnt", 0777) == 0);
			testfilepath = g_build_filename(mountdir, "verify.txt", NULL);
			g_assert(test_mount(slotfile, mountdir));
			g_assert(g_file_test(testfilepath, G_FILE_TEST_IS_REGULAR));
			g_assert(test_umount(fixture->tmpdir, "mnt"));
			g_assert(test_rm_tree(fixture->tmpdir, "mnt"));
		}
	} else {
		/* expected installation error */
		g_assert_error(ierror, data->install_err_domain, data->install_err_code);
		g_assert_false(res);
	}

	if (data->message_needles != NULL) {
		const gchar **message_needles = data->message_needles;
		while (*message_needles != NULL) {
			g_assert_true(install_args_find_message(args, *message_needles));
			message_needles++;
		}
	}

	args->status_result = 0;
	args->cleanup(args);
}

static void install_test_bundle_twice(InstallFixture *fixture,
		gconstpointer user_data)
{
	/* First run */
	install_test_bundle(fixture, user_data);

	/* Second run */
	install_test_bundle(fixture, user_data);
}

static void install_test_bundle_thread(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucInstallArgs *args = NULL;
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountdir = NULL;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	replace_strdup(&r_context_conf()->mountprefix, mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	g_assert_true(determine_slot_states(NULL));

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;

	r_loop = g_main_loop_new(NULL, FALSE);
	install_run(args);
	g_main_loop_run(r_loop);
	g_clear_pointer(&r_loop, g_main_loop_unref);
}

static void install_test_bundle_hook_install_check(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountdir = NULL;
	RaucInstallArgs *args;
	g_autoptr(GError) ierror = NULL;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	replace_strdup(&r_context_conf()->mountprefix, mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	g_assert_true(determine_slot_states(NULL));

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	g_assert_false(do_install_bundle(args, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Bundle rejected: Hook returned: 'No, I won't install this!'");

	args->status_result = 0;
	args->cleanup(args);
}

static void install_test_bundle_hook_install(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountdir = NULL;
	g_autofree gchar *slotfile = NULL;
	g_autofree gchar *stamppath = NULL;
	g_autofree gchar *hookfilepath = NULL;
	RaucInstallArgs *args;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	replace_strdup(&r_context_conf()->mountprefix, mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	res = determine_slot_states(&ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
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

	g_free(slotfile);
	slotfile = g_build_filename(fixture->tmpdir, "images/appfs-1", NULL);
	g_free(stamppath);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert_false(g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));

	args->status_result = 0;
	args->cleanup(args);
}

static void install_test_bundle_hook_post_install(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountdir = NULL;
	g_autofree gchar *slotfile = NULL;
	g_autofree gchar *testfilepath = NULL;
	g_autofree gchar *stamppath = NULL;
	RaucInstallArgs *args;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	replace_strdup(&r_context_conf()->mountprefix, mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	g_assert_true(determine_slot_states(NULL));

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
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

	g_free(slotfile);
	slotfile = g_build_filename(fixture->tmpdir, "images/appfs-1", NULL);
	g_free(stamppath);
	stamppath = g_build_filename(mountdir, "hook-stamp", NULL);
	g_assert(test_mount(slotfile, mountdir));
	g_assert(!g_file_test(stamppath, G_FILE_TEST_IS_REGULAR));
	g_assert(test_umount(fixture->tmpdir, "mount"));

	args->status_result = 0;
	args->cleanup(args);
}

/* Test with already mounted slot */
static void install_test_already_mounted(InstallFixture *fixture,
		gconstpointer user_data)
{
	g_autofree gchar *bundlepath = NULL;
	g_autofree gchar *mountprefix = NULL;
	g_autofree gchar *hookfilepath = NULL;
	RaucInstallArgs *args;
	g_autoptr(GError) ierror = NULL;
	gboolean res;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* Set mount path to current temp dir */
	mountprefix = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountprefix);
	replace_strdup(&r_context_conf()->mountprefix, mountprefix);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	hookfilepath = g_build_filename(fixture->tmpdir, "bootloader", "hook-install-mounted", NULL);
	g_assert_nonnull(hookfilepath);
	g_assert_false(g_file_test(hookfilepath, G_FILE_TEST_EXISTS));

	res = determine_slot_states(&ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	args = install_args_new();
	args->name = g_steal_pointer(&bundlepath);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	res = do_install_bundle(args, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_assert_true(g_file_test(hookfilepath, G_FILE_TEST_IS_REGULAR));

	args->status_result = 0;
	args->cleanup(args);
}

/* This is a tests for issue #1105 where the external mount point detection
 * aborted too early when seeing a mount twice. */
static void install_test_external_mount_points(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *tmpdir = fixture->tmpdir;
	g_autofree gchar *sysconfpath = NULL;
	g_autoptr(GError) error = NULL;
	gchar *slotfile = NULL;
	g_autofree gchar *mountpoint_a = NULL;
	g_autofree gchar *mountpoint_b = NULL;
	g_autofree gchar *mountpoint_c = NULL;
	gboolean res;

	const gchar *system_conf = "\
[system]\n\
compatible=foo\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
bootname=system0\n\
device=images/rootfs-0\n\
\n\
[slot.rootfs.1]\n\
bootname=system1\n\
device=images/rootfs-1\n\
";

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	sysconfpath = write_tmp_file(tmpdir, "test.conf", system_conf, NULL);
	g_assert_nonnull(sysconfpath);

	/* Set up context */
	replace_strdup(&r_context_conf()->configpath, sysconfpath);
	replace_strdup(&r_context_conf()->bootslot, "system0");
	r_context();
	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);

	/* mount rootfs-0 */
	slotfile = g_build_filename(tmpdir, "images/rootfs-0", NULL);
	g_assert(test_mkdir_relative(tmpdir, "slot-0", 0777) == 0);
	mountpoint_a = g_build_filename(tmpdir, "slot-0", NULL);
	g_assert(test_mount(slotfile, mountpoint_a));

	g_free(slotfile);

	/* mount rootfs-0 again */
	slotfile = g_build_filename(tmpdir, "images/rootfs-0", NULL);
	g_assert(test_mkdir_relative(tmpdir, "slot-1", 0777) == 0);
	mountpoint_b = g_build_filename(tmpdir, "slot-1", NULL);
	g_assert(test_mount(slotfile, mountpoint_b));

	g_free(slotfile);

	/* mount rootfs-1 */
	slotfile = g_build_filename(tmpdir, "images/rootfs-1", NULL);
	g_assert(test_mkdir_relative(tmpdir, "slot-2", 0777) == 0);
	mountpoint_c = g_build_filename(tmpdir, "slot-2", NULL);
	g_assert(test_mount(slotfile, mountpoint_c));

	g_free(slotfile);

	res = determine_slot_states(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = update_external_mount_points(&error);
	g_assert_no_error(error);
	g_assert_true(res);

	/* The first mount point for each slot should be detected */
	g_assert_cmpstr(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.0"))->ext_mount_point, ==, mountpoint_a);
	g_assert_cmpstr(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.1"))->ext_mount_point, ==, mountpoint_c);

	test_umount(fixture->tmpdir, "slot-0");
	test_umount(fixture->tmpdir, "slot-1");
	test_umount(fixture->tmpdir, "slot-2");
}

static void install_fixture_set_up_system_user(InstallFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_fixture_set_up_system_user(fixture->tmpdir, NULL, NULL);
}

int main(int argc, char *argv[])
{
	g_autoptr(GPtrArray) ptrs = g_ptr_array_new_with_free_func(g_free);
	InstallData *install_data;
	g_autofree gchar *path = NULL;
	setlocale(LC_ALL, "C");

	path = g_strdup_printf("%s:%s", g_getenv("PATH"), "test/bin");
	g_setenv("PATH", path, TRUE);

	g_test_init(&argc, &argv, NULL);

	r_context_conf()->handlerextra = g_strdup("--dummy1 --dummy2");
	r_context();

	g_test_add_func("/install/target-group/non-redundant", test_install_determine_target_group_non_redundant);

	g_test_add_func("/install/target-group/async", test_install_target_group_async);

	g_test_add_func("/install/target-group/sync", test_install_target_group_sync);

	g_test_add_func("/install/target-group/loose", test_install_target_group_loose);

	g_test_add_func("/install/target-group/n-redundant", test_install_target_group_n_redundant);

	g_test_add_func("/install/image-selection/redundant", test_install_image_selection);

	g_test_add_func("/install/image-selection/non-matching", test_install_image_selection_no_matching_slot);

	g_test_add_func("/install/image-selection/boot-external", test_install_image_selection_boot_external);

	g_test_add_func("/install/image-selection/readonly", test_install_image_readonly);

	g_test_add_func("/install/image-mapping/variants", test_install_image_variants);

	g_test_add("/install/external_mounts", InstallFixture, NULL,
			install_fixture_set_up_system_user, install_test_external_mount_points,
			install_fixture_tear_down);

	for (RManifestBundleFormat format = R_MANIFEST_FORMAT_PLAIN; format <= R_MANIFEST_FORMAT_VERITY; format++) {
		const gchar *format_name = r_manifest_bundle_format_to_str(format);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.manifest_test_options = {
				.format = format,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bootname/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_system_user, install_test_bootname,
				install_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/install/target/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_system_conf, install_test_target,
				install_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/install/bundle/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle, install_test_bundle,
				install_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/install/bundle/central-status/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_central_status, install_test_bundle,
				install_fixture_tear_down);

		g_test_add(dup_test_printf(ptrs, "/install/bundle-thread/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle, install_test_bundle_thread,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = dup_test_data(ptrs, (&(const gchar *[]) {
				"Checking and mounting bundle...",
				"Debug: arg1 arg2 --dummy1 --dummy2",
				"Handler status: [STARTED]",
				"Bootloader status: [DONE]",
				"Handler status: [DONE]",
				NULL,
			})),
			.manifest_test_options = {
				.custom_handler = TRUE,
				.preinstall_handler = FALSE,
				.postinstall_handler = FALSE,
				.hooks = FALSE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bundle-custom-handler/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_custom_handler, install_test_bundle,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = NULL,
			.manifest_test_options = {
				.custom_handler = FALSE,
				.preinstall_handler = TRUE,
				.postinstall_handler = TRUE,
				.hooks = FALSE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bundle-pre-post-install-handler/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_pre_post_install_handler, install_test_bundle,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = NULL,
			.manifest_test_options = {
				.custom_handler = FALSE,
				.preinstall_handler = FALSE,
				.postinstall_handler = FALSE,
				.hooks = TRUE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bundle-hook/install-check/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_install_check_hook, install_test_bundle_hook_install_check,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = NULL,
			.manifest_test_options = {
				.custom_handler = FALSE,
				.preinstall_handler = FALSE,
				.postinstall_handler = FALSE,
				.hooks = TRUE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bundle-hook/slot-install/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_install_hook, install_test_bundle_hook_install,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = NULL,
			.manifest_test_options = {
				.custom_handler = FALSE,
				.preinstall_handler = FALSE,
				.postinstall_handler = FALSE,
				.hooks = TRUE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/bundle-hook/slot-post-install/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_post_hook, install_test_bundle_hook_post_install,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.message_needles = NULL,
			.manifest_test_options = {
				.custom_handler = TRUE,
				.preinstall_handler = TRUE,
				.postinstall_handler = TRUE,
				.hooks = TRUE,
				.slots = TRUE,
			},
		}));
		g_test_add(dup_test_printf(ptrs, "/install/already-mounted/%s", format_name),
				InstallFixture, install_data,
				install_fixture_set_up_bundle_already_mounted, install_test_already_mounted,
				install_fixture_tear_down);
	}

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.slots = TRUE,
		},
	}));
	g_test_add("/install/adaptive",
			InstallFixture, install_data,
			install_fixture_set_up_bundle_adaptive, install_test_bundle,
			install_fixture_tear_down);

	g_test_add("/install/slot-skipping",
			InstallFixture, install_data,
			install_fixture_set_up_slot_skipping, install_test_bundle_twice,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.install_err_domain = R_INSTALL_ERROR,
		.install_err_code = R_INSTALL_ERROR_VERSION_MISMATCH,
		.system_test_options = {
			.min_bundle_version = "1.0",
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.slots = TRUE,
			.bundle_version = "0.0.1",
		},
	}));
	g_test_add("/install/min-bundle-version/version-bad",
			InstallFixture, install_data,
			install_fixture_set_up_bundle,
			install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.min_bundle_version = "1.0",
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.slots = TRUE,
			.bundle_version = "1.0.1",
		},
	}));
	g_test_add("/install/min-bundle-version/version-good-1",
			InstallFixture, install_data,
			install_fixture_set_up_bundle,
			install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.min_bundle_version = "1.0",
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.slots = TRUE,
			.bundle_version = "2025.1-foo+bar",
		},
	}));
	g_test_add("/install/min-bundle-version/version-good-2",
			InstallFixture, install_data,
			install_fixture_set_up_bundle,
			install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.install_err_domain = R_INSTALL_ERROR,
		.install_err_code = R_INSTALL_ERROR_VERSION_MISMATCH,
		.system_test_options = {
			.min_bundle_version = "1.0",
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.slots = TRUE,
			.no_bundle_version = TRUE,
		},
	}));
	g_test_add("/install/min-bundle-version/version-missing",
			InstallFixture, install_data,
			install_fixture_set_up_bundle,
			install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.artifact_repos = TRUE,
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "artifact-1.file",
			.artifact_slotclass = "files",
		},
	}));
	g_test_add("/install/artifacts/file",
			InstallFixture, install_data,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.artifact_repos = TRUE,
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-common.tar",
			.artifact_slotclass = "trees",
		},
	}));
	g_test_add("/install/artifacts/common-tar/direct",
			InstallFixture, install_data,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.artifact_repos = TRUE,
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-common.tar",
			.artifact_slotclass = "trees",
			.artifact_convert = "tar-extract",
		},
	}));
	g_test_add("/install/artifacts/common-tar/extracted",
			InstallFixture, install_data,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.artifact_repos = TRUE,
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-special.tar",
			.artifact_slotclass = "trees",
		},
	}));
	g_test_add("/install/artifacts/special-tar/direct",
			InstallFixture, install_data,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	install_data = dup_test_data(ptrs, (&(InstallData) {
		.system_test_options = {
			.artifact_repos = TRUE,
		},
		.manifest_test_options = {
			.format = R_MANIFEST_FORMAT_VERITY,
			.artifact_file = "payload-special.tar",
			.artifact_slotclass = "trees",
			.artifact_convert = "tar-extract",
		},
	}));
	g_test_add("/install/artifacts/special-tar/extracted",
			InstallFixture, install_data,
			install_fixture_set_up_bundle, install_test_bundle,
			install_fixture_tear_down);

	if (ENABLE_COMPOSEFS) {
		install_data = dup_test_data(ptrs, (&(InstallData) {
			.system_test_options = {
				.artifact_repos = TRUE,
			},
			.manifest_test_options = {
				.format = R_MANIFEST_FORMAT_VERITY,
				.artifact_file = "payload-medium-data-size-a.tar.gz",
				.artifact_slotclass = "composefs",
				.artifact_convert = "composefs",
			},
		}));
		g_test_add("/install/artifacts/composefs",
				InstallFixture, install_data,
				install_fixture_set_up_bundle, install_test_bundle,
				install_fixture_tear_down);

		install_data = dup_test_data(ptrs, (&(InstallData) {
			.install_err_domain = R_ARTIFACTS_ERROR,
			.install_err_code = R_ARTIFACTS_ERROR_INSTALL,
			.system_test_options = {
				.artifact_repos = TRUE,
			},
			.manifest_test_options = {
				.format = R_MANIFEST_FORMAT_VERITY,
				.artifact_file = "payload-medium-data-size-a.tar.gz",
				.artifact_slotclass = "trees",
				.artifact_convert = "composefs",
			},
		}));
		g_test_add("/install/artifacts/composefs-type-mismatch",
				InstallFixture, install_data,
				install_fixture_set_up_bundle, install_test_bundle,
				install_fixture_tear_down);
	}

	return g_test_run();
}
