#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <install.h>
#include <manifest.h>
#include <mount.h>

#include "common.h"

typedef struct {
	gchar *tmpdir;
} InstallFixture;

static void install_fixture_set_up(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *contentdir;
	gchar *bundlepath;
	gchar *configpath;
	gchar *certpath;
	gchar *keypath;
	gchar *capath;

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("bundle tmpdir: %s\n", fixture->tmpdir);

	g_assert(test_mkdir_relative(fixture->tmpdir, "content", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "mount", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "images", 0777) == 0);
	g_assert(test_mkdir_relative(fixture->tmpdir, "openssl-ca", 0777) == 0);

	/* copy system config to temp dir*/
	configpath = g_build_filename(fixture->tmpdir, "system.conf", NULL);
	g_assert_nonnull(configpath);
	g_assert_true(test_copy_file("test/test.conf", configpath));
	r_context_conf()->configpath = g_strdup(configpath);

	/* copy cert */
	certpath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.cert.pem", NULL);
	g_assert_nonnull(certpath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/release-1.cert.pem", certpath));
	r_context_conf()->certpath = g_strdup(certpath);

	/* copy key */
	keypath = g_build_filename(fixture->tmpdir, "openssl-ca/release-1.pem", NULL);
	g_assert_nonnull(keypath);
	g_assert_true(test_copy_file("test/openssl-ca/rel/private/release-1.pem", keypath));
	r_context_conf()->keypath = g_strdup(keypath);

	/* copy ca */
	capath = g_build_filename(fixture->tmpdir, "openssl-ca/dev-ca.pem", NULL);
	g_assert_nonnull(capath);
	g_assert_true(test_copy_file("test/openssl-ca/dev-ca.pem", capath));

	/* Setup pseudo devices */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/rootfs-1", 0) == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "images/appfs-1", 0) == 0);

	/* Setup bundle content */
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/rootfs.img", 10*1024*1024) == 0);
	g_assert(test_prepare_dummy_file(fixture->tmpdir, "content/appfs.img", 10*1024*1024) == 0);
	g_assert_true(test_make_filesystem(fixture->tmpdir, "content/rootfs.img"));
	g_assert_true(test_make_filesystem(fixture->tmpdir, "content/appfs.img"));
	g_assert(test_prepare_manifest_file(fixture->tmpdir, "content/manifest.raucm") == 0);

	/* make images user-writable */
	test_make_slot_user_writable(fixture->tmpdir, "content/rootfs.img");
	test_make_slot_user_writable(fixture->tmpdir, "content/appfs.img");

	contentdir = g_build_filename(fixture->tmpdir, "content", NULL);
	g_assert_nonnull(contentdir);

	g_assert_true(update_manifest(contentdir, FALSE));

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	/* Create bundle */
	g_assert_true(create_bundle(bundlepath, contentdir));

	/* Set dummy bootname provider */
	set_bootname_provider(test_bootname_provider);

	g_free(contentdir);
	g_free(bundlepath);
	g_free(configpath);
	g_free(certpath);
	g_free(keypath);
	g_free(capath);
}

static void install_fixture_tear_down(InstallFixture *fixture,
		gconstpointer user_data)
{
	//test_umount(fixture->tmpdir, "mount/bundle");
}

static void install_test1(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm;
	GHashTable *tgrp;

	g_assert_true(load_manifest_file("test/manifest.raucm", &rm));

	set_bootname_provider(test_bootname_provider);
	g_assert_true(determine_slot_states());

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rescue.0"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "rootfs.1"))->state, ==, ST_INACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.0"))->state, ==, ST_ACTIVE);
	g_assert_cmpint(((RaucSlot*) g_hash_table_lookup(r_context()->config->slots, "appfs.1"))->state, ==, ST_INACTIVE);


	tgrp = determine_target_install_group(rm);

	g_assert_true(g_hash_table_contains(tgrp, "rootfs"));
	g_assert_true(g_hash_table_contains(tgrp, "appfs"));
	g_assert_cmpstr(g_hash_table_lookup(tgrp, "rootfs"), ==, "rootfs.1");
	g_assert_cmpstr(g_hash_table_lookup(tgrp, "appfs"), ==, "appfs.1");
	g_assert_cmpint(g_hash_table_size(tgrp), ==, 2);
}

static void install_test2(InstallFixture *fixture,
		gconstpointer user_data)
{
	gchar *bundlepath;
	gchar* mountdir;

	/* Set mount path to current temp dir */
	mountdir = g_build_filename(fixture->tmpdir, "mount", NULL);
	g_assert_nonnull(mountdir);
	r_context_conf()->mountprefix = g_strdup(mountdir);
	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	g_assert_true(do_install_bundle(bundlepath));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/install/test1", InstallFixture, NULL,
		   install_fixture_set_up, install_test1,
		   install_fixture_tear_down);

	g_test_add("/install/test2", InstallFixture, NULL,
		   install_fixture_set_up, install_test2,
		   install_fixture_tear_down);

	return g_test_run();
}
