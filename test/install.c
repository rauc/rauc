#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>
#include <manifest.h>
#include "bundle.h"
#include <install.h>

typedef struct {
} InstallFixture;

static void install_fixture_set_up(InstallFixture *fixture,
		gconstpointer user_data)
{
	if (g_file_test ("test/createdbundle.raucb", G_FILE_TEST_EXISTS)) {
		g_remove("test/createdbundle.raucb");
	}
	if (!g_file_test ("test/createdbundle.raucb", G_FILE_TEST_IS_DIR)) {
		g_mkdir("test/install-mount", 0777);
	}
}

static void install_fixture_tear_down(InstallFixture *fixture,
		gconstpointer user_data)
{
}

static const gchar* dummy_bootname_provider(void) {
	return "system0";
}

static void install_test1(InstallFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm;
	GHashTable *tgrp;

	g_assert_true(load_manifest("test/manifest.raucm", &rm));

	g_assert_true(determine_slot_states(dummy_bootname_provider));

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
	g_assert_true(create_bundle("test/createdbundle.raucb", "test/install-content"));
	g_assert_true(do_install("test/createdbundle.raucb"));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context_conf()->mountprefix = g_strdup("test/install-mount/");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/install/test1", InstallFixture, NULL,
		   install_fixture_set_up, install_test1,
		   install_fixture_tear_down);

	g_test_add("/install/test2", InstallFixture, NULL,
		   install_fixture_set_up, install_test2,
		   install_fixture_tear_down);

	return g_test_run ();
}
