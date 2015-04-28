#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include "config_file.h"

typedef struct {
	RaucConfig *config;
} ConfigFileFixture;

static void config_file_fixture_set_up(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
}

static void config_file_fixture_tear_down(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_free(fixture->config);
}

static void config_file_test1(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	GList *slotlist, *l;
	RaucSlot *slot;

	load_config("test/system.conf", &fixture->config);
	g_assert_nonnull(fixture->config);
	g_assert_cmpstr(fixture->config->system_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(fixture->config->system_bootloader, ==, "barebox");

	g_assert_nonnull(fixture->config->slots);
	slotlist = g_hash_table_get_keys(fixture->config->slots);
	slot = g_hash_table_lookup(fixture->config->slots, "rootfs.0");
	g_assert_cmpstr(slot->name, ==, "rootfs.0");
	g_assert_cmpstr(slot->device, ==, "/dev/sda0");
	g_assert_cmpstr(slot->bootname, ==, "system0");
	g_assert_false(slot->readonly);
	g_assert_null(slot->parent);

	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(fixture->config->slots, l->data);
		g_assert_nonnull(s->name);
		g_assert_nonnull(s->device);
		g_assert_nonnull(s->type);
		g_assert_nonnull(s->bootname);
	}
	g_list_free(slotlist);


	free_config(fixture->config);

}

static void config_file_test2(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucSlotStatus *ss;
	g_assert_true(load_slot_status("test/rootfs.raucs", &ss));
	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27");
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/config-file/test1", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_test1,
			config_file_fixture_tear_down);

	g_test_add("/config-file/test2", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_test2,
			config_file_fixture_tear_down);

	return g_test_run ();
}
