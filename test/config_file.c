#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <config_file.h>
#include <context.h>

#include "utils.h"

static void config_file_test1(void)
{
	GList *slotlist, *l;
	RaucConfig *config;
	RaucSlot *slot;

	g_assert_true(load_config("test/system.conf", &config, NULL));
	g_assert_nonnull(config);
	g_assert_cmpstr(config->system_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(config->system_bootloader, ==, "barebox");
	g_assert_cmpstr(config->mount_prefix, ==, "/mnt/myrauc/");

	g_assert_nonnull(config->slots);
	slotlist = g_hash_table_get_keys(config->slots);
	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_cmpstr(slot->name, ==, "rootfs.0");
	g_assert_cmpstr(slot->device, ==, "/dev/sda0");
	g_assert_cmpstr(slot->bootname, ==, "system0");
	g_assert_false(slot->readonly);
	g_assert_null(slot->parent);

	g_assert_cmpuint(g_list_length(slotlist), ==, 5);

	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(config->slots, l->data);
		g_assert_nonnull(s->name);
		g_assert_nonnull(s->device);
		g_assert_nonnull(s->type);
		g_assert_nonnull(s->bootname);

		g_print("slot: %s\n", s->name);
		g_print("\tdevice:   %s\n", s->device);
		g_print("\ttype:     %s\n", s->type);
		g_print("\tbootname: %s\n", s->bootname);
		g_print("\treadonly: %d\n", s->readonly);
		if (s->parent)
			g_print("\tparent: %s\n", ((RaucSlot*)s->parent)->name);
	}
	g_list_free(slotlist);

	g_assert(find_config_slot_by_device(config, "/dev/sda0") == slot);
	g_assert(find_config_slot_by_device(config, "/dev/xxx0") == NULL);

	free_config(config);
}


static void config_file_test3(void)
{
	RaucSlotStatus *ss;
	g_assert_true(load_slot_status("test/rootfs.raucs", &ss, NULL));
	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27");

	free_slot_status(ss);
}


static void config_file_test5(void)
{
	RaucSlotStatus *ss = g_new0(RaucSlotStatus, 1);

	ss->status = g_strdup("ok");
	ss->checksum.type = G_CHECKSUM_SHA256;
	ss->checksum.digest = g_strdup("dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	save_slot_status("test/savedslot.raucs", ss, NULL);

	free_slot_status(ss);

	load_slot_status("test/savedslot.raucs", &ss, NULL);

	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	free_slot_status(ss);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->handlerextra = g_strdup("--dummy1 --dummy2");
	r_context();

	g_test_add_func("/config-file/test1", config_file_test1);
	g_test_add_func("/config-file/test3", config_file_test3);
	g_test_add_func("/config-file/test5", config_file_test5);

	return g_test_run ();
}
