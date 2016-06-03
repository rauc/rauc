#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <config_file.h>
#include <context.h>

#include "common.h"
#include "utils.h"

typedef struct {
	gchar *tmpdir;
} ConfigFileFixture;

static void config_file_fixture_set_up(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-conf_file-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
}

static void config_file_fixture_tear_down(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

/* Test: Parse entire config file and check if derived slot / file structures
 * are initialized correctly */
static void config_file_full_config(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	GList *slotlist;
	RaucConfig *config;
	RaucSlot *slot;


	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
description=Root filesystem partition 0\n\
device=/dev/sda0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
description=Root filesystem partition 1\n\
device=/dev/sda1\n\
type=ext4\n\
bootname=system1\n\
\n\
[slot.appfs.0]\n\
description=Application filesystem partition 0\n\
device=/dev/sda2\n\
type=ext4\n\
parent=rootfs.0\n\
\n\
[slot.appfs.1]\n\
description=Application filesystem partition 1\n\
device=/dev/sda3\n\
type=ext4\n\
parent=rootfs.1\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "full_config.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_true(load_config(pathname, &config, NULL));
	g_assert_nonnull(config);
	g_assert_cmpstr(config->system_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(config->system_bootloader, ==, "barebox");
	g_assert_cmpstr(config->mount_prefix, ==, "/mnt/myrauc/");

	g_assert_nonnull(config->slots);
	slotlist = g_hash_table_get_keys(config->slots);

	slot = g_hash_table_lookup(config->slots, "rescue.0");
	g_assert_cmpstr(slot->name, ==, "rescue.0");
	g_assert_cmpstr(slot->description, ==, "Rescue partition");
	g_assert_cmpstr(slot->device, ==, "/dev/mtd4");
	g_assert_cmpstr(slot->bootname, ==, "factory0");
	g_assert_cmpstr(slot->type, ==, "raw");
	g_assert_true(slot->readonly);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_device(config, "/dev/mtd4") == slot);

	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_cmpstr(slot->name, ==, "rootfs.0");
	g_assert_cmpstr(slot->description, ==, "Root filesystem partition 0");
	g_assert_cmpstr(slot->device, ==, "/dev/sda0");
	g_assert_cmpstr(slot->bootname, ==, "system0");
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_false(slot->readonly);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_device(config, "/dev/sda0") == slot);

	slot = g_hash_table_lookup(config->slots, "rootfs.1");
	g_assert_cmpstr(slot->name, ==, "rootfs.1");
	g_assert_cmpstr(slot->description, ==, "Root filesystem partition 1");
	g_assert_cmpstr(slot->device, ==, "/dev/sda1");
	g_assert_cmpstr(slot->bootname, ==, "system1");
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_false(slot->readonly);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_device(config, "/dev/sda1") == slot);

	slot = g_hash_table_lookup(config->slots, "appfs.0");
	g_assert_cmpstr(slot->name, ==, "appfs.0");
	g_assert_cmpstr(slot->description, ==, "Application filesystem partition 0");
	g_assert_cmpstr(slot->device, ==, "/dev/sda2");
	g_assert_null(slot->bootname);
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_false(slot->readonly);
	g_assert_nonnull(slot->parent);
	g_assert(find_config_slot_by_device(config, "/dev/sda2") == slot);

	slot = g_hash_table_lookup(config->slots, "appfs.1");
	g_assert_cmpstr(slot->name, ==, "appfs.1");
	g_assert_cmpstr(slot->description, ==, "Application filesystem partition 1");
	g_assert_cmpstr(slot->device, ==, "/dev/sda3");
	g_assert_null(slot->bootname);
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_false(slot->readonly);
	g_assert_nonnull(slot->parent);
	g_assert(find_config_slot_by_device(config, "/dev/sda3") == slot);

	g_assert_cmpuint(g_list_length(slotlist), ==, 5);

	g_list_free(slotlist);

	g_assert(find_config_slot_by_device(config, "/dev/xxx0") == NULL);

	free_config(config);
}

static void config_file_bootloaders(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucConfig *config;
	GError *ierror = NULL;
	gchar* pathname;

	const gchar *boot_inval_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=superloader2000\n\
mountprefix=/mnt/myrauc/\n";
	const gchar *boot_missing_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
mountprefix=/mnt/myrauc/\n";


	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", boot_inval_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Unsupported bootloader 'superloader2000' selected in system config");
	g_clear_error(&ierror);


	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", boot_missing_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "No bootloader selected in system config");
	g_clear_error(&ierror);
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

static void config_file_test6(void)
{
	g_assert_nonnull(r_context()->system_serial);
	g_assert_cmpstr(r_context()->system_serial, ==, "1234");
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->handlerextra = g_strdup("--dummy1 --dummy2");
	r_context();

	g_test_add("/config-file/full-config", ConfigFileFixture, NULL,
		   config_file_fixture_set_up, config_file_full_config,
		   config_file_fixture_tear_down);
	g_test_add("/config-file/bootloaders", ConfigFileFixture, NULL,
		   config_file_fixture_set_up, config_file_bootloaders,
		   config_file_fixture_tear_down);
	g_test_add_func("/config-file/test3", config_file_test3);
	g_test_add_func("/config-file/test5", config_file_test5);
	g_test_add_func("/config-file/test6", config_file_test6);

	return g_test_run ();
}
