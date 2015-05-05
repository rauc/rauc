#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include "config_file.h"
#include "manifest.h"

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
	g_assert_cmpstr(fixture->config->mount_prefix, ==, "/mnt/myrauc/");

	g_assert_nonnull(fixture->config->slots);
	slotlist = g_hash_table_get_keys(fixture->config->slots);
	slot = g_hash_table_lookup(fixture->config->slots, "rootfs.0");
	g_assert_cmpstr(slot->name, ==, "rootfs.0");
	g_assert_cmpstr(slot->device, ==, "/dev/sda0");
	g_assert_cmpstr(slot->bootname, ==, "system0");
	g_assert_false(slot->readonly);
	g_assert_null(slot->parent);

	g_assert_cmpuint(g_list_length(slotlist), ==, 5);

	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(fixture->config->slots, l->data);
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


	free_config(fixture->config);

}

static void config_file_test2(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm;
	GList *l;

	g_assert_true(load_manifest("test/manifest.raucm", &rm));
	g_assert_nonnull(rm);
	g_assert_cmpstr(rm->update_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(rm->update_version, ==, "2015.04-1");
	g_assert_cmpstr(rm->keyring, ==, "release.tar");
	g_assert_cmpstr(rm->handler_name, ==, "custom_handler.sh");
	g_assert_nonnull(rm->images);

	g_assert_cmpuint(g_list_length(rm->images), ==, 2);


	g_print("Update Manifest\n");
	g_print("\tCompatible: %s\n", rm->update_compatible);
	g_print("\tVersion:    %s\n", rm->update_version);
	if (rm->keyring)
		g_print("\tKeyring:    %s\n", rm->keyring);
	if (rm->handler_name)
		g_print("\tHandler:    %s\n\n", rm->handler_name);

	for (l = rm->images; l != NULL; l = l->next) {
		RaucImage *img = (RaucImage*) l->data;
		g_assert_nonnull(img);
		g_assert_nonnull(img->slotclass);
		g_assert_nonnull(img->checksum.digest);
		g_assert_nonnull(img->filename);


		g_print("\tSlotClass:  %s\n", img->slotclass);
		g_print("\tDigest:     %s\n", img->checksum.digest);
		if (img->filename)
			g_print("\tFilename:   %s\n\n", img->filename);

	}

	free_manifest(rm);

}

static void config_file_test3(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucSlotStatus *ss;
	g_assert_true(load_slot_status("test/rootfs.raucs", &ss));
	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27");

	free_slot_status(ss);
}

static void config_file_test4(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucManifest *rm = g_new0(RaucManifest, 1);
	RaucImage *img;

	rm->update_compatible = g_strdup("BarCorp FooBazzer");
	rm->update_version = g_strdup("2011.03-1");
	rm->keyring = g_strdup("mykeyring.tar");
	rm->handler_name = g_strdup("myhandler.sh");

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("rootfs");
	img->checksum.type = G_CHECKSUM_SHA256;
	img->checksum.digest = g_strdup("c8af04e62bad4ab75dafd22119026e5e3943f385bdcbe7731a4938102453754c");
	img->filename = g_strdup("myrootimg.ext4");
	rm->images = g_list_append(rm->images, img);

	img = g_new0(RaucImage, 1);

	img->slotclass = g_strdup("appfs");
	img->checksum.type = G_CHECKSUM_SHA256;
	img->checksum.digest = g_strdup("4e7e45db749b073eda450d30c978c7e2f6035b057d3e33ac4c61d69ce5155313");
	img->filename = g_strdup("myappimg.ext4");
	rm->images = g_list_append(rm->images, img);

	g_assert_true(save_manifest("test/savedmanifest.raucm", rm));

	free_manifest(rm);

	g_assert_true(load_manifest("test/savedmanifest.raucm", &rm));

	g_assert_nonnull(rm);
	g_assert_cmpstr(rm->update_compatible, ==, "BarCorp FooBazzer");
	g_assert_cmpstr(rm->update_version , ==, "2011.03-1");
	g_assert_cmpstr(rm->keyring, ==, "mykeyring.tar");
	g_assert_cmpstr(rm->handler_name, ==, "myhandler.sh");

	g_assert_cmpuint(g_list_length(rm->images), ==, 2);

	for (GList *l = rm->images; l != NULL; l = l->next) {
		RaucImage *image = (RaucImage*) l->data;
		g_assert_nonnull(image);
		g_assert_nonnull(image->slotclass);
		g_assert_nonnull(image->checksum.digest);
		g_assert_nonnull(image->filename);
	}

	free_manifest(rm);
}


static void config_file_test5(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	RaucSlotStatus *ss = g_new0(RaucSlotStatus, 1);

	ss->status = g_strdup("ok");
	ss->checksum.type = G_CHECKSUM_SHA256;
	ss->checksum.digest = g_strdup("dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	save_slot_status("test/savedslot.raucs", ss);

	free_slot_status(ss);

	load_slot_status("test/savedslot.raucs", &ss);

	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	free_slot_status(ss);
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

	g_test_add("/config-file/test3", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_test3,
			config_file_fixture_tear_down);

	g_test_add("/config-file/test4", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_test4,
			config_file_fixture_tear_down);

	g_test_add("/config-file/test5", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_test5,
			config_file_fixture_tear_down);

	return g_test_run ();
}
