#include <glib.h>

#include "config_file.h"

#include <utils.h>

#define RAUC_SLOT_PREFIX	"slot"

static void free_slot(gpointer value) {
	RaucSlot *slot = (RaucSlot*)value;

	g_free(slot->device);
	g_free(slot->type);
	g_free(slot->name);
	if (slot->bootname != slot->name)
		g_free(slot->bootname);
}

gboolean load_config(const gchar *filename, RaucConfig **config) {
	RaucConfig *c = g_new0(RaucConfig, 1);
	gboolean res = FALSE;
	GKeyFile *key_file = NULL;
	gchar **groups;
	gsize group_count;
	GList *slotlist = NULL;
	GHashTable *slots = NULL;
	GList *l;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto free;

	/* parse [system] section */
	c->system_compatible = g_key_file_get_string(key_file, "system", "compatible", NULL);
	if (!c->system_compatible) {
		goto free;
	}
	c->system_bootloader = g_key_file_get_string(key_file, "system", "bootloader", NULL);

	c->mount_prefix = g_key_file_get_string(key_file, "system", "mountprefix", NULL);
	if (!c->mount_prefix) {
		g_print("No mount prefix provided, using /mnt/rauc/ as default\n");
		c->mount_prefix = g_strdup("/mnt/rauc/");
	}

	/* parse [keyring] section */
	c->keyring_path = resolve_path(filename,
		g_key_file_get_string(key_file, "keyring", "path", NULL));

	/* parse [slot.*.#] sections */
	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_slot);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		RaucSlot *slot = g_new0(RaucSlot, 1);
		gchar **groupsplit;

		groupsplit = g_strsplit(groups[i], ".", 2);

		/* We treat sections starting with "slot." as slots */
		if (g_str_equal(groupsplit[0], RAUC_SLOT_PREFIX)) {
			gchar* value;

			value = groupsplit[1];
			if (!value) {
				g_printerr("Invalid slot name\n");
				goto free;
			}
			slot->name = g_strdup(value);

			value = resolve_path(filename,
				g_key_file_get_string(key_file, groups[i], "device", NULL));
			if (!value) {
				g_printerr("Failed to parse device name\n");
				goto free;
			}
			slot->device = value;

			value = g_key_file_get_string(key_file, groups[i], "type", NULL);
			if (!value)
				value = (gchar*) "raw";
			slot->type = value;

			value = g_key_file_get_string(key_file, groups[i], "bootname", NULL);
			if (!value)
				value = slot->name;
			slot->bootname = value;

			slot->readonly = g_key_file_get_boolean(key_file, groups[i], "readonly", NULL);

			g_hash_table_insert(slots, slot->name, slot);

		}
		g_strfreev(groupsplit);
	}

	/* Add parent pointers */
	slotlist = g_hash_table_get_keys(slots);
	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s;
		gchar* group_name;
		gchar* value;

		group_name = g_strconcat(RAUC_SLOT_PREFIX ".", l->data, NULL);
		value = g_key_file_get_string(key_file, group_name, "parent", NULL);
		g_free(group_name);
		if (!value)
			continue;

		s = g_hash_table_lookup(slots, value);
		if (!s) {
			g_print("Parent %s not found!\n", value);
			continue;
		}

		((RaucSlot*)g_hash_table_lookup(slots, l->data))->parent = s;

	}
	g_list_free(slotlist);

	c->slots = slots;

	g_strfreev(groups);

	res = TRUE;
free:
	if (!res) {
		free_config(c);
		c = NULL;
	}
	g_key_file_free(key_file);
	*config = c;
	return res;
}

void free_config(RaucConfig *config) {

	g_free(config->system_compatible);
	g_free(config->system_bootloader);
	g_free(config->keyring_path);

	if (config->slots)
		g_hash_table_destroy(config->slots);

}

gboolean load_slot_status(const gchar *filename, RaucSlotStatus **slotstatus) {
	RaucSlotStatus *ss = g_new(RaucSlotStatus, 1);
	gboolean res = TRUE;
	GKeyFile *key_file = NULL;
	gchar *digest;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto free;

	ss->status = g_key_file_get_string(key_file, "slot", "status", NULL);
	digest = g_key_file_get_string(key_file, "slot", "sha256", NULL);
	if (digest) {
		ss->checksum.type = G_CHECKSUM_SHA256;
		ss->checksum.digest = digest;
	}

	res = TRUE;
free:
	g_key_file_free(key_file);
	*slotstatus = ss;
	return res;
}

gboolean save_slot_status(const gchar *filename, RaucSlotStatus *ss) {
	GKeyFile *key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	if (ss->status)
		g_key_file_set_string(key_file, "slot", "status", ss->status);

	if (ss->checksum.type == G_CHECKSUM_SHA256)
		g_key_file_set_string(key_file, "slot", "sha256", ss->checksum.digest);


	res = g_key_file_save_to_file(key_file, filename, NULL);
	if (!res)
		goto free;

free:
	g_key_file_free(key_file);

	return res;
}

void free_slot_status(RaucSlotStatus *slotstatus) {

	g_free(slotstatus->status);
	g_free(slotstatus->checksum.digest);
	g_free(slotstatus);
}
