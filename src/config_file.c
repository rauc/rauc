#include <glib.h>

#include "config_file.h"

#define RAUC_SLOT_PREFIX	"slot"

gboolean load_config(const gchar *filename, RaucConfig **config) {
	RaucConfig *c = g_new(RaucConfig, 1);
	gboolean res = FALSE;
	GKeyFile *key_file = NULL;
	gchar **groups;
	gsize group_count;
	GList *slotlist = NULL;
	GHashTable *slots;
	GList *l;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto free;

	/* parse [system] section */
	c->system_compatible = g_key_file_get_string(key_file, "system", "compatible", NULL);
	if (!c->system_compatible) {
		res = FALSE;
		goto free;
	}
	c->system_bootloader = g_key_file_get_string(key_file, "system", "bootloader", NULL);

	/* parse [keyring] section */
	c->keyring_path = g_key_file_get_string(key_file, "keyring", "path", NULL);

	/* parse [slot.*.#] sections */
	slots = g_hash_table_new(g_str_hash, g_str_equal);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		RaucSlot *slot = g_new(RaucSlot, 1);
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

			value = g_key_file_get_string(key_file, groups[i], "device", NULL);
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

			slot->parent = NULL;
			g_hash_table_insert(slots, slot->name, slot);

		}
		g_strfreev(groupsplit);
	}

	slotlist = g_hash_table_get_keys(slots);

	/* Add parent pointers */
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

	c->slots = slots;

	g_list_free(slotlist);

	g_strfreev(groups);


	res = TRUE;
free:
	g_key_file_free(key_file);
	*config = c;
	return res;
}

gboolean load_manifest(const gchar *filename, RaucManifest **manifest) {
	return FALSE;
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
