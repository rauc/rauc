#include <glib.h>

#include "config_file.h"

gboolean load_config(const gchar *filename, RaucConfig **config) {
	RaucConfig *c = g_new(RaucConfig, 1);
	gboolean res = TRUE;
	GKeyFile *key_file = NULL;
	gchar **groups;
	gsize group_count;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto free;

	c->system_compatible = g_key_file_get_string(key_file, "system", "compatible", NULL);
	c->system_bootloader = g_key_file_get_string(key_file, "system", "bootloader", NULL);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		g_print("%s\n", groups[i]);
	}
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
