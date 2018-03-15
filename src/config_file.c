#include <glib.h>
#include <string.h>

#include "config_file.h"
#include "context.h"
#include "manifest.h"
#include "mount.h"
#include "utils.h"

G_DEFINE_QUARK(r-config-error-quark, r_config_error)
G_DEFINE_QUARK(r-slot-error-quark, r_slot_error)

#define RAUC_SLOT_PREFIX	"slot"

void r_free_slot(gpointer value) {
	RaucSlot *slot = (RaucSlot*)value;

	g_return_if_fail(slot);

	g_free(slot->description);
	g_free(slot->device);
	g_free(slot->type);
	g_free(slot->bootname);
	g_free(slot->mount_point);
	g_clear_pointer(&slot->status, free_slot_status);
	g_free(slot);
}

gboolean default_config(RaucConfig **config) {
	RaucConfig *c = g_new0(RaucConfig, 1);

	c->mount_prefix = g_strdup("/mnt/rauc/");

	*config = c;
	return TRUE;
}

typedef struct {
	const gchar *name;
	gboolean mountable;
} RaucSlotType;

RaucSlotType supported_slot_types[] = {
	{"raw", FALSE},
	{"ext4", TRUE},
	{"ubifs", TRUE},
	{"ubivol", FALSE},
	{"nand", FALSE},
	{"vfat", TRUE},
	{}
};

gboolean is_slot_mountable(RaucSlot *slot) {
	for (RaucSlotType *slot_type = supported_slot_types; slot_type->name != NULL; slot_type++) {
		if (g_strcmp0(slot->type, slot_type->name) == 0) {
			return slot_type->mountable;
		}
	}

	return FALSE;
}

static const gchar *supported_bootloaders[] = {"barebox", "grub", "uboot", "efi", "noop", NULL};

gboolean load_config(const gchar *filename, RaucConfig **config, GError **error) {
	GError *ierror = NULL;
	RaucConfig *c = g_new0(RaucConfig, 1);
	gboolean res = FALSE;
	GKeyFile *key_file = NULL;
	gchar **groups;
	gsize group_count;
	GList *slotlist = NULL;
	GHashTable *slots = NULL;
	GList *l;
	gchar *bootloader;
	const gchar **pointer;
	gboolean dtbvariant;
	gchar *variant_data;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

	/* parse [system] section */
	c->system_compatible = g_key_file_get_string(key_file, "system", "compatible", &ierror);
	if (!c->system_compatible) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	bootloader = g_key_file_get_string(key_file, "system", "bootloader", NULL);
	if (!bootloader) {
		g_set_error_literal (
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_BOOTLOADER,
				"No bootloader selected in system config");
		res = FALSE;
		goto free;
	}

	pointer = &supported_bootloaders[0];
	while (*pointer) {
		if (g_strcmp0(bootloader, *pointer) == 0) {
			c->system_bootloader = bootloader;
			break;
		}
		pointer++;
	}

	if (!c->system_bootloader) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_BOOTLOADER,
				"Unsupported bootloader '%s' selected in system config", bootloader);
		res = FALSE;
		goto free;
	}

	c->mount_prefix = g_key_file_get_string(key_file, "system", "mountprefix", NULL);
	if (!c->mount_prefix) {
		g_debug("No mount prefix provided, using /mnt/rauc/ as default");
		c->mount_prefix = g_strdup("/mnt/rauc/");
	}

	if (g_strcmp0(c->system_bootloader, "grub") == 0) {
		c->grubenv_path = resolve_path(filename,
			g_key_file_get_string(key_file, "system", "grubenv", NULL));
		if (!c->grubenv_path) {
			g_debug("No grubenv path provided, using /boot/grub/grubenv as default");
			c->grubenv_path = g_strdup("/boot/grub/grubenv");
		}
	}

	c->activate_installed = g_key_file_get_boolean(key_file, "system", "activate-installed", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->activate_installed = TRUE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}

	c->system_variant_type = R_CONFIG_SYS_VARIANT_NONE;

	/* parse 'variant-dtb' key */
	dtbvariant = g_key_file_get_boolean(key_file, "system", "variant-dtb", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		dtbvariant = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	if (dtbvariant)
		c->system_variant_type = R_CONFIG_SYS_VARIANT_DTB;

	/* parse 'variant-file' key */
	variant_data = g_key_file_get_string(key_file, "system", "variant-file", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		variant_data = NULL;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	if (variant_data) {
		if (c->system_variant_type != R_CONFIG_SYS_VARIANT_NONE) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Only one of the keys 'variant-file', variant-dtb','variant-name' is allowed");
			res = FALSE;
			goto free;
		}

		c->system_variant_type = R_CONFIG_SYS_VARIANT_FILE;
		c->system_variant = variant_data;
	}

	/* parse 'variant-name' key */
	variant_data = g_key_file_get_string(key_file, "system", "variant-name", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		variant_data = NULL;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	if (variant_data) {
		if (c->system_variant_type != R_CONFIG_SYS_VARIANT_NONE) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Only one of the keys 'variant-file', variant-dtb','variant-name' is allowed");
			res = FALSE;
			goto free;
		}

		c->system_variant_type = R_CONFIG_SYS_VARIANT_NAME;
		c->system_variant = variant_data;
	}

	c->statusfile_path = resolve_path(filename,
		g_key_file_get_string(key_file, "system", "statusfile", NULL));

	/* parse [keyring] section */
	c->keyring_path = resolve_path(filename,
		g_key_file_get_string(key_file, "keyring", "path", NULL));

	/* parse [casync] section */
	c->store_path = g_key_file_get_string(key_file, "casync", "storepath", NULL);

	/* parse [autoinstall] section */
	c->autoinstall_path = resolve_path(filename,
		g_key_file_get_string(key_file, "autoinstall", "path", NULL));

	/* parse [handlers] section */
	c->systeminfo_handler = resolve_path(filename,
		g_key_file_get_string(key_file, "handlers", "system-info", NULL));

	c->preinstall_handler = resolve_path(filename,
		g_key_file_get_string(key_file, "handlers", "pre-install", NULL));

	c->postinstall_handler = resolve_path(filename,
		g_key_file_get_string(key_file, "handlers", "post-install", NULL));

	/* parse [slot.*.#] sections */
	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_free_slot);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		RaucSlot *slot = g_new0(RaucSlot, 1);
		gchar **groupsplit;

		groupsplit = g_strsplit(groups[i], ".", -1);

		/* We treat sections starting with "slot." as slots */
		if (g_str_equal(groupsplit[0], RAUC_SLOT_PREFIX)) {
			gchar* value;

			/* Assure slot strings consist of 3 parts, delimited by dots */
			if (g_strv_length(groupsplit) != 3) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_FORMAT,
						"Invalid slot name format: %s", groups[i]);
				res = FALSE;
				goto free;
			}

			value = g_strconcat(groupsplit[1], ".", groupsplit[2], NULL);
			if (!value) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_FORMAT,
						"Invalid slot name");
				res = FALSE;
				goto free;
			}
			slot->name = g_intern_string(value);
			g_free(value);

			slot->description = g_key_file_get_string(key_file, groups[i], "description", NULL);
			if (!slot->description)
				slot->description = g_strdup("");

			slot->sclass = g_intern_string(groupsplit[1]);

			value = resolve_path(filename,
				g_key_file_get_string(key_file, groups[i], "device", &ierror));
			if (!value) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}
			slot->device = value;

			value = g_key_file_get_string(key_file, groups[i], "type", NULL);
			if (!value)
				value = g_strdup("raw");
			slot->type = value;

			value = g_key_file_get_string(key_file, groups[i], "bootname", NULL);
			slot->bootname = value;

			slot->readonly = g_key_file_get_boolean(key_file, groups[i], "readonly", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->readonly = FALSE;
				g_clear_error(&ierror);
			} else if (ierror) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}

			slot->ignore_checksum = g_key_file_get_boolean(key_file, groups[i], "ignore-checksum", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->ignore_checksum = FALSE;
				g_clear_error(&ierror);
			}
			else if (ierror) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}

			g_hash_table_insert(slots, (gchar*)slot->name, slot);

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
			g_set_error (
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_PARENT,
					"Parent slot '%s' not found!", value);
			res = FALSE;
			goto free;
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

RaucSlot *find_config_slot_by_device(RaucConfig *config, const gchar *device) {
	GHashTableIter iter;
	RaucSlot *slot;

	g_hash_table_iter_init(&iter, config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->device, device) == 0) {
			goto out;
		}
	}

	slot = NULL;

out:
	return slot;
}

void free_config(RaucConfig *config) {
	g_return_if_fail(config);

	g_free(config->system_compatible);
	g_free(config->system_bootloader);
	g_free(config->mount_prefix);
	g_free(config->store_path);
	g_free(config->grubenv_path);
	g_free(config->statusfile_path);
	g_free(config->keyring_path);
	g_free(config->autoinstall_path);
	g_free(config->systeminfo_handler);
	g_free(config->preinstall_handler);
	g_free(config->postinstall_handler);
	g_clear_pointer(&config->slots, g_hash_table_destroy);
	g_free(config);
}

static void status_file_get_slot_status(GKeyFile *key_file, const gchar *group, RaucSlotStatus *slotstatus) {
	GError *ierror = NULL;
	gchar *digest;
	guint64 count;

	if (!g_key_file_has_group(key_file, group))
		g_debug("Group %s not found in key file.", group);

	g_free(slotstatus->bundle_compatible);
	g_free(slotstatus->bundle_version);
	g_free(slotstatus->bundle_description);
	g_free(slotstatus->bundle_build);
	g_free(slotstatus->status);
	g_clear_pointer(&slotstatus->checksum.digest, g_free);
	g_free(slotstatus->installed_timestamp);
	g_free(slotstatus->activated_timestamp);

	slotstatus->bundle_compatible = g_key_file_get_string(key_file, group, "bundle.compatible", NULL);
	slotstatus->bundle_version = g_key_file_get_string(key_file, group, "bundle.version", NULL);
	slotstatus->bundle_description = g_key_file_get_string(key_file, group, "bundle.description", NULL);
	slotstatus->bundle_build = g_key_file_get_string(key_file, group, "bundle.build", NULL);
	slotstatus->status = g_key_file_get_string(key_file, group, "status", NULL);

	digest = g_key_file_get_string(key_file, group, "sha256", NULL);
	if (digest) {
		slotstatus->checksum.type = G_CHECKSUM_SHA256;
		slotstatus->checksum.digest = digest;
		slotstatus->checksum.size = g_key_file_get_uint64(key_file, group, "size", NULL);
	}

	slotstatus->installed_timestamp = g_key_file_get_string(key_file, group, "installed.timestamp", NULL);
	count = g_key_file_get_uint64(key_file, group, "installed.count", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE)) {
		g_message("Value of key \"installed.count\" in group [%s] "
			"is no valid unsigned integer - setting to zero.", group);
		count = 0;
	}
	g_clear_error(&ierror);
	if (count > G_MAXUINT32) {
		g_message("Value of key \"installed.count\" in group [%s] "
			"is greater than G_MAXUINT32 - setting to zero.", group);
		count = 0;
	}
	slotstatus->installed_count = count;

	slotstatus->activated_timestamp = g_key_file_get_string(key_file, group, "activated.timestamp", NULL);
	count = g_key_file_get_uint64(key_file, group, "activated.count", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE)) {
		g_message("Value of key \"activated.count\" in group [%s] "
			"is no valid unsigned integer - setting to zero.", group);
		count = 0;
	}
	g_clear_error(&ierror);
	if (count > G_MAXUINT32) {
		g_message("Value of key \"activated.count\" in group [%s] "
			"is greater than G_MAXUINT32 - setting to zero.", group);
		count = 0;
	}
	slotstatus->activated_count = count;
}

static void status_file_set_string_or_remove_key(GKeyFile *key_file, const gchar *group, const gchar *key, gchar *string) {
	if (string)
		g_key_file_set_string(key_file, group, key, string);
	else
		g_key_file_remove_key(key_file, group, key, NULL);
}

static void status_file_set_slot_status(GKeyFile *key_file, const gchar *group, RaucSlotStatus *slotstatus) {
	status_file_set_string_or_remove_key(key_file, group, "bundle.compatible", slotstatus->bundle_compatible);
	status_file_set_string_or_remove_key(key_file, group, "bundle.version", slotstatus->bundle_version);
	status_file_set_string_or_remove_key(key_file, group, "bundle.description", slotstatus->bundle_description);
	status_file_set_string_or_remove_key(key_file, group, "bundle.build", slotstatus->bundle_build);
	status_file_set_string_or_remove_key(key_file, group, "status", slotstatus->status);

	if (slotstatus->checksum.digest && slotstatus->checksum.type == G_CHECKSUM_SHA256) {
		g_key_file_set_string(key_file, group, "sha256", slotstatus->checksum.digest);
		g_key_file_set_uint64(key_file, group, "size", slotstatus->checksum.size);
	} else {
		g_key_file_remove_key(key_file, group, "sha256", NULL);
		g_key_file_remove_key(key_file, group, "size", NULL);
	}

	if (slotstatus->installed_timestamp) {
		g_key_file_set_string(key_file, group, "installed.timestamp", slotstatus->installed_timestamp);
		g_key_file_set_uint64(key_file, group, "installed.count", slotstatus->installed_count);
	} else {
		g_key_file_remove_key(key_file, group, "installed.timestamp", NULL);
		g_key_file_remove_key(key_file, group, "installed.count", NULL);
	}

	if (slotstatus->activated_timestamp) {
		g_key_file_set_string(key_file, group, "activated.timestamp", slotstatus->activated_timestamp);
		g_key_file_set_uint64(key_file, group, "activated.count", slotstatus->activated_count);
	} else {
		g_key_file_remove_key(key_file, group, "activated.timestamp", NULL);
		g_key_file_remove_key(key_file, group, "activated.count", NULL);
	}

	return;
}

gboolean read_slot_status(const gchar *filename, RaucSlotStatus *slotstatus, GError **error) {
	GError *ierror = NULL;
	gboolean res = FALSE;
	GKeyFile *key_file = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(slotstatus, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

	status_file_get_slot_status(key_file, "slot", slotstatus);

	res = TRUE;
free:
	g_key_file_free(key_file);

	return res;
}

gboolean write_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error) {
	GError *ierror = NULL;
	GKeyFile *key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	status_file_set_slot_status(key_file, "slot", ss);

	res = g_key_file_save_to_file(key_file, filename, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

free:
	g_key_file_free(key_file);

	return res;
}

static void load_slot_status_locally(RaucSlot *dest_slot) {
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *slotstatuspath = NULL;

	g_return_if_fail(dest_slot);

	if (dest_slot->status)
		return;

	dest_slot->status = g_new0(RaucSlotStatus, 1);

	if (!is_slot_mountable(dest_slot))
		return;

	/* read slot status */
	g_message("mounting slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_message("Failed to mount slot %s: %s", dest_slot->device, ierror->message);
		goto free;
	}

	slotstatuspath = g_build_filename(dest_slot->mount_point, "slot.raucs", NULL);

	res = read_slot_status(slotstatuspath, dest_slot->status, &ierror);
	if (!res) {
		g_message("Failed to load status file %s: %s", slotstatuspath, ierror->message);
		r_umount_slot(dest_slot, NULL);
		goto free;
	}

	res = r_umount_slot(dest_slot, &ierror);
	if (!res) {
		g_message("Failed to unmount slot %s: %s", dest_slot->device, ierror->message);
		goto free;
	}

free:
	g_clear_pointer(&slotstatuspath, g_free);
	g_clear_error(&ierror);
}

static void load_slot_status_globally(void) {
	GError *ierror = NULL;
	GHashTable *slots = r_context()->config->slots;
	GKeyFile *key_file = g_key_file_new();
	gchar **groups, **group, *slotname;
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_if_fail(r_context()->config->statusfile_path);

	g_key_file_load_from_file(key_file, r_context()->config->statusfile_path, G_KEY_FILE_NONE, &ierror);
	if (ierror && !g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT))
		g_message("load_slot_status_globally: %s.", ierror->message);
	g_clear_error(&ierror);

	/* Load all slot states included in the statusfile */
	groups = g_key_file_get_groups(key_file, NULL);
	for (group = groups; *group != NULL; group++) {
		if (!g_str_has_prefix(*group, RAUC_SLOT_PREFIX "."))
			continue;

		slotname = *group + strlen(RAUC_SLOT_PREFIX ".");
		slot = g_hash_table_lookup(slots, slotname);
		if (!slot || slot->status)
			continue;

		slot->status = g_new0(RaucSlotStatus, 1);
		g_debug("Load status for slot %s.", slot->name);
		status_file_get_slot_status(key_file, *group, slot->status);
	}
	g_strfreev(groups);
	g_clear_pointer(&key_file, g_key_file_free);

	/* Set all other slots to the default status */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (slot->status)
			continue;

		g_debug("Set default status for slot %s.", slot->name);
		slot->status = g_new0(RaucSlotStatus, 1);
	}
}

void load_slot_status(RaucSlot *dest_slot) {
	g_return_if_fail(dest_slot);

	if (dest_slot->status)
		return;

	if (r_context()->config->statusfile_path)
		load_slot_status_globally();
	else
		load_slot_status_locally(dest_slot);
}

static gboolean save_slot_status_locally(RaucSlot *dest_slot, GError **error) {
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *slotstatuspath = NULL;

	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(dest_slot->status, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!is_slot_mountable(dest_slot)) {
		res = TRUE;
		goto free;
	}

	g_debug("mounting slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

	slotstatuspath = g_build_filename(dest_slot->mount_point, "slot.raucs", NULL);
	g_message("Updating slot file %s", slotstatuspath);

	res = write_slot_status(slotstatuspath, dest_slot->status, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		r_umount_slot(dest_slot, NULL);

		goto free;
	}

	res = r_umount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

free:
	g_clear_pointer(&slotstatuspath, g_free);

	return res;
}

static gboolean save_slot_status_globally(GError **error) {
	GKeyFile *key_file = g_key_file_new();
	GError *ierror = NULL;
	GHashTableIter iter;
	RaucSlot *slot;
	gboolean res;
	gchar *group;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(r_context()->config->statusfile_path, FALSE);

	g_debug("Saving global slot status");

	/* Save all slot status information */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (!slot->status) {
			continue;
		}
		group = g_strdup_printf(RAUC_SLOT_PREFIX ".%s", slot->name);
		status_file_set_slot_status(key_file, group, slot->status);
		g_free(group);
	}

	res = g_key_file_save_to_file(key_file, r_context()->config->statusfile_path, &ierror);
	if (!res)
		g_propagate_error(error, ierror);

	g_key_file_free(key_file);

	return res;
}

gboolean save_slot_status(RaucSlot *dest_slot, GError **error) {
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->statusfile_path)
		return save_slot_status_globally(error);
	else
		return save_slot_status_locally(dest_slot, error);
}

void free_slot_status(RaucSlotStatus *slotstatus) {
	g_return_if_fail(slotstatus);

	g_free(slotstatus->bundle_compatible);
	g_free(slotstatus->bundle_version);
	g_free(slotstatus->bundle_description);
	g_free(slotstatus->bundle_build);
	g_free(slotstatus->status);
	g_free(slotstatus->checksum.digest);
	g_free(slotstatus->installed_timestamp);
	g_free(slotstatus->activated_timestamp);
	g_free(slotstatus);
}
