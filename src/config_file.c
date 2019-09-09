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

gboolean default_config(RaucConfig **config)
{
	RaucConfig *c = g_new0(RaucConfig, 1);

	c->max_bundle_download_size = DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE;
	c->mount_prefix = g_strdup("/mnt/rauc/");

	*config = c;
	return TRUE;
}

static const gchar *supported_bootloaders[] = {"barebox", "grub", "uboot", "efi", "noop", NULL};

gboolean load_config(const gchar *filename, RaucConfig **config, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucConfig) c = g_new0(RaucConfig, 1);
	gboolean res = FALSE;
	g_autoptr(GKeyFile) key_file = NULL;
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
	c->system_compatible = key_file_consume_string(key_file, "system", "compatible", &ierror);
	if (!c->system_compatible) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	bootloader = key_file_consume_string(key_file, "system", "bootloader", NULL);
	if (!bootloader) {
		g_set_error_literal(
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

	if (g_strcmp0(c->system_bootloader, "barebox") == 0) {
		c->system_bb_statename = key_file_consume_string(key_file, "system", "barebox-statename", NULL);
	} else if (g_strcmp0(c->system_bootloader, "grub") == 0) {
		c->grubenv_path = resolve_path(filename,
				key_file_consume_string(key_file, "system", "grubenv", NULL));
		if (!c->grubenv_path) {
			g_debug("No grubenv path provided, using /boot/grub/grubenv as default");
			c->grubenv_path = g_strdup("/boot/grub/grubenv");
		}
	} else if (g_strcmp0(c->system_bootloader, "efi") == 0) {
		c->efi_use_bootnext = g_key_file_get_boolean(key_file, "system", "efi-use-bootnext", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			c->efi_use_bootnext = TRUE;
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			res = FALSE;
			goto free;
		}
		g_key_file_remove_key(key_file, "system", "efi-use-bootnext", NULL);
	}

	c->max_bundle_download_size = g_key_file_get_uint64(key_file, "system", "max-bundle-download-size", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_debug("No value for key \"max-bundle-download-size\" in [system] defined "
				"- using default value of %d bytes.", DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE);
		c->max_bundle_download_size = DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	if (c->max_bundle_download_size == 0) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_MAX_BUNDLE_DOWNLOAD_SIZE,
				"Invalid value (%" G_GUINT64_FORMAT ") for key \"max-bundle-download-size\" in system config", c->max_bundle_download_size);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_key(key_file, "system", "max-bundle-download-size", NULL);

	c->mount_prefix = key_file_consume_string(key_file, "system", "mountprefix", NULL);
	if (!c->mount_prefix) {
		g_debug("No mount prefix provided, using /mnt/rauc/ as default");
		c->mount_prefix = g_strdup("/mnt/rauc/");
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
	g_key_file_remove_key(key_file, "system", "activate-installed", NULL);

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
	g_key_file_remove_key(key_file, "system", "variant-dtb", NULL);
	if (dtbvariant)
		c->system_variant_type = R_CONFIG_SYS_VARIANT_DTB;

	/* parse 'variant-file' key */
	variant_data = key_file_consume_string(key_file, "system", "variant-file", &ierror);
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
	variant_data = key_file_consume_string(key_file, "system", "variant-name", &ierror);
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
			key_file_consume_string(key_file, "system", "statusfile", NULL));
	if (!check_remaining_keys(key_file, "system", &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_group(key_file, "system", NULL);

	/* parse [keyring] section */
	c->keyring_path = resolve_path(filename,
			key_file_consume_string(key_file, "keyring", "path", NULL));
	c->keyring_directory = resolve_path(filename,
			key_file_consume_string(key_file, "keyring", "directory", NULL));

	c->use_bundle_signing_time = g_key_file_get_boolean(key_file, "keyring", "use-bundle-signing-time", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		c->use_bundle_signing_time = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_key(key_file, "keyring", "use-bundle-signing-time", NULL);

	if (!check_remaining_keys(key_file, "keyring", &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_group(key_file, "keyring", NULL);

	/* parse [casync] section */
	c->store_path = key_file_consume_string(key_file, "casync", "storepath", NULL);
	c->tmp_path = key_file_consume_string(key_file, "casync", "tmppath", NULL);
	if (!check_remaining_keys(key_file, "casync", &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_group(key_file, "casync", NULL);

	/* parse [autoinstall] section */
	c->autoinstall_path = resolve_path(filename,
			key_file_consume_string(key_file, "autoinstall", "path", NULL));
	if (!check_remaining_keys(key_file, "autoinstall", &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_group(key_file, "autoinstall", NULL);

	/* parse [handlers] section */
	c->systeminfo_handler = resolve_path(filename,
			key_file_consume_string(key_file, "handlers", "system-info", NULL));

	c->preinstall_handler = resolve_path(filename,
			key_file_consume_string(key_file, "handlers", "pre-install", NULL));

	c->postinstall_handler = resolve_path(filename,
			key_file_consume_string(key_file, "handlers", "post-install", NULL));
	if (!check_remaining_keys(key_file, "handlers", &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}
	g_key_file_remove_group(key_file, "handlers", NULL);

	/* parse [slot.*.#] sections */
	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);

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

			slot->description = key_file_consume_string(key_file, groups[i], "description", NULL);
			if (!slot->description)
				slot->description = g_strdup("");

			slot->sclass = g_intern_string(groupsplit[1]);

			value = resolve_path(filename,
					key_file_consume_string(key_file, groups[i], "device", &ierror));
			if (!value) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}
			slot->device = value;

			value = key_file_consume_string(key_file, groups[i], "type", NULL);
			if (!value)
				value = g_strdup("raw");
			slot->type = value;

			value = key_file_consume_string(key_file, groups[i], "bootname", NULL);
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
			g_key_file_remove_key(key_file, groups[i], "readonly", NULL);

			slot->install_same = g_key_file_get_boolean(key_file, groups[i], "install-same", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				g_clear_error(&ierror);
				/* try also deprecated flag force-install-same */
				slot->install_same = g_key_file_get_boolean(key_file, groups[i], "force-install-same", &ierror);
				if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
					g_clear_error(&ierror);
					/* try also deprecated flag ignore-checksum */
					slot->install_same = g_key_file_get_boolean(key_file, groups[i], "ignore-checksum", &ierror);
					if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
						slot->install_same = TRUE;
						g_clear_error(&ierror);
					}
					else if (ierror) {
						g_propagate_error(error, ierror);
						res = FALSE;
						goto free;
					}
				}
				else if (ierror) {
					g_propagate_error(error, ierror);
					res = FALSE;
					goto free;
				}
			}
			else if (ierror) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}
			g_key_file_remove_key(key_file, groups[i], "install-same", NULL);
			g_key_file_remove_key(key_file, groups[i], "force-install-same", NULL);
			g_key_file_remove_key(key_file, groups[i], "ignore-checksum", NULL);

			slot->extra_mount_opts = key_file_consume_string(key_file, groups[i], "extra-mount-opts", NULL);

			slot->resize = g_key_file_get_boolean(key_file, groups[i], "resize", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->resize = FALSE;
				g_clear_error(&ierror);
			}
			else if (ierror) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto free;
			}
			g_key_file_remove_key(key_file, groups[i], "resize", NULL);

			if (g_strcmp0(slot->type, "boot-mbr-switch") == 0) {
				slot->region_start = key_file_consume_binary_suffixed_string(key_file, groups[i],
						"region-start", &ierror);
				if (ierror) {
					g_propagate_prefixed_error(error, ierror, "mandatory for boot-mbr-switch: ");
					res = FALSE;
					goto free;
				}

				slot->region_size = key_file_consume_binary_suffixed_string(key_file, groups[i],
						"region-size", &ierror);
				if (ierror) {
					g_propagate_prefixed_error(error, ierror, "mandatory for boot-mbr-switch: ");
					res = FALSE;
					goto free;
				}
			}

			g_hash_table_insert(slots, (gchar*)slot->name, slot);
		}
		g_strfreev(groupsplit);
	}

	/* Add parent pointers */
	slotlist = g_hash_table_get_keys(slots);
	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s;
		g_autofree gchar* group_name = NULL;
		gchar* value;

		group_name = g_strconcat(RAUC_SLOT_PREFIX ".", l->data, NULL);
		value = key_file_consume_string(key_file, group_name, "parent", NULL);
		if (!value) {
			g_key_file_remove_group(key_file, group_name, NULL);
			continue;
		}

		s = g_hash_table_lookup(slots, value);
		if (!s) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_PARENT,
					"Parent slot '%s' not found!", value);
			res = FALSE;
			goto free;
		}

		((RaucSlot*)g_hash_table_lookup(slots, l->data))->parent = s;


		if (!check_remaining_keys(key_file, group_name, &ierror)) {
			g_propagate_error(error, ierror);
			res = FALSE;
			goto free;
		}
		g_key_file_remove_group(key_file, group_name, NULL);
	}
	g_list_free(slotlist);

	c->slots = slots;

	if (!check_remaining_groups(key_file, &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto free;
	}

	g_strfreev(groups);

	res = TRUE;
free:
	if (res)
		*config = g_steal_pointer(&c);
	else
		*config = NULL;
	return res;
}

RaucSlot *find_config_slot_by_device(RaucConfig *config, const gchar *device)
{
	g_return_val_if_fail(config, NULL);

	return r_slot_find_by_device(config->slots, device);
}

void free_config(RaucConfig *config)
{
	g_return_if_fail(config);

	g_free(config->system_compatible);
	g_free(config->system_bootloader);
	g_free(config->mount_prefix);
	g_free(config->store_path);
	g_free(config->tmp_path);
	g_free(config->grubenv_path);
	g_free(config->statusfile_path);
	g_free(config->keyring_path);
	g_free(config->keyring_directory);
	g_free(config->autoinstall_path);
	g_free(config->systeminfo_handler);
	g_free(config->preinstall_handler);
	g_free(config->postinstall_handler);
	g_clear_pointer(&config->slots, g_hash_table_destroy);
	g_free(config);
}

static void status_file_get_slot_status(GKeyFile *key_file, const gchar *group, RaucSlotStatus *slotstatus)
{
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

	slotstatus->bundle_compatible = key_file_consume_string(key_file, group, "bundle.compatible", NULL);
	slotstatus->bundle_version = key_file_consume_string(key_file, group, "bundle.version", NULL);
	slotstatus->bundle_description = key_file_consume_string(key_file, group, "bundle.description", NULL);
	slotstatus->bundle_build = key_file_consume_string(key_file, group, "bundle.build", NULL);
	slotstatus->status = key_file_consume_string(key_file, group, "status", NULL);

	digest = key_file_consume_string(key_file, group, "sha256", NULL);
	if (digest) {
		slotstatus->checksum.type = G_CHECKSUM_SHA256;
		slotstatus->checksum.digest = digest;
		slotstatus->checksum.size = g_key_file_get_uint64(key_file, group, "size", NULL);
	}

	slotstatus->installed_timestamp = key_file_consume_string(key_file, group, "installed.timestamp", NULL);
	count = g_key_file_get_uint64(key_file, group, "installed.count", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE))
		g_message("Value of key \"installed.count\" in group [%s] "
				"is no valid unsigned integer - setting to zero.", group);
	else if (ierror && !g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND))
		g_message("Unexpected error while trying to read key \"installed.count\" in group [%s] "
				"- setting to zero: %s", group, ierror->message);
	g_clear_error(&ierror);
	if (count > G_MAXUINT32) {
		g_message("Value of key \"installed.count\" in group [%s] "
				"is greater than G_MAXUINT32 - setting to zero.", group);
		count = 0;
	}
	slotstatus->installed_count = count;

	slotstatus->activated_timestamp = key_file_consume_string(key_file, group, "activated.timestamp", NULL);
	count = g_key_file_get_uint64(key_file, group, "activated.count", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE))
		g_message("Value of key \"activated.count\" in group [%s] "
				"is no valid unsigned integer - setting to zero.", group);
	else if (ierror && !g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND))
		g_message("Unexpected error while trying to read key \"activated.count\" in group [%s] "
				"- setting to zero: %s", group, ierror->message);
	g_clear_error(&ierror);
	if (count > G_MAXUINT32) {
		g_message("Value of key \"activated.count\" in group [%s] "
				"is greater than G_MAXUINT32 - setting to zero.", group);
		count = 0;
	}
	slotstatus->activated_count = count;
}

static void status_file_set_string_or_remove_key(GKeyFile *key_file, const gchar *group, const gchar *key, gchar *string)
{
	if (string)
		g_key_file_set_string(key_file, group, key, string);
	else
		g_key_file_remove_key(key_file, group, key, NULL);
}

static void status_file_set_slot_status(GKeyFile *key_file, const gchar *group, RaucSlotStatus *slotstatus)
{
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

gboolean read_slot_status(const gchar *filename, RaucSlotStatus *slotstatus, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GKeyFile) key_file = NULL;

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
	return res;
}

gboolean write_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	status_file_set_slot_status(key_file, "slot", ss);

	res = g_key_file_save_to_file(key_file, filename, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto free;
	}

free:
	return res;
}

static void load_slot_status_locally(RaucSlot *dest_slot)
{
	GError *ierror = NULL;
	g_autofree gchar *slotstatuspath = NULL;

	g_return_if_fail(dest_slot);

	if (dest_slot->status)
		return;

	dest_slot->status = g_new0(RaucSlotStatus, 1);

	if (!r_slot_is_mountable(dest_slot))
		return;

	/* read slot status */
	if (!dest_slot->ext_mount_point) {
		g_message("mounting slot %s", dest_slot->device);
		if (!r_mount_slot(dest_slot, &ierror)) {
			g_message("Failed to mount slot %s: %s", dest_slot->device, ierror->message);
			g_clear_error(&ierror);
			return;
		}
	}

	slotstatuspath = g_build_filename(
			dest_slot->ext_mount_point ? dest_slot->ext_mount_point : dest_slot->mount_point,
			"slot.raucs", NULL);

	if (!read_slot_status(slotstatuspath, dest_slot->status, &ierror)) {
		g_message("Failed to load status file %s: %s", slotstatuspath, ierror->message);
		g_clear_error(&ierror);
	}

	if (!dest_slot->ext_mount_point) {
		if (!r_umount_slot(dest_slot, &ierror)) {
			g_message("Failed to unmount slot %s: %s", dest_slot->device, ierror->message);
			g_clear_error(&ierror);
			return;
		}
	}
}

static void load_slot_status_globally(void)
{
	GError *ierror = NULL;
	GHashTable *slots = r_context()->config->slots;
	g_autoptr(GKeyFile) key_file = g_key_file_new();
	g_auto(GStrv) groups = NULL;
	gchar **group, *slotname;
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

	/* Set all other slots to the default status */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (slot->status)
			continue;

		g_debug("Set default status for slot %s.", slot->name);
		slot->status = g_new0(RaucSlotStatus, 1);
	}
}

void load_slot_status(RaucSlot *dest_slot)
{
	g_return_if_fail(dest_slot);

	if (dest_slot->status)
		return;

	if (r_context()->config->statusfile_path)
		load_slot_status_globally();
	else
		load_slot_status_locally(dest_slot);
}

static gboolean save_slot_status_locally(RaucSlot *dest_slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autofree gchar *slotstatuspath = NULL;

	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(dest_slot->status, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!r_slot_is_mountable(dest_slot)) {
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
	return res;
}

static gboolean save_slot_status_globally(GError **error)
{
	g_autoptr(GKeyFile) key_file = g_key_file_new();
	GError *ierror = NULL;
	GHashTableIter iter;
	RaucSlot *slot;
	gboolean res;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(r_context()->config->statusfile_path, FALSE);

	g_debug("Saving global slot status");

	/* Save all slot status information */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		g_autofree gchar *group = NULL;

		if (!slot->status) {
			continue;
		}
		group = g_strdup_printf(RAUC_SLOT_PREFIX ".%s", slot->name);
		status_file_set_slot_status(key_file, group, slot->status);
	}

	res = g_key_file_save_to_file(key_file, r_context()->config->statusfile_path, &ierror);
	if (!res)
		g_propagate_error(error, ierror);

	return res;
}

gboolean save_slot_status(RaucSlot *dest_slot, GError **error)
{
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->statusfile_path)
		return save_slot_status_globally(error);
	else
		return save_slot_status_locally(dest_slot, error);
}
