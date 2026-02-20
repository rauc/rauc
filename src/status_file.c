#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "context.h"
#include "mount.h"
#include "status_file.h"
#include "utils.h"

static void status_file_get_slot_status(GKeyFile *key_file, const gchar *group, RaucSlotStatus *slotstatus)
{
	GError *ierror = NULL;
	gchar *digest;
	guint64 count;
	gchar *timestamp;

	if (!g_key_file_has_group(key_file, group))
		g_debug("Group %s not found in key file.", group);

	r_slot_clear_status(slotstatus);

	slotstatus->bundle_compatible = key_file_consume_string(key_file, group, "bundle.compatible", NULL);
	slotstatus->bundle_version = key_file_consume_string(key_file, group, "bundle.version", NULL);
	slotstatus->bundle_description = key_file_consume_string(key_file, group, "bundle.description", NULL);
	slotstatus->bundle_build = key_file_consume_string(key_file, group, "bundle.build", NULL);
	slotstatus->bundle_hash = key_file_consume_string(key_file, group, "bundle.hash", NULL);
	slotstatus->status = key_file_consume_string(key_file, group, "status", NULL);

	digest = key_file_consume_string(key_file, group, "sha256", NULL);
	if (digest) {
		slotstatus->checksum.type = G_CHECKSUM_SHA256;
		slotstatus->checksum.digest = digest;
		slotstatus->checksum.size = g_key_file_get_uint64(key_file, group, "size", NULL);
	}

	timestamp = key_file_consume_string(key_file, group, "installed.timestamp", NULL);
	if (timestamp) {
		slotstatus->installed_timestamp = g_date_time_new_from_iso8601(timestamp, NULL);
		if (!slotstatus->installed_timestamp)
			g_warning("Cannot parse slot 'installed' timestamp '%s'", timestamp);
		g_free(timestamp);
	}
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

	timestamp = key_file_consume_string(key_file, group, "activated.timestamp", NULL);
	if (timestamp) {
		slotstatus->activated_timestamp = g_date_time_new_from_iso8601(timestamp, NULL);
		if (!slotstatus->activated_timestamp)
			g_warning("Cannot parse slot 'activated' timestamp '%s'", timestamp);
		g_free(timestamp);
	}
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
	status_file_set_string_or_remove_key(key_file, group, "bundle.hash", slotstatus->bundle_hash);
	status_file_set_string_or_remove_key(key_file, group, "status", slotstatus->status);

	if (slotstatus->checksum.digest && slotstatus->checksum.type == G_CHECKSUM_SHA256) {
		g_key_file_set_string(key_file, group, "sha256", slotstatus->checksum.digest);
		g_key_file_set_uint64(key_file, group, "size", slotstatus->checksum.size);
	} else {
		g_key_file_remove_key(key_file, group, "sha256", NULL);
		g_key_file_remove_key(key_file, group, "size", NULL);
	}

	status_file_set_string_or_remove_key(key_file, group, "installed.transaction", slotstatus->installed_txn);

	if (slotstatus->installed_timestamp) {
		g_autofree gchar *stamp = g_date_time_format(slotstatus->installed_timestamp, RAUC_FORMAT_ISO_8601);
		g_key_file_set_string(key_file, group, "installed.timestamp", stamp);
	} else {
		g_key_file_remove_key(key_file, group, "installed.timestamp", NULL);
	}

	if (slotstatus->installed_count > 0) {
		g_key_file_set_uint64(key_file, group, "installed.count", slotstatus->installed_count);
	} else {
		g_key_file_remove_key(key_file, group, "installed.count", NULL);
	}

	if (slotstatus->activated_timestamp) {
		g_autofree gchar *stamp = g_date_time_format(slotstatus->activated_timestamp, RAUC_FORMAT_ISO_8601);
		g_key_file_set_string(key_file, group, "activated.timestamp", stamp);
	} else {
		g_key_file_remove_key(key_file, group, "activated.timestamp", NULL);
	}

	if (slotstatus->activated_count > 0) {
		g_key_file_set_uint64(key_file, group, "activated.count", slotstatus->activated_count);
	} else {
		g_key_file_remove_key(key_file, group, "activated.count", NULL);
	}

	return;
}

gboolean r_slot_status_read(const gchar *filename, RaucSlotStatus *slotstatus, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(slotstatus, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	status_file_get_slot_status(key_file, "slot", slotstatus);

	return TRUE;
}

gboolean r_slot_status_write(const gchar *filename, RaucSlotStatus *ss, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;

	key_file = g_key_file_new();

	status_file_set_slot_status(key_file, "slot", ss);

	if (!g_key_file_save_to_file(key_file, filename, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
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

	if (!r_slot_status_read(slotstatuspath, dest_slot->status, &ierror)) {
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

void r_slot_status_load_globally(const gchar *filename, GHashTable *slots)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = g_key_file_new();
	g_auto(GStrv) groups = NULL;
	gchar **group, *slotname;
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_if_fail(filename);
	g_return_if_fail(slots);

	if (!g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror)) {
		if (!g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			g_message("Failed to load global slot status file: %s", ierror->message);
		g_clear_error(&ierror);
	}

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
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &slot)) {
		if (slot->status)
			continue;

		g_debug("Set default status for slot %s.", slot->name);
		slot->status = g_new0(RaucSlotStatus, 1);
	}
}

void r_slot_status_load(RaucSlot *dest_slot)
{
	g_return_if_fail(dest_slot);

	if (!dest_slot->status) {
		if (g_strcmp0(r_context()->config->statusfile_path, "per-slot") == 0)
			load_slot_status_locally(dest_slot);
		else
			r_slot_status_load_globally(r_context()->config->statusfile_path, r_context()->config->slots);
	}

	r_slot_clean_data_directory(dest_slot);
}

static gboolean save_slot_status_locally(RaucSlot *dest_slot, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *slotstatuspath = NULL;

	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(dest_slot->status, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!r_slot_is_mountable(dest_slot)) {
		return TRUE;
	}

	g_debug("mounting slot %s", dest_slot->device);
	if (!r_mount_slot(dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	slotstatuspath = g_build_filename(dest_slot->mount_point, "slot.raucs", NULL);
	g_message("Updating slot file %s", slotstatuspath);

	if (!r_slot_status_write(slotstatuspath, dest_slot->status, &ierror)) {
		g_propagate_error(error, ierror);
		r_umount_slot(dest_slot, NULL);
		return FALSE;
	}

	if (!r_umount_slot(dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/**
 * Returns a new GKeyFile optionally pre-populated form a (shared) key file.
 *
 * With keep_prefix, one can define groups to keep in the returned GKeyFile.
 * All other groups will be removed and can be newly populated.
 *
 * @param path Path to key file
 * @param keep_prefix prefix for groups to keep when loading the file
 * @param error Return location for a GError, or NULL
 *
 * @return newly-allocated GKeyFile or NULL on error
 */
static GKeyFile *key_file_init_from_shared_status_file(const gchar *keep_prefix, GError **error)
{
	g_autoptr(GKeyFile) key_file = NULL;
	g_auto(GStrv) groups = NULL;
	GError *ierror = NULL;

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, r_context()->config->statusfile_path, G_KEY_FILE_NONE, &ierror)) {
		if (g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_info("Status file does not exist yet, ignore loading");
			g_clear_error(&ierror);
		} else {
			g_autofree gchar *broken_file = g_strconcat(r_context()->config->statusfile_path, ".broken", NULL);
			/* Allow recovering from broken status file */
			g_warning("Failed to load status file: %s\n", ierror->message);
			g_warning("Will move status file to %s and re-create it.", broken_file);
			g_clear_error(&ierror);
			if (g_rename(r_context()->config->statusfile_path, broken_file) != 0) {
				int err = errno;
				g_warning("Renaming %s to %s failed: %s", r_context()->config->statusfile_path, broken_file, g_strerror(err));
			}
			g_clear_pointer(&key_file, g_key_file_free);
			key_file = g_key_file_new();
		}
	}

	groups = g_key_file_get_groups(key_file, NULL);
	for (gchar **group = groups; *group != NULL; group++) {
		if (!g_str_has_prefix(*group, keep_prefix))
			continue;

		if (!g_key_file_remove_group(key_file, *group, &ierror)) {
			g_propagate_error(error, ierror);
			return NULL;
		}
	}

	return g_steal_pointer(&key_file);
}

/* Updates slot status information in status file while leaving system status
 * information untouched */
static gboolean save_slot_status_globally(GError **error)
{
	g_autoptr(GKeyFile) key_file = NULL;
	GError *ierror = NULL;
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(r_context()->config->statusfile_path, FALSE);

	g_debug("Saving global slot status");

	key_file = key_file_init_from_shared_status_file(RAUC_SLOT_PREFIX ".", &ierror);
	if (!key_file) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Save all slot status information */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &slot)) {
		g_autofree gchar *group = NULL;

		if (!slot->status) {
			continue;
		}
		group = g_strdup_printf(RAUC_SLOT_PREFIX ".%s", slot->name);
		status_file_set_slot_status(key_file, group, slot->status);
	}

	if (!g_key_file_save_to_file(key_file, r_context()->config->statusfile_path, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

gboolean r_slot_status_save(RaucSlot *dest_slot, GError **error)
{
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_slot_clean_data_directory(dest_slot);

	if (g_strcmp0(r_context()->config->statusfile_path, "per-slot") == 0)
		return save_slot_status_locally(dest_slot, error);
	else
		return save_slot_status_globally(error);
}

gboolean r_system_status_load(const gchar *filename, RSystemStatus *status, GError **error)
{
	g_autoptr(GKeyFile) key_file = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(status, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	status->boot_id = g_key_file_get_string(key_file, "system", "boot-id", NULL);

	return TRUE;
}

gboolean r_system_status_save(GError **error)
{
	g_autoptr(GKeyFile) key_file = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* noop if per-slot status file is used */
	if (g_strcmp0(r_context()->config->statusfile_path, "per-slot") == 0) {
		g_message("Not saving system status since per-slot status file is used");
		return TRUE;
	}

	key_file = key_file_init_from_shared_status_file("system", &ierror);
	if (!key_file) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_key_file_set_string(key_file, "system", "boot-id", r_context()->system_status->boot_id);

	if (!g_key_file_save_to_file(key_file, r_context()->config->statusfile_path, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

void r_system_status_free(RSystemStatus *state)
{
	g_free(state->boot_id);
	g_free(state);
}
