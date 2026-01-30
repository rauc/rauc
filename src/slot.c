#include <errno.h>
#include <stdio.h>

#include "slot.h"

#include "utils.h"

void r_slot_free(gpointer value)
{
	RaucSlot *slot = (RaucSlot*)value;

	if (!slot)
		return;

	/* Not freeing slot->name and slot->sclass here since they
	 * are expected to be intern strings! */

	g_free(slot->description);
	g_free(slot->device);
	g_free(slot->type);
	g_strfreev(slot->extra_mkfs_opts);
	g_free(slot->bootname);
	g_free(slot->extra_mount_opts);
	g_free(slot->parent_name);
	g_free(slot->mount_point);
	g_free(slot->ext_mount_point);
	g_clear_pointer(&slot->status, r_slot_free_status);
	g_free(slot->data_directory);
	g_free(slot->efi_loader);
	g_free(slot->efi_cmdline);
	g_free(slot);
}

void r_slot_clear_status(RaucSlotStatus *slotstatus)
{
	if (!slotstatus)
		return;

	g_clear_pointer(&slotstatus->bundle_compatible, g_free);
	g_clear_pointer(&slotstatus->bundle_version, g_free);
	g_clear_pointer(&slotstatus->bundle_description, g_free);
	g_clear_pointer(&slotstatus->bundle_build, g_free);
	g_clear_pointer(&slotstatus->bundle_hash, g_free);
	g_clear_pointer(&slotstatus->status, g_free);
	g_clear_pointer(&slotstatus->checksum.digest, g_free);
	slotstatus->checksum.size = 0;
	g_clear_pointer(&slotstatus->installed_txn, g_free);
	g_clear_pointer(&slotstatus->installed_timestamp, g_date_time_unref);
	g_clear_pointer(&slotstatus->activated_timestamp, g_date_time_unref);
}

void r_slot_free_status(RaucSlotStatus *slotstatus)
{
	if (!slotstatus)
		return;

	r_slot_clear_status(slotstatus);
	g_free(slotstatus);
}

RaucSlot *r_slot_find_by_device(GHashTable *slots, const gchar *device)
{
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(device, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->device, device) == 0) {
			return slot;
		}
	}

	return NULL;
}

RaucSlot *r_slot_get_booted(GHashTable *slots)
{
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(slots, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (slot->state == ST_BOOTED) {
			return slot;
		}
	}

	return NULL;
}

/* returns string representation of slot state */
const gchar* r_slot_slotstate_to_str(SlotState slotstate)
{
	switch (slotstate) {
		case ST_ACTIVE:
			return "active";
		case ST_INACTIVE:
			return "inactive";
		case ST_BOOTED:
			return "booted";
			break;
		case ST_UNKNOWN:
		default:
			g_error("invalid slot status %d", slotstate);
			break;
	}

	return NULL;
}

SlotState r_slot_str_to_slotstate(gchar *str)
{
	if (g_strcmp0(str, "active") == 0) {
		return ST_ACTIVE;
	} else if (g_strcmp0(str, "inactive") == 0) {
		return ST_INACTIVE;
	} else if (g_strcmp0(str, "booted") == 0) {
		return ST_BOOTED;
	}

	return ST_UNKNOWN;
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
	{"nor", FALSE},
	{"boot-emmc", FALSE},
	{"boot-mbr-switch", FALSE},
	{"boot-gpt-switch", FALSE},
	{"vfat", TRUE},
	{"boot-raw-fallback", FALSE},
	{"emmc-boot-linked", FALSE},
	{}
};

gboolean r_slot_is_valid_type(const gchar *type)
{
	for (RaucSlotType *slot_type = supported_slot_types; slot_type->name != NULL; slot_type++) {
		if (g_strcmp0(type, slot_type->name) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean r_slot_is_mountable(RaucSlot *slot)
{
	for (RaucSlotType *slot_type = supported_slot_types; slot_type->name != NULL; slot_type++) {
		if (g_strcmp0(slot->type, slot_type->name) == 0) {
			return slot_type->mountable;
		}
	}

	return FALSE;
}

RaucSlot* r_slot_get_parent_root(RaucSlot *slot)
{
	RaucSlot *base = NULL;

	g_return_val_if_fail(slot, NULL);

	base = slot;
	while (base != NULL && base->parent != NULL)
		base = base->parent;

	return base;
}

gchar *r_slot_get_checksum_data_directory(const RaucSlot *slot, const RaucChecksum *checksum, GError **error)
{
	const gchar *hex_digest = NULL;
	g_autofree gchar *sub_directory = NULL;
	g_autofree gchar *path = NULL;

	g_return_val_if_fail(slot, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!slot->data_directory) {
		return NULL;
	}

	if (checksum) {
		hex_digest = checksum->digest;
	}
	if (!hex_digest && slot->status) {
		hex_digest = slot->status->checksum.digest;
	}
	if (!hex_digest) {
		hex_digest = "unknown";
	}

	sub_directory = g_strdup_printf("hash-%s", hex_digest);

	path = g_build_filename(slot->data_directory, sub_directory, NULL);
	if (g_mkdir_with_parents(path, 0700) != 0) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to create slot data directory '%s': %s",
				path,
				g_strerror(err));
		return NULL;
	}

	return g_steal_pointer(&path);
}

gboolean r_slot_move_checksum_data_directory(const RaucSlot *slot, const gchar *old_digest, const gchar *new_digest, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!slot->data_directory) {
		/* nothing to do */
		return TRUE;
	}

	if (!old_digest) {
		/* nothing to do */
		return TRUE;
	}

	if (!new_digest) {
		new_digest = "unknown";
	}

	g_autofree gchar *old_sub_directory = g_strdup_printf("hash-%s", old_digest);
	g_autofree gchar *old_path = g_build_filename(slot->data_directory, old_sub_directory, NULL);

	g_autofree gchar *new_sub_directory = g_strdup_printf("hash-%s", new_digest);
	g_autofree gchar *new_path = g_build_filename(slot->data_directory, new_sub_directory, NULL);

	if (g_file_test(new_path, G_FILE_TEST_EXISTS)) {
		if (!rm_tree(new_path, &ierror)) {
			g_propagate_prefixed_error(error, ierror, "Failed to remove existing data directory %s: ", new_path);
			return FALSE;
		}
	}

	if (rename(old_path, new_path) == -1) {
		int err = errno;
		/* Continue if the old path doesn't exist. */
		if (err == ENOENT)
			return TRUE;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to move data directory to %s: %s", new_path, g_strerror(err));
		return FALSE;
	}

	return TRUE;
}

void r_slot_clean_data_directory(const RaucSlot *slot)
{
	GError *ierror = NULL;
	const gchar *hex_digest = NULL;
	g_autoptr(GDir) dir = NULL;
	g_autofree gchar *expected_directory = NULL;
	const gchar *name;

	g_return_if_fail(slot);

	if (!slot->data_directory) {
		return;
	}

	g_assert(g_path_is_absolute(slot->data_directory));

	/* Do not attempt to clean yet when slot status is still 'pending' */
	if (slot->status && g_strcmp0(slot->status->status, "pending") == 0)
		return;

	if (slot->status) {
		hex_digest = slot->status->checksum.digest;
	} else {
		hex_digest = "unknown";
	}

	expected_directory = g_strdup_printf("hash-%s", hex_digest);
	dir = g_dir_open(slot->data_directory, 0, NULL);
	if (!dir)
		return;

	while ((name = g_dir_read_name(dir))) {
		g_autofree gchar *path = NULL;
		if (!g_str_has_prefix(name, "hash-")) {
			continue;
		}
		if (g_str_equal(name, expected_directory)) {
			continue;
		}

		/* We have a subdir that begins with hash-, but doesn't match the current hash. */
		path = g_build_filename(slot->data_directory, name, NULL);
		g_debug("removing obsolete slot data dir '%s'", path);

		if (!rm_tree(path, &ierror)) {
			g_warning("Continuing after failure to remove old slot data dir: %s", ierror->message);
			g_clear_error(&ierror);
		}
	}
}

gchar** r_slot_get_root_classes(GHashTable *slots)
{
	GPtrArray *slotclasses = NULL;
	GHashTableIter iter;
	RaucSlot *iterslot = NULL;

	g_return_val_if_fail(slots, NULL);

	slotclasses = g_ptr_array_new();

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &iterslot)) {
		const gchar *key = NULL;

		g_assert_nonnull(iterslot->sclass);

		if (iterslot->parent)
			continue;

		key = g_intern_string(iterslot->sclass);
		g_ptr_array_remove_fast(slotclasses, (gpointer)key); /* avoid duplicates */
		g_ptr_array_add(slotclasses, (gpointer)key);
	}
	g_ptr_array_add(slotclasses, NULL);

	return (gchar**) g_ptr_array_free(slotclasses, FALSE);
}

gboolean r_slot_list_contains(GList *slotlist, const RaucSlot *testslot)
{
	g_return_val_if_fail(testslot, FALSE);

	if (!slotlist)
		return FALSE;

	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *slot = l->data;

		if (slot == testslot) {
			return TRUE;
		}
	}

	return FALSE;
}

GList* r_slot_get_all_of_class(GHashTable *slots, const gchar* class)
{
	GList *retlist = NULL;
	GHashTableIter iter;
	gchar *name;
	RaucSlot *slot = NULL;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(class, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, (gpointer*) &name, (gpointer*) &slot)) {
		if (g_strcmp0(slot->sclass, class) != 0)
			continue;
		retlist = g_list_append(retlist, slot);
	}

	return retlist;
}

GList* r_slot_get_all_children(GHashTable *slots, RaucSlot *parent)
{
	GList *retlist = NULL;
	GHashTableIter iter;
	gchar *name;
	RaucSlot *slot = NULL;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(parent, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, (gpointer*) &name, (gpointer*) &slot)) {
		if (slot == parent)
			continue;

		if (parent != r_slot_get_parent_root(slot))
			continue;

		retlist = g_list_append(retlist, slot);
	}

	return retlist;
}

GList* r_slot_get_all_of_type(GHashTable *slots, const gchar* type)
{
	GList *retlist = NULL;
	GHashTableIter iter;
	RaucSlot *slot = NULL;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(type, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->type, type) == 0) {
			retlist = g_list_append(retlist, slot);
		}
	}

	return retlist;
}
