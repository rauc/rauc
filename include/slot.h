#pragma once

#include <glib.h>

#include "checksum.h"

typedef enum {
	ST_UNKNOWN = 0,
	ST_ACTIVE = 1,
	ST_INACTIVE = 2,
	ST_BOOTED = 4 | ST_ACTIVE,
} SlotState;

typedef struct {
	gchar *bundle_compatible;
	gchar *bundle_version;
	gchar *bundle_description;
	gchar *bundle_build;
	gchar *bundle_hash;
	gchar *status;
	RaucChecksum checksum;
	gchar *installed_txn;
	GDateTime *installed_timestamp;
	guint32 installed_count;
	GDateTime *activated_timestamp;
	guint32 activated_count;
} RaucSlotStatus;

#define RAUC_FORMAT_ISO_8601 "%Y-%m-%dT%H:%M:%SZ"

typedef struct _RaucSlot {
	/** name of the slot. A glib intern string. */
	const gchar *name;
	/** user-friendly description of the slot. */
	gchar *description;
	/** slot class the slot belongs to. A glib intern string. */
	const gchar *sclass;
	/** device this slot uses */
	gchar *device;
	/** the slots partition type */
	gchar *type;
	/** extra mkfs options for this slot */
	gchar **extra_mkfs_opts;
	/** the name this slot is known to the bootloader */
	gchar *bootname;
	/** flag to indicate that this slot can be updated even if already mounted */
	gboolean allow_mounted;
	/** flag indicating if the slot is updatable */
	gboolean readonly;
	/** flag indicating if slot skipping optimization should be used */
	gboolean install_same;
	/** extra mount options for this slot */
	gchar *extra_mount_opts;
	/** flag indicating to resize after writing (only for ext4) */
	gboolean resize;
	/** start address of first boot-partition (for boot-mbr-switch, boot-gpt-switch and boot-raw-fallback) */
	guint64 region_start;
	/** size of both partitions(for boot-mbr-switch, boot-gpt-switch and boot-raw-fallback) */
	guint64 region_size;
	/** limit the writable size of the boot partition (for boot-emmc) */
	guint64 size_limit;
	gchar *efi_loader;
	gchar *efi_cmdline;

	/** current state of the slot (runtime) */
	SlotState state;
	gboolean boot_good;
	struct _RaucSlot *parent;
	/** the name of the parent as parsed by config (parsing-internal use only) */
	gchar *parent_name;
	gchar *mount_point;
	gchar *ext_mount_point;
	RaucSlotStatus *status;
	/** the name of the per-slot data subdirectory */
	gchar *data_directory;
} RaucSlot;

/**
 * Frees the memory allocated by a RaucSlot
 */
void r_slot_free(gpointer value);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucSlot, r_slot_free);

/**
 * Clears the data in a RaucSlotStatus.
 *
 * @param slotstatus a RaucSlotStatus
 */
void r_slot_clear_status(RaucSlotStatus *slotstatus);

/**
 * Frees the memory allocated by the RaucSlotStatus.
 *
 * @param slotstatus a RaucSlotStatus
 */
void r_slot_free_status(RaucSlotStatus *slotstatus);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucSlotStatus, r_slot_free_status);

/**
 * Finds a slot given its device path.
 *
 * @param slots a GHashTable containing (gchar, RaucSlot) entries
 * @param device the device path to search for
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *r_slot_find_by_device(GHashTable *slots, const gchar *device)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns booted slot.
 *
 * @param slots a GHashTable containing (gchar, RaucSlot) entries
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *r_slot_get_booted(GHashTable *slots);

/**
 * Get string representation of slot state
 *
 * @param slotstate state to turn into string
 *
 * @return string representation of slot state
 */
const gchar* r_slot_slotstate_to_str(SlotState slotstate)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get SlotState from string representation.
 *
 * @param str string representation of state
 *
 * @return corresponding SlotState value
 */
SlotState r_slot_str_to_slotstate(gchar *str)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check if slot type name is valid.
 *
 * @param typename Name of type as string
 *
 * @return TRUE if it is a valid (known) slot type, otherwise FALSE
 */
gboolean r_slot_is_valid_type(const gchar *type)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check if slot type is mountable.
 *
 * @param slot slot to check
 *
 * @return TRUE if mountable, otherwise FALSE
 */
gboolean r_slot_is_mountable(RaucSlot *slot)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the parent root slot for given slot.
 *
 * If the given slot is a root slot itself, a pointer to itself will be
 * returned.
 *
 * @param slot slot to find parent root slot for
 *
 * @return pointer to RaucSlot
 */
RaucSlot* r_slot_get_parent_root(RaucSlot *slot)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Moves a data directory to a name with a different digest.
 *
 * This is useful when we want to update a slot, as we move it to the "unknown"
 * digest while we are writing to it. Existing data for the new digest is
 * removed. If no data exists for the old digest, nothing is moved.
 *
 * @param slot slot for which the data directory should be moved
 * @param old_digest the old digest or NULL
 * @param new_digest the new digest or NULL
 *
 * @return TRUE if successful, otherwise FALSE
 */
gboolean r_slot_move_checksum_data_directory(const RaucSlot *slot, const gchar *old_digest, const gchar *new_digest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the data subdirectory corresponding to the current or given
 * hash/checksum.
 *
 * To allow cleanup of data that corresponds to a specific image hash, we use a
 * hash-<hash value>/ subdirectory in /<rauc data dir>/<slot data dir>/.
 *
 * If the directory does not exist, it is created.
 *
 * @param slot slot to clean data directory for
 * @param checksum optional checksum to use instead of the current one
 *
 * @return name of the directory, must be freed.
 */
gchar *r_slot_get_checksum_data_directory(const RaucSlot *slot, const RaucChecksum *checksum, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * This removes obsolete data in /<rauc data dir>/<slot data dir>/.
 *
 * Currently, it removes subdirectories which match hash-<hash value>/, but don't correspond to the current slot
 * hash/checksum.
 *
 * @param slot slot to get the data directory for
 */
void r_slot_clean_data_directory(const RaucSlot *slot);

/**
 * Gets all classes that do not have a parent
 *
 * @return NULL-teminated array of intern strings. Free with g_free().
 */
gchar** r_slot_get_root_classes(GHashTable *slots)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Test if provided slot list contains slot instance (same pointer!)
 *
 * @param slots GHashTable of system slots
 * @param testslot Slot to find
 *
 * @return TRUE if slot was found, FALSE if not
 */
gboolean r_slot_list_contains(GList *slotlist, const RaucSlot *testslot)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns list of slots of given slot class
 *
 * @param slots GHashTable of system slots
 * @param class name of class to find all slots for
 *
 * @return list of pointers to all members of slots hash table that are of
 *         selected class.
 */
GList* r_slot_get_all_of_class(GHashTable *slots, const gchar* class)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns list of child slots of given parent slot.
 *
 * @param slots GHashTable of system slots
 * @param parent Slot to find children for
 *
 * @return list of pointers to all members of slots hash table that are children
 *         of given slot.
 */
GList* r_slot_get_all_children(GHashTable *slots, RaucSlot *parent)
G_GNUC_WARN_UNUSED_RESULT;
