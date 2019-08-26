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
	gchar *status;
	RaucChecksum checksum;
	gchar *installed_timestamp;
	guint32 installed_count;
	gchar *activated_timestamp;
	guint32 activated_count;
} RaucSlotStatus;

typedef struct _RaucSlot {
	/** name of the slot. A glib intern string. */
	const gchar *name;
	/** user-friendly description of the slot. A glib intern string. */
	gchar *description;
	/** slot class the slot belongs to. A glib intern string. */
	const gchar *sclass;
	/** device this slot uses */
	gchar *device;
	/** the slots partition type */
	gchar *type;
	/** the name this slot is known to the bootloader */
	gchar *bootname;
	/** flag indicating if the slot is updatable */
	gboolean readonly;
	/** flag indicating if slot skipping optimization should be used */
	gboolean install_same;
	/** extra mount options for this slot */
	gchar *extra_mount_opts;
	/** flag indicating to resize after writing (only for ext4) */
	gboolean resize;
	/** start address of first boot-partition (only for boot-mbr-switch) */
	guint64 region_start;
	/** size of both partitions(only for boot-mbr-switch) */
	guint64 region_size;

	/** current state of the slot (runtime) */
	SlotState state;
	gboolean boot_good;
	struct _RaucSlot *parent;
	gchar *mount_point;
	gchar *ext_mount_point;
	RaucSlotStatus *status;
} RaucSlot;

/**
 * Finds a slot given its device path.
 *
 * @param slots a GHashTable containing (gchar, RaucSlot) entries
 * @param device the device path to search for
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *find_slot_by_device(GHashTable *slots, const gchar *device);

/**
 * Finds a slot given its bootname
 *
 * @param slots a GHashTable containing (gchar, RaucSlot) entries
 * @param botname the bootname to search for
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *find_slot_by_bootname(GHashTable *slots, const gchar *bootname);

/**
 * Get string representation of slot state
 *
 * @param slotstate state to turn into string
 *
 * @return string representation of slot state
 */
gchar* slotstate_to_str(SlotState slotstate);

/**
 * Get SlotState from string representation.
 *
 * @param str string representation of state
 *
 * @return corresponding SlotState value
 */
SlotState str_to_slotstate(gchar *str);
