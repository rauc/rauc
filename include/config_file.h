#pragma once

#include <glib.h>

#include <checksum.h>

/* System configuration */
typedef struct {
	gchar *system_compatible;
	gchar *system_bootloader;
	/* path prefix where rauc may create mount directories */
	gchar *mount_prefix;
	gchar *grubenv_path;
	gchar *keyring_path;

	GHashTable *slots;
} RaucConfig;

typedef enum {
	ST_UNKNOWN,
	ST_ACTIVE,
	ST_INACTIVE
} SlotState;

typedef struct _RaucSlot {
	/** name of the slot. A glib intern string. */
	const gchar *name;
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
	/** current state of the slot (runtime) */
	SlotState state;
	struct _RaucSlot *parent;
} RaucSlot;

typedef struct {
} RaucSlotGroup;

typedef struct {
	gchar *status;
	RaucChecksum checksum;
} RaucSlotStatus;

/**
 * Loads rauc system configuration from file.
 *
 * @param filename file to load
 * @param config a location to place the loaded config
 * @param error a GError, or NULL
 *
 * @return TRUE if the configuration was sucessfully loaded. FALSE if there were errors.
 */
gboolean load_config(const gchar *filename, RaucConfig **config, GError **error);

/**
 * Frees the memory allocated by the RaucConfig.
 *
 * @param config a RaucConfig
 */
void free_config(RaucConfig *config);

/**
 * Load slot status file.
 *
 * @param filename file to load
 * @param slotstatus a location to place the slot status
 * @param error a GError, or NULL
 *
 * @return TRUE if the slot status was sucessfully loaded. FALSE if there were errors.
 */
gboolean load_slot_status(const gchar *filename, RaucSlotStatus **slotstatus, GError **error);

/**
 * Save slot status file.
 *
 * @param filename name of destination file
 * @param ss the slot status to save
 * @param error a GError, or NULL
 */
gboolean save_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error);

/**
 * Frees the memory allocated by the RaucSlotStatus.
 *
 * @param slotstatus a RaucSlotStatus
 */
void free_slot_status(RaucSlotStatus *slotstatus);
