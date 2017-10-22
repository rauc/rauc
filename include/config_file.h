#pragma once

#include <glib.h>

#include <checksum.h>
#include "manifest.h"

typedef enum {
	R_CONFIG_ERROR_INVALID_FORMAT,
	R_CONFIG_ERROR_BOOTLOADER,
	R_CONFIG_ERROR_PARENT
} RConfigError;

#define R_CONFIG_ERROR r_config_error_quark()
GQuark r_config_error_quark(void);

/* System configuration */
typedef struct {
	gchar *system_compatible;
	gchar *system_bootloader;
	/* path prefix where rauc may create mount directories */
	gchar *mount_prefix;
	gchar *grubenv_path;
	gboolean activate_installed;
	gchar *keyring_path;

	gchar *autoinstall_path;
	gchar *preinstall_handler;
	gchar *postinstall_handler;

	gchar *systeminfo_handler;

	GHashTable *slots;
} RaucConfig;

typedef enum {
	ST_UNKNOWN = 0,
	ST_ACTIVE = 1,
	ST_INACTIVE = 2,
	ST_BOOTED = 4 | ST_ACTIVE,
} SlotState;

typedef enum {
	R_SLOT_ERROR_NO_CONFIG,
	R_SLOT_ERROR_NO_BOOTSLOT,
	R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
	R_SLOT_ERROR_FAILED
} RSlotError;

#define R_SLOT_ERROR r_slot_error_quark()
GQuark r_slot_error_quark(void);

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

	/** current state of the slot (runtime) */
	SlotState state;
	struct _RaucSlot *parent;
	gchar *mount_point;
	gboolean mount_internal;
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
 * Creates a default rauc system configuration.
 *
 * @param config a location to place the new config
 *
 * @return TRUE if the configuration was sucessfully created. FALSE if there were errors.
 */
gboolean default_config(RaucConfig **config);

/**
 * Finds a config slot given the device path.
 *
 * @param config a RaucConfig
 * @param device the device path to search for
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *find_config_slot_by_device(RaucConfig *config, const gchar *device);

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
gboolean read_slot_status(const gchar *filename, RaucSlotStatus **slotstatus, GError **error);

/**
 * Save slot status file.
 *
 * @param filename name of destination file
 * @param ss the slot status to save
 * @param error a GError, or NULL
 */
gboolean write_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error);

/**
 * Frees the memory allocated by the RaucSlotStatus.
 *
 * @param slotstatus a RaucSlotStatus
 */
void free_slot_status(RaucSlotStatus *slotstatus);

/**
 * Load slot status.
 *
 * This mounts the given slot, reads the status information from its status
 * file and unmounts the slot afterwards.
 *
 * @param dest_slot Slot to load status information for
 * @param slot_state return location for the slot information obtained
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if loading status succeeded, FALSE otherwise
 */
gboolean load_slot_status(RaucSlot *dest_slot, RaucSlotStatus **slot_state, GError **error);

/**
 * Save slot status.
 *
 * This mounts the given slot, writes the status information into its status
 * file and unmounts the slot afterwards.
 *
 * @param dest_slot Slot to write status information for
 * @param mfimage image that was just installed
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if saving status succeeded, FALSE otherwise
 */
gboolean save_slot_status(RaucSlot *dest_slot, RaucImage *mfimage, GError **error);

/**
 * Frees the memory allocated by a RaucSlot
 */
void r_free_slot(gpointer value);

/**
 * Check if slot type is mountable.
 *
 * @param slot slot to check
 *
 * @return TRUE if mountable, otherwise FALSE
 */
gboolean is_slot_mountable(RaucSlot *slot);
