#pragma once

#include <glib.h>

#include <checksum.h>
#include "manifest.h"
#include "slot.h"

/* Default maximum downloadable bundle size (8 MiB) */
#define DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE 8*1024*1024

typedef enum {
	R_CONFIG_ERROR_INVALID_FORMAT,
	R_CONFIG_ERROR_BOOTLOADER,
	R_CONFIG_ERROR_PARENT,
	R_CONFIG_ERROR_PARENT_LOOP,
	R_CONFIG_ERROR_MAX_BUNDLE_DOWNLOAD_SIZE,
	R_CONFIG_ERROR_CHILD_HAS_BOOTNAME,
	R_CONFIG_ERROR_DUPLICATE_BOOTNAME,
	R_CONFIG_ERROR_SLOT_TYPE,
	R_CONFIG_ERROR_INVALID_DEVICE,
	R_CONFIG_ERROR_DATA_DIRECTORY,
} RConfigError;

#define R_CONFIG_ERROR r_config_error_quark()
GQuark r_config_error_quark(void);

typedef enum {
	R_CONFIG_SYS_VARIANT_NONE,
	R_CONFIG_SYS_VARIANT_DTB,
	R_CONFIG_SYS_VARIANT_FILE,
	R_CONFIG_SYS_VARIANT_NAME,
} RConfigSysVariant;

/* System configuration */
typedef struct {
	gchar *system_compatible;
	RConfigSysVariant system_variant_type;
	gchar *system_variant;
	gchar *system_bootloader;
	gchar *system_bb_statename;
	gchar *system_bb_dtbpath;
	gint boot_default_attempts;
	gint boot_attempts_primary;
	gchar *grubenv_path;
	gchar *custom_bootloader_backend;
	gboolean efi_use_bootnext;
	/* maximum filesize to download in bytes */
	guint64 max_bundle_download_size;
	/* path prefix where rauc may create mount directories */
	gchar *mount_prefix;
	gchar *store_path;
	gchar *tmp_path;
	gchar *casync_install_args;
	gboolean use_desync;
	gboolean activate_installed;
	gchar *data_directory;
	gchar *statusfile_path;
	gchar *keyring_path;
	gchar *keyring_directory;
	gboolean keyring_allow_partial_chain;
	gboolean keyring_check_crl;
	gchar *keyring_check_purpose;
	gboolean use_bundle_signing_time;
	/* bit mask for allowed formats */
	guint bundle_formats_mask;

	gchar *autoinstall_path;
	gchar *preinstall_handler;
	gchar *postinstall_handler;

	gchar *systeminfo_handler;

	/* streaming */
	gchar *streaming_sandbox_user;
	gchar *streaming_tls_cert;
	gchar *streaming_tls_key;
	gchar *streaming_tls_ca;

	/* encryption */
	gchar *encryption_key;
	gchar *encryption_cert;

	GHashTable *slots;
} RaucConfig;

typedef enum {
	R_SLOT_ERROR_NO_CONFIG,
	R_SLOT_ERROR_NO_BOOTSLOT,
	R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
	R_SLOT_ERROR_FAILED,
} RSlotError;

#define R_SLOT_ERROR r_slot_error_quark()
GQuark r_slot_error_quark(void);

typedef struct {
} RaucSlotGroup;

/**
 * Parses a bundle format list into a mask.
 *
 * @param mask pointer to the mask to be updated
 * @param config space separated list of formats (prefixed with +/- for modification)
 * @param error a GError, or NULL
 *
 * @return TRUE if the bundle format was successfully parsed. FALSE if there were errors.
 */
gboolean parse_bundle_formats(guint *mask, const gchar *config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Loads rauc system configuration from file.
 *
 * @param filename file to load
 * @param config a location to place the loaded config
 * @param error a GError, or NULL
 *
 * @return TRUE if the configuration was successfully loaded. FALSE if there were errors.
 */
gboolean load_config(const gchar *filename, RaucConfig **config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a default rauc system configuration.
 *
 * @param config a location to place the new config
 */
void default_config(RaucConfig **config);

/**
 * Finds a config slot given the device path.
 *
 * @param config a RaucConfig
 * @param device the device path to search for
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *find_config_slot_by_device(RaucConfig *config, const gchar *device)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Finds a config slot given its name.
 *
 * @param config a RaucConfig
 * @param name the slot name to search for
 *
 * @note Current layout of rauc data structures makes this the fastest way to
 * find a slot.
 *
 * @return a RaucSlot pointer or NULL
 */
RaucSlot *find_config_slot_by_name(RaucConfig *config, const gchar *name)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Frees the memory allocated by the RaucConfig.
 *
 * @param config a RaucConfig
 */
void free_config(RaucConfig *config);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucConfig, free_config);

/**
 * Load a single slot status from a file into a pre-allocated status structure.
 * If a problem occurs this structure is left unmodified.
 *
 * @param filename file to load
 * @param slotstatus pointer to the pre-allocated structure going to store the slot status
 * @param error a GError, or NULL
 *
 * @return TRUE if the slot status was successfully loaded. FALSE if there were errors.
 */
gboolean read_slot_status(const gchar *filename, RaucSlotStatus *slotstatus, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Save slot status file.
 *
 * @param filename name of destination file
 * @param ss the slot status to save
 * @param error a GError, or NULL
 */
gboolean write_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Load slot status.
 *
 * Takes care to fill in slot status information into the designated component
 * of the slot data structure. If the user configured a global status file in
 * the system.conf they are read from this file. Otherwise mount the given slot,
 * read the status information from its local status file and unmount the slot
 * afterwards. If a problem occurs the stored slot status consists of default
 * values. Do nothing if the status information have already been loaded before.
 *
 * @param dest_slot Slot to load status information for
 */
void load_slot_status(RaucSlot *dest_slot);

/**
 * Save slot status.
 *
 * This persists the status information from the designated component of the
 * given slot data structure. If the user configured a global status file in the
 * system.conf they are written to this file. Otherwise mount the given slot,
 * transfer the status information to the local status file and unmount the slot
 * afterwards.
 *
 * @param dest_slot Slot to write status information for
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if slot is not mountable or saving status succeeded, FALSE otherwise
 */
gboolean save_slot_status(RaucSlot *dest_slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
