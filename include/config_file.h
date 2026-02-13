#pragma once

#include <glib.h>

#include "checksum.h"
#include "manifest.h"
#include "slot.h"

/* Default maximum downloadable bundle size (8 MiB) */
#define DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE 8*1024*1024
/* Default maximum signature/CMS size (64 KiB) */
#define DEFAULT_MAX_BUNDLE_SIGNATURE_SIZE 64*1024

typedef enum {
	R_CONFIG_ERROR_INVALID_FORMAT,
	R_CONFIG_ERROR_BOOTLOADER,
	R_CONFIG_ERROR_PARENT,
	R_CONFIG_ERROR_PARENT_LOOP,
	R_CONFIG_ERROR_MAX_BUNDLE_DOWNLOAD_SIZE,
	R_CONFIG_ERROR_MAX_BUNDLE_SIGNATURE_SIZE,
	R_CONFIG_ERROR_CHILD_HAS_BOOTNAME,
	R_CONFIG_ERROR_DUPLICATE_BOOTNAME,
	R_CONFIG_ERROR_DUPLICATE_CLASS,
	R_CONFIG_ERROR_SLOT_TYPE,
	R_CONFIG_ERROR_INVALID_DEVICE,
	R_CONFIG_ERROR_DATA_DIRECTORY,
	R_CONFIG_ERROR_ARTIFACT_REPO_TYPE,
	R_CONFIG_ERROR_EMPTY_FILE,
	R_CONFIG_ERROR_MISSING_OPTION,
	R_CONFIG_ERROR_POLLING,
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
	gchar *system_min_bundle_version;
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
	/** prevent fallback after successfully booting into primary slot */
	gboolean prevent_late_fallback;
	/* maximum filesize to download in bytes */
	guint64 max_bundle_download_size;
	/* maximum signature/CMS size in bytes */
	guint64 max_bundle_signature_size;
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
	gchar **keyring_allowed_signer_cns;
	gboolean use_bundle_signing_time;
	/* bit mask for allowed formats */
	guint bundle_formats_mask;
	/* enable complete read before mount */
	gboolean perform_pre_check;

	gchar *autoinstall_path;
	gchar *preinstall_handler;
	gchar *postinstall_handler;

	gchar *systeminfo_handler;

	gchar **enabled_headers; /* standard HTTP headers to send */

	/* streaming */
	gchar *streaming_sandbox_user;
	gchar *streaming_tls_cert;
	gchar *streaming_tls_key;
	gchar *streaming_tls_ca;

	/* encryption */
	gchar *encryption_key;
	gchar *encryption_cert;

	/* logging */
	GList *loggers;

	/* polling */
	gchar *polling_url;
	gchar **polling_inhibit_files;
	gchar **polling_candidate_criteria;
	gchar **polling_install_criteria;
	gchar **polling_reboot_criteria;
	gint64 polling_interval_ms;
	gint64 polling_max_interval_ms;
	gchar *polling_reboot_cmd;

	GHashTable *slots;
	/* flag to ensure slot states were determined */
	gboolean slot_states_determined;
	gchar *file_checksum;

	GHashTable *artifact_repos;
} RaucConfig;

typedef enum {
	R_SLOT_ERROR_NO_CONFIG,
	R_SLOT_ERROR_NO_BOOTSLOT,
	R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
	R_SLOT_ERROR_FAILED,
} RSlotError;

#define R_SLOT_ERROR r_slot_error_quark()
GQuark r_slot_error_quark(void);

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
 * Creates a default RAUC system configuration for usage on the host.
 *
 * As this processes config overrides from the command line, errors can be
 * returned.
 *
 * @param config a location to place the new config
 * @param error a GError, or NULL
 *
 * @return TRUE if the configuration was successfully initialized. FALSE if there were errors.
 */
gboolean default_config(RaucConfig **config, GError **error);

/**
 * Check if a configuration satisfies the requirements for on-target use.
 *
 * @param config pointer to the config to check
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean check_config_target(const RaucConfig *config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
 * Checks if the current file checksum of the system config matches the one currently loaded.
 *
 * Prints a warning if the checksums of the config file does not match the one
 * recorded during config parsing.
 */
void r_config_file_modified_check(void);
