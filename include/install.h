#pragma once

#include <glib.h>

#include "manifest.h"

#define R_INSTALL_ERROR r_install_error_quark ()
GQuark r_install_error_quark (void);

typedef enum {
	R_INSTALL_ERROR_FAILED,
	R_INSTALL_ERROR_NOSRC,
	R_INSTALL_ERROR_NODST,
	R_INSTALL_ERROR_COMPAT_MISMATCH,
	R_INSTALL_ERROR_REJECTED,
	R_INSTALL_ERROR_MARK_BOOTABLE,
	R_INSTALL_ERROR_MARK_NONBOOTABLE,
	R_INSTALL_ERROR_TARGET_GROUP,
	R_INSTALL_ERROR_DOWNLOAD_MF,
	R_INSTALL_ERROR_HANDLER,
	R_INSTALL_ERROR_NO_SUPPORTED,
	R_INSTALL_ERROR_MOUNTED
} RInstallError;

typedef struct {
	gchar *name;
	GSourceFunc notify;
	GSourceFunc cleanup;
	GMutex status_mutex;
	GQueue status_messages;
	gint status_result;
} RaucInstallArgs;

/**
 * Determines the states (ACTIVE | INACTIVE | BOOTED) of the slots specified in
 * system configuration.
 *
 * @param error return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean determine_slot_states(GError **error);

/**
 * Returns hash table of slot classes for that a potential installation target
 * slot could be determined.
 *
 * @param manifest manifest to use
 *
 * @return GHashTable mapping a slotclass (gchar*) to a slot instance
 * (RaucSlot*)
 */
GHashTable* determine_target_install_group(RaucManifest *manifest);

/**
 * Basic bundle installation procedure.
 *
 * @param args RaucInstallArgs instance
 * @param error return location for a GError
 *
 * @return TRUE if installation succeeded, FALSE if any critical error occurred
 */
gboolean do_install_bundle(RaucInstallArgs *args, GError **error);

/**
 * Basic network installation procedure.
 *
 * NOTE: The network mode of RAUC is deprecated and will be replaced by some
 * other mechanism in the near future. Do not rely on it for new designs.
 *
 * @param url URL to manifest to install
 * @param error return location for a GError
 *
 * @return TRUE if installation succeeded, FALSE if any critical error occurred
 */
gboolean do_install_network(const gchar *url, GError **error);

/**
 * Initialize new RaucInstallArgs structure
 *
 * @return returns newly allocated RaucInstallArgs.
 *         Free with install_args_free.
 */
RaucInstallArgs *install_args_new(void);

/**
 * Free allocated RaucInstallArgs structure
 *
 * @param args instance to free
 */
void install_args_free(RaucInstallArgs *args);

/**
 * Start a new installer thread.
 *
 * @param args RaucInstallArgs instance
 *
 * @return TRUE if starting thread succeeded, otherwise FALSE
 */
gboolean install_run(RaucInstallArgs *args);
