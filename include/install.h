#pragma once

#include <glib.h>

#include "artifacts.h"
#include "bundle.h"
#include "manifest.h"
#include "slot.h"
#include "update_handler.h"

#define R_INSTALL_ERROR r_install_error_quark()
GQuark r_install_error_quark(void);

typedef enum {
	R_INSTALL_ERROR_FAILED,
	R_INSTALL_ERROR_COMPAT_MISMATCH,
	R_INSTALL_ERROR_VERSION_MISMATCH,
	R_INSTALL_ERROR_REJECTED,
	R_INSTALL_ERROR_MARK_BOOTABLE,
	R_INSTALL_ERROR_MARK_NONBOOTABLE,
	R_INSTALL_ERROR_TARGET_GROUP,
	R_INSTALL_ERROR_MOUNTED,
} RInstallError;

typedef struct {
	gchar *name;
	GSourceFunc notify;
	GSourceFunc cleanup;
	GMutex status_mutex;
	GQueue status_messages;
	gint status_result;

	/* install options */
	gboolean ignore_compatible;
	gboolean ignore_version_limit;
	gchar *require_manifest_hash;
	gchar *transaction;
	RaucBundleAccessArgs access_args;

	/* install result flags */
	gboolean updated_slots;
	gboolean updated_artifacts;
} RaucInstallArgs;

/**
 * Update the external mount points of a slot.
 *
 * @param error return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean update_external_mount_points(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Determines the states (ACTIVE | INACTIVE | BOOTED) of the slots specified in
 * system configuration.
 *
 * @param error return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean determine_slot_states(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Obtains boot status information for all relevant slots and stores
 * information into context.
 *
 * @param error return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean determine_boot_states(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns hash table of slot classes for that a potential installation target
 * slot could be determined.
 *
 * @return GHashTable mapping a slotclass (gchar*) to a slot instance
 * (RaucSlot*)
 */
GHashTable* determine_target_install_group(void)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Basic bundle installation procedure.
 *
 * @param args RaucInstallArgs instance
 * @param error return location for a GError
 *
 * @return TRUE if installation succeeded, FALSE if any critical error occurred
 */
gboolean do_install_bundle(RaucInstallArgs *args, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Initialize new RaucInstallArgs structure
 *
 * @return returns newly allocated RaucInstallArgs.
 *         Free with install_args_free.
 */
RaucInstallArgs *install_args_new(void)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Free allocated RaucInstallArgs structure
 *
 * @param args instance to free
 */
void install_args_free(RaucInstallArgs *args);

/**
 * Start a new installer thread.
 *
 * Internally, this uses g_thread_new(), which aborts on error. If we can't
 * start threads, we can't recover anyway.
 *
 * @param args RaucInstallArgs instance
 */
void install_run(RaucInstallArgs *args);

typedef struct {
	RaucImage *image;

	RaucSlot *target_slot;
	img_to_slot_handler slot_handler;

	RArtifactRepo *target_repo;
} RImageInstallPlan;

void r_image_install_plan_free(gpointer value);

/**
 * Builds and returns an array of RImageInstallPlans.
 *
 * Check is performed against target_group.
 *
 * NOTE: This function might be extended to perform further selection on
 * install images later on.
 *
 * @param manifest manifest to obtain install images from
 * @param target_group target group to verify against
 * @param error Return location for a GError
 *
 * @return Returns GPtrArray of RImageInstallPlans
 *         or NULL if an error occurred
 */
GPtrArray* r_install_make_plans(const RaucManifest *manifest, GHashTable *target_group, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Checks if header is supported.
 *
 * @param header Header config name to check
 *
 * @return TRUE if is supported, FALSE otherwise
 */
gboolean r_install_is_supported_http_header(const gchar *header)
G_GNUC_WARN_UNUSED_RESULT;
