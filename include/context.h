#pragma once

#include <glib.h>
#include <glib-object.h>
#include <glib/gprintf.h>

#include "config_file.h"
#include "status_file.h"
#include "bundle.h"

typedef void (*progress_callback) (gint percentage, const gchar *message,
		gint nesting_depth);

typedef struct {
	/* The bundle currently mounted by RAUC */
	RaucBundle *mounted_bundle;
} RContextInstallationInfo;

typedef enum {
	R_CONTEXT_CONFIG_MODE_NONE, /* use default config values */
	R_CONTEXT_CONFIG_MODE_AUTO, /* load config file if it exists */
	R_CONTEXT_CONFIG_MODE_REQUIRED, /* require config file */
} RContextConfigMode;

typedef struct {
	gchar *section;
	gchar *name;
	gchar *value;
} ConfigFileOverride;

typedef struct {
	/* a busy context must not be reconfigured */
	gboolean busy;
	gboolean pending;

	/* system configuration data */
	RContextConfigMode configmode;
	gchar *configpath;
	GList *configoverride;
	RaucConfig *config;

	/* system status (not available when using per-slot status file) */
	RSystemStatus *system_status;

	GList *progress; /* List of RaucProgressStep used as sub step stack (most recent first) */
	progress_callback progress_callback;

	/* signing data */
	gchar *certpath;
	gchar *keypath;
	gchar *keyringpath;
	gchar *keyringdirectory;
	gchar *signing_keyringpath;
	gchar *encryption_key;
	gchar *mksquashfs_args;
	gchar *casync_args;
	gchar **recipients;
	gchar **intermediatepaths;
	/* optional global mount prefix overwrite */
	gchar *mountprefix;
	gchar *bootslot;
	gchar *boot_id;
	gchar *machine_id;

	gchar *system_serial;
	gchar *system_version;
	GHashTable *system_info; /* key/values of system information */

	/* optional custom handler extra arguments */
	gchar *handlerextra;

	/* for storing installation runtime information */
	RContextInstallationInfo *install_info;

	/* mock data for testing, zero during normal usage */
	struct {
		/* mock contents of /proc/cmdline */
		const gchar *proc_cmdline;
		gint64 polling_speedup;
	} mock;
} RaucContext;

typedef struct {
	/* name identifying progress step */
	gchar *name;
	gchar *description;
	gint weight;

	gint substeps_total;
	gint substeps_done;

	gfloat percent_total;
	gfloat percent_done;
	gint last_explicit_percent;
} RaucProgressStep;

/**
 * Starts a new progress step at the current nesting level.
 *
 * The progress step needs to be completed by r_context_end_step() called at
 * the same level.
 *
 * Should be called at the beginning of a code block relevant for progress
 * information.
 * Provides progress information via DBus when rauc service is running.
 *
 * @param name Internal identifier for the step.
 * @param description that is emitted via DBus on begin/end
 * @param sub_steps number of direct sub steps contained in this step, or 0 for no sub step.
 */
void r_context_begin_step(const gchar *name, const gchar *description,
		gint sub_steps);

/**
 * Call at the beginning of a relevant code block. Provides progress
 * information via DBus when rauc service is running.
 *
 * This is the weighted variant of r_context_begin_step() which allows a step
 * to span multiple parent steps
 *
 * @param name identifying the step
 * @param description that is emitted via DBus on begin/end
 * @param sub_steps number of direct sub steps contained in this step
 * @param weight Parent steps to span
 */
void r_context_begin_step_weighted(const gchar *name, const gchar *description,
		gint substeps, gint weight);

/**
 * Call at the beginning of a relevant code block. Provides progress
 * information via DBus when rauc service is running.
 *
 * Same as r_context_begin_step() but allows printf-like format strings.
 *
 * @param name identifying the step
 * @param sub_steps number of direct sub steps contained in this step
 * @param description that is emitted via DBus on begin/end.
 *   A printf-like format string.
 */
void r_context_begin_step_formatted(const gchar *name, gint substeps, const gchar *description, ...)
__attribute__((__format__(__printf__, 3, 4)));

void r_context_begin_step_weighted_formatted(const gchar *name, gint substeps, gint weight, const gchar *description, ...)
__attribute__((__format__(__printf__, 4, 5)));

/**
 * Call at the end of a relevant code block. Percentage calculation is done
 * automatically if not set explicitly.
 * If the step did not complete successfully the number of nested substeps
 * does not need to match the number of substeps completed.
 *
 * @param name identifying the step
 * @param success true if step was executed successfully otherwise false
 */
void r_context_end_step(const gchar *name, gboolean success);

/**
 * Sets explicit percentage for the given step.
 *
 * This is useful for longer operations, e.g. file copying.
 *
 * @param name identifying the step. Must be a step with no explicit substeps.
 * @param percentage explicit step percentage
 */
void r_context_set_step_percentage(const gchar *name, gint percentage);

/**
 * Increases step percentage by one.
 *
 * @param name identifying the step. Must be a step with no explicit substeps.
 */
void r_context_inc_step_percentage(const gchar *name);

/**
 * Frees the memory allocated by the RaucProgressStep.
 *
 * @param step a RaucProgressStep to free
 */
void r_context_free_progress_step(RaucProgressStep *step);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucProgressStep, r_context_free_progress_step);

/**
 * Callback to register for progress updates.
 *
 * @param progress_cb Callback method of type 'progress_callback'
 */
void r_context_register_progress_callback(progress_callback progress_cb);

/**
 * Return if context is marked 'busy'.
 *
 * @return TRUE if context is 'busy', otherwise FALSE.
 */
gboolean r_context_get_busy(void)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Explicitly mark the context busy to prevent concurrent access on context
 * during installation.
 *
 * Note this will fail if context is 'busy' already.
 *
 * @param[in] busy Whether to set 'busy' (TRUE) or 'not busy' (FALSE)
 */
void r_context_set_busy(gboolean busy);

/**
 * Returns a non-const instance of context object, to allow changing variables.
 *
 * Sets up context object if not existing, yet and initializes APIs.
 *
 * Leaves the context object with 'pending' flag set.
 *
 * @param (non-const) instance of context object
 */
RaucContext *r_context_conf(void);

/**
 * Returns read-only (const) reference to context object.
 *
 * Use this to access context information regularly.
 *
 * If the context has 'pending' flag set, this configures the context and
 * removes the 'pending' flag from the context object.
 *
 * @return read-only (const) reference to global context object
 */
const RaucContext *r_context(void);

/**
 * Sets up global context.
 *
 * Removes 'pending' flag from the context object.
 *
 * * Loads RAUC configuration file (system.conf)
 * * Reads basic system information like variant, system info, etc. (if
 *   configured)
 * * Reads 'bootname' from kernel commandline
 * * Overrides config file values by commandline argument values where required.
 *
 * Note: Must not be called when context is 'busy'.
 *
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if context configuration succeeded, otherwise FALSE
 */
gboolean r_context_configure(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Cleans up provided RContextInstallationInfo.
 *
 * @param[in] info RContextInstallationInfo to free
 */
void r_context_install_info_free(RContextInstallationInfo *info);

/**
 * Cleans up a global context created with r_context_conf().
 *
 * Will do nothing if context was not created.
 */
void r_context_clean(void);
