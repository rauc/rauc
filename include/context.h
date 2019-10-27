#pragma once

#include <glib.h>
#include <glib-object.h>
#include <glib/gprintf.h>


#include "config_file.h"
#include "bundle.h"

typedef void (*progress_callback) (gint percentage, const gchar *message,
		gint nesting_depth);

typedef struct {
	/* The bundle currently mounted by RAUC */
	RaucBundle *mounted_bundle;
} RContextInstallationInfo;

typedef struct {
	/* a busy context must not be reconfigured */
	gboolean busy;
	gboolean pending;

	/* system configuration data */
	gchar *configpath;
	RaucConfig *config;

	GList *progress;
	progress_callback progress_callback;

	/* signing data */
	gchar *certpath;
	gchar *keypath;
	gchar *keyringpath;
	gchar *keyringdirectory;
	gchar *signing_keyringpath;
	gchar **intermediatepaths;
	/* optional global mount prefix overwrite */
	gchar *mountprefix;
	gchar *bootslot;

	gchar *system_serial;

	/* optional custom handler extra arguments */
	gchar *handlerextra;
	/* ignore compatible check */
	gboolean ignore_compatible;

	/* for storing installation runtime informations */
	RContextInstallationInfo *install_info;
} RaucContext;

typedef struct {
	/* name identifying progress step */
	gchar *name;
	gchar *description;

	gint substeps_total;
	gint substeps_done;

	gfloat percent_total;
	gfloat percent_done;
	gint last_explicit_percent;
} RaucProgressStep;

gboolean r_context_get_busy(void);
void r_context_set_busy(gboolean busy);

/**
 * Call at the beginning of a relevant code block. Provides progress
 * information via DBus when rauc service is running.
 *
 * @param name identifying the step
 * @param description that is emitted via DBus on begin/end
 * @param sub_steps number of direct sub steps contained in this step
 */
void r_context_begin_step(const gchar *name, const gchar *description,
		gint sub_steps);

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
 * Sets explicit percentage for the given step. This is useful for long lasting
 * operations, e.g. file copying.
 *
 * @param name identifying the step
 * @param percentage explicit step percentage
 */
void r_context_set_step_percentage(const gchar *name, gint percentage);

/**
 * Frees the memory allocated by the RaucProgressStep.
 *
 * @param step a RaucProgressStep to free
 */
void r_context_free_progress_step(RaucProgressStep *step);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucProgressStep, r_context_free_progress_step);

void r_context_register_progress_callback(progress_callback progress_cb);

RaucContext *r_context_conf(void);
const RaucContext *r_context(void);
void r_context_clean(void);