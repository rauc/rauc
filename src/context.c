#include <errno.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <string.h>

#include "bootchooser.h"
#include "bootloaders/barebox.h"
#include "config_file.h"
#include "context.h"
#include "event_log.h"
#include "status_file.h"
#include "network.h"
#include "install.h"
#include "signature.h"
#include "utils.h"

RaucContext *context = NULL;
gboolean context_configuring = FALSE;

static gchar* get_machine_id(void)
{
	gchar *contents = NULL;
	g_autoptr(GError) ierror = NULL;

	if (!g_file_get_contents("/etc/machine-id", &contents, NULL, &ierror)) {
		g_info("Failed to get machine-id: %s", ierror->message);
		return NULL;
	}

	/* file contains newline, modify in-place */
	g_strchomp(contents);
	if (!contents[0]) {
		g_info("Failed to get machine-id: empty file");
		return NULL;
	}

	return contents;
}

static gchar* get_boot_id(void)
{
	gchar *contents = NULL;
	g_autoptr(GError) ierror = NULL;

	if (!g_file_get_contents("/proc/sys/kernel/random/boot_id", &contents, NULL, &ierror)) {
		g_warning("Failed to get boot_id: %s", ierror->message);
		return NULL;
	}

	/* file contains newline, modify in-place */
	return g_strchomp(contents);
}

static gchar *get_cmdline(void)
{
	gchar *contents = NULL;
	g_autoptr(GError) ierror = NULL;

	if (context->mock.proc_cmdline)
		return g_strdup(context->mock.proc_cmdline);

	if (!g_file_get_contents("/proc/cmdline", &contents, NULL, &ierror)) {
		g_warning("Failed to get kernel cmdline: %s", ierror->message);
		return NULL;
	}

	return contents;
}

static gchar* get_cmdline_bootname_explicit(const gchar *cmdline)
{
	if (!cmdline)
		return NULL;

	gchar *bootname = NULL;

	if (strstr(cmdline, "rauc.external") != NULL) {
		g_message("Detected explicit external boot, ignoring missing active slot");
		return g_strdup("_external_");
	}

	if (strstr(cmdline, "root=/dev/nfs") != NULL) {
		g_message("Detected nfs boot, ignoring missing active slot");
		return g_strdup("_external_");
	}

	bootname = r_regex_match_simple("rauc\\.slot=(\\S+)", cmdline);
	if (bootname)
		return bootname;

	return NULL;
}

static gchar* get_cmdline_bootname_root(const gchar *cmdline)
{
	if (!cmdline)
		return NULL;

	g_autofree gchar *realdev = NULL;
	gchar *bootname = NULL;

	bootname = r_regex_match_simple("root=(\\S+)", cmdline);
	if (!bootname)
		bootname = r_regex_match_simple("systemd\\.verity_root_data=(\\S+)", cmdline);

	if (!bootname)
		return NULL;

	if (strncmp(bootname, "PARTLABEL=", 10) == 0) {
		gchar *partlabelpath = g_build_filename(
				"/dev/disk/by-partlabel/",
				&bootname[10],
				NULL);
		if (partlabelpath) {
			g_free((gchar*) bootname);
			bootname = partlabelpath;
		}
	}

	if (strncmp(bootname, "PARTUUID=", 9) == 0) {
		gchar *partuuidpath = g_build_filename(
				"/dev/disk/by-partuuid/",
				&bootname[9],
				NULL);
		if (partuuidpath) {
			g_free((gchar*) bootname);
			bootname = partuuidpath;
		}
	}

	if (strncmp(bootname, "UUID=", 5) == 0) {
		gchar *uuidpath = g_build_filename(
				"/dev/disk/by-uuid/",
				&bootname[5],
				NULL);
		if (uuidpath) {
			g_free((gchar*) bootname);
			bootname = uuidpath;
		}
	}

	realdev = r_realpath(bootname);
	if (realdev == NULL) {
		g_message("Failed to resolve realpath for '%s'", bootname);
		return bootname;
	}

	if (g_strcmp0(realdev, bootname) != 0) {
		g_debug("Resolved bootname %s to %s", bootname, realdev);
		r_replace_strdup(&bootname, realdev);
	}

	return bootname;
}

static gchar* get_bootname(void)
{
	g_autofree gchar *cmdline = get_cmdline();
	gchar *bootname = NULL;
	GError *ierror = NULL;

	bootname = get_cmdline_bootname_explicit(cmdline);
	if (bootname)
		return bootname;

	bootname = r_boot_get_current_bootname(context->config, cmdline, &ierror);
	if (ierror) {
		g_message("Failed to get bootname: %s", ierror->message);
		g_clear_error(&ierror);
	}
	if (bootname)
		return bootname;

	bootname = get_cmdline_bootname_root(cmdline);

	return bootname;
}

/**
 * Launches a handler and obtains variables from output by looking for
 * 'RAUC_<SOMETHING>=value' lines to put them into a key/value store (GHashTable).
 *
 * @param handler_name name / path of handler script to start
 * @param[out] variables Return location for a GHashTable table with obtained key/value-pairs
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE on success, otherwise FALSE
 */
static gboolean launch_and_wait_variables_handler(gchar *handler_name, GHashTable **variables, GError **error)
{
	g_autoptr(GSubprocessLauncher) handlelaunch = NULL;
	g_autoptr(GSubprocess) handleproc = NULL;
	GError *ierror = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	GInputStream *instream;
	g_autoptr(GHashTable) vars = NULL;
	gchar* outline;

	g_return_val_if_fail(handler_name, FALSE);
	g_return_val_if_fail(variables && *variables == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch,
			&ierror, handler_name,
			NULL,
			NULL);

	if (!handleproc) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	instream = g_subprocess_get_stdout_pipe(handleproc);
	datainstream = g_data_input_stream_new(instream);

	vars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	do {
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline)
			continue;

		if (g_str_has_prefix(outline, "RAUC_")) {
			g_auto(GStrv) split = g_strsplit(outline, "=", 2);

			if (g_strv_length(split) != 2) {
				g_message("Failed to convert '%s' line to variable", outline);
				g_free(outline);
				continue;
			}

			g_hash_table_insert(vars, g_strdup(split[0]), g_strdup(split[1]));
		}

		g_free(outline);
	} while (outline);

	if (!g_subprocess_wait_check(handleproc, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	*variables = g_steal_pointer(&vars);

	return TRUE;
}

static gchar* get_system_dtb_compatible(GError **error)
{
	gchar *contents = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!g_file_get_contents("/sys/firmware/devicetree/base/compatible", &contents, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_assert_nonnull(contents); /* fixes scan-build false positive */

	return contents;
}

static gchar* get_variant_from_file(const gchar* filename, GError **error)
{
	gchar *contents = NULL;
	GError *ierror = NULL;
	gsize length;

	g_return_val_if_fail(filename, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!g_file_get_contents(filename, &contents, &length, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_assert_nonnull(contents); /* fixes scan-build false positive */

	/*
	 * We'll discard surrounding whitespace later anyway, but as it's
	 * customary for UNIX files to have a trailing new line, we chomp
	 * it off here to avoid a runtime warning.
	 */
	if (length && contents[length - 1] == '\n')
		contents[length - 1] = '\0';

	return contents;
}

static GHashTable *get_system_info_from_handler(GError **error)
{
	g_autoptr(GHashTable) vars = NULL;
	GError *ierror = NULL;
	GHashTableIter iter;
	gchar *key = NULL;
	gchar *value = NULL;

	if (!g_file_test(context->config->systeminfo_handler, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT, "System info handler script/binary '%s' not found.", context->config->systeminfo_handler);
		return NULL;
	}

	g_message("Getting Systeminfo: %s", context->config->systeminfo_handler);
	if (!launch_and_wait_variables_handler(context->config->systeminfo_handler, &vars, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Failed to read system-info variables: ");
		return NULL;
	}

	g_hash_table_iter_init(&iter, vars);
	while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
		/* handle special-purpose variables */
		if (g_strcmp0(key, "RAUC_SYSTEM_SERIAL") == 0) {
			r_replace_strdup(&context->system_serial, value);
		} else if (g_strcmp0(key, "RAUC_SYSTEM_VARIANT") == 0) {
			/* set variant (overrides possible previous value) */
			r_replace_strdup(&context->config->system_variant, value);
		} else if (g_strcmp0(key, "RAUC_SYSTEM_VERSION") == 0) {
			r_replace_strdup(&context->system_version, value);
		}
	}

	return g_steal_pointer(&vars);
}

/**
 * Configures options that are only relevant when running as update service on
 * the target device.
 */
static gboolean r_context_configure_target(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (context->config->data_directory) {
		if (g_mkdir_with_parents(context->config->data_directory, 0700) != 0) {
			int err = errno;
			g_set_error(
					error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to create data directory '%s': %s",
					context->config->data_directory,
					g_strerror(err));
			return FALSE;
		}
	}

	/* load system status and slot status if central status file is available */
	if (g_strcmp0(context->config->statusfile_path, "per-slot") != 0) {
		g_clear_pointer(&context->system_status, r_system_status_free);
		context->system_status = g_new0(RSystemStatus, 1);
		if (!r_system_status_load(context->config->statusfile_path, context->system_status, &ierror)) {
			g_message("Failed to load system status: %s", ierror->message);
			g_clear_error(&ierror);
		}

		r_slot_status_load_globally(context->config->statusfile_path, context->config->slots);
	}

	/* set up logging */
	for (GList *l = context->config->loggers; l != NULL; l = l->next) {
		REventLogger* logger = l->data;

		r_event_log_setup_logger(logger);
	}

	if (context->config->system_variant_type == R_CONFIG_SYS_VARIANT_DTB) {
		gchar *compatible = get_system_dtb_compatible(&ierror);
		if (!compatible) {
			g_warning("Failed to read dtb compatible: %s", ierror->message);
			g_clear_error(&ierror);
		}
		g_free(context->config->system_variant);
		context->config->system_variant = compatible;
	} else if (context->config->system_variant_type == R_CONFIG_SYS_VARIANT_FILE) {
		gchar *variant = get_variant_from_file(context->config->system_variant, &ierror);
		if (!variant) {
			g_warning("Failed to read system variant from file: %s", ierror->message);
			g_clear_error(&ierror);
		}
		g_free(context->config->system_variant);
		context->config->system_variant = variant;
	}

	g_clear_pointer(&context->system_info, g_hash_table_destroy);
	if (context->config->systeminfo_handler) {
		context->system_info = get_system_info_from_handler(&ierror);
		if (!context->system_info) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	} else {
		/* Ensure the hash table is always created so that we do not need to check this later */
		context->system_info = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}

	if (r_whitespace_removed(context->config->system_variant))
		g_warning("Ignoring surrounding whitespace in system variant: %s", context->config->system_variant);

	if (context->bootslot == NULL) {
		context->bootslot = get_bootname();
	}

	/* If prevent_late_fallback=lock-counter, it needs a variable available in barebox-state.
	 * We can not use r_boot_get_lock_counter here, as it uses r_context() to get the variable
	 * and would cause a recursion. But we can access context directly here. */
	if (context->config->prevent_late_fallback == R_CONFIG_FALLBACK_LOCK_COUNTER) {
		if (g_strcmp0(context->config->system_bootloader, "barebox") == 0) {
			if (context->config->system_bb_statename || context->config->system_bb_dtbpath) {
				g_set_error_literal(error, R_BOOTCHOOSER_ERROR,
						R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
						"Providing custom name, state or path not yet supported for locking");
				return FALSE;
			}
			gboolean locked = FALSE;
			if (!r_barebox_get_lock_counter(&locked, &ierror)) {
				/* If we would throw an error here, RAUC would fail and it might not be possible to execute updates anymore. */
				g_warning("Failed to read barebox lock counter: %s", ierror->message);
				g_clear_error(&ierror);
			}
		} else {
			g_set_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
					"prevent-late-fallback is set to 'lock-counter', but not supported by selected bootloader: %s",
					context->config->system_bootloader);
			return FALSE;
		}
	}

	g_clear_pointer(&context->boot_id, g_free);
	g_clear_pointer(&context->machine_id, g_free);

	context->boot_id = get_boot_id();
	if (context->boot_id)
		g_debug("Obtained system boot ID: '%s'", context->boot_id);
	context->machine_id = get_machine_id();
	if (context->machine_id)
		g_debug("Obtained system machine ID: '%s'", context->machine_id);

	return TRUE;
}

static gboolean load_config_verbose(const char *configpath, GError **error)
{
	GError *ierror = NULL;

	if (load_config(configpath, &context->config, &ierror)) {
		g_message("Using system config file %s", configpath);
		if (!context->configpath)
			context->configpath = g_strdup(configpath);
		return TRUE;
	}

	g_propagate_prefixed_error(error, ierror, "Failed to load system config (%s): ", configpath);
	return FALSE;
}

static const gchar *const search_paths[] = {
	"/etc/rauc/system.conf",
	"/run/rauc/system.conf",
	"/usr/lib/rauc/system.conf",
	NULL,
};

gboolean r_context_configure(GError **error)
{
	GError *ierror = NULL;
	RContextConfigMode configmode;
	const gchar *configpath = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_nonnull(context);
	g_assert_false(context->busy);

	g_clear_pointer(&context->config, free_config);
	configmode = context->configmode;
	if (context->configpath) {
		/* explicitly set on the command line */
		configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
		configpath = context->configpath;
	} else if (configmode != R_CONTEXT_CONFIG_MODE_NONE) {
		for (const gchar *const *path = search_paths; *path; path++) {
			GStatBuf st_buf;

			configpath = *path;
			if (g_stat(configpath, &st_buf) == 0)
				break;
		}
	}
	switch (configmode) {
		case R_CONTEXT_CONFIG_MODE_REQUIRED:
			if (load_config_verbose(configpath, error))
				break;
			return FALSE;
		case R_CONTEXT_CONFIG_MODE_AUTO:
			if (load_config_verbose(configpath, &ierror))
				break;
			if (ierror->domain != G_FILE_ERROR &&
			    !g_error_matches(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_EMPTY_FILE)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}

			g_clear_error(&ierror);
		/* This is a hack as we cannot get rid of config easily */
		/* Fallthrough */
		case R_CONTEXT_CONFIG_MODE_NONE:
			if (!default_config(&context->config, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
			break;
		default:
			g_error("invalid context config mode %d", configmode);
			break;
	}

	if (context->mountprefix) {
		r_replace_strdup(&context->config->mount_prefix, context->mountprefix);
	}

	if (context->keyringpath) {
		r_replace_strdup(&context->config->keyring_path, context->keyringpath);
	}

	if (context->keyringdirectory) {
		r_replace_strdup(&context->config->keyring_directory, context->keyringdirectory);
	}

	if (context->encryption_key) {
		r_replace_strdup(&context->config->encryption_key, context->encryption_key);
	}

	/* When no context is required, we can safely assume that we do not
	 * operate on the target but are used as a (host) tool.
	 * In this case, skip all the necessary target-related context setup steps
	 */
	if (configmode != R_CONTEXT_CONFIG_MODE_REQUIRED) {
		context->pending = FALSE;

		return TRUE;
	}

	if (!r_context_configure_target(error)) {
		return FALSE;
	}

	context->pending = FALSE;

	return TRUE;
}

gboolean r_context_get_busy(void)
{
	if (context == NULL) {
		return FALSE;
	}

	return context->busy;
}

void r_context_set_busy(gboolean busy)
{
	GError *ierror = NULL;

	g_assert_nonnull(context);
	g_assert(context->busy != busy);

	if (!context->busy && context->pending)
		if (!r_context_configure(&ierror))
			g_error("Failed to initialize context: %s", ierror->message);

	context->busy = busy;
}

static void r_context_send_progress(gboolean op_finished, gboolean success)
{
	RaucProgressStep *step;
	RaucProgressStep *iter_step;
	gfloat percentage = 0;

	/* last step already notified parent, ignore it */
	GList *iter = g_list_next(context->progress);

	/* "stack" should never be NULL at this point */
	g_assert_nonnull(context->progress);

	step = context->progress->data;

	/* no step in list left means operation complete */
	if (!iter)
		percentage = step->percent_done;

	/* sum up done percentages of all steps */
	while (iter) {
		iter_step = iter->data;
		percentage = percentage + iter_step->percent_done;
		iter = g_list_next(iter);
	}

	/* This step is not 100% itself, so it must not be the root step even though the
	   previous steps sum to 100. Max out the percentage at 99% in that case. */
	if (step->percent_done < 100.0f && percentage > 99.0f)
		percentage = 99.0f;

	g_assert_cmpint(percentage, <=, 100);

	/* call installer callback with percentage and message */
	if (op_finished) {
		g_autofree gchar *old = step->description;
		if (success)
			step->description = g_strdup_printf("%s done.", old);
		else
			step->description = g_strdup_printf("%s failed.", old);
	}

	/* handle missing callback gracefully */
	if (context->progress_callback)
		context->progress_callback(percentage, step->description,
				g_list_length(context->progress));
}

void r_context_begin_step(const gchar *name, const gchar *description,
		gint substeps)
{
	r_context_begin_step_weighted(name, description, substeps, 1);
}

void r_context_begin_step_weighted(const gchar *name, const gchar *description,
		gint substeps, gint weight)
{
	RaucProgressStep *step = g_new0(RaucProgressStep, 1);
	RaucProgressStep *parent;

	g_return_if_fail(name);
	g_return_if_fail(description);

	/* set properties */
	step->name = g_strdup(name);
	step->description = g_strdup(description);
	step->weight = weight;
	step->substeps_total = substeps;
	step->substeps_done = 0;
	step->percent_done = 0;
	step->last_explicit_percent = 0;

	/* calculate percentage */
	if (context->progress) {
		parent = context->progress->data;
		if (parent->substeps_total == 0)
			g_error("Cannot add substep '%s': Parent step '%s' has no substeps.", name, parent->name);

		/* nesting check */
		if (parent->substeps_total == parent->substeps_done)
			g_error("Step nesting wrong: %s contains %s exceeding step limit (%d/%d)",
					parent->name, step->name,
					parent->substeps_done + 1,
					parent->substeps_total);

		step->percent_total = step->weight * parent->percent_total
		                      / parent->substeps_total;

		g_assert_cmpint(step->percent_total, <=,
				parent->percent_total);
		g_assert_cmpint(step->percent_total, <=, 100);
	} else {
		/* root step */
		step->percent_total = 100;
	}

	/* add step to "stack" */
	context->progress = g_list_prepend(context->progress, step);

	r_context_send_progress(FALSE, FALSE);
}

void r_context_begin_step_formatted(const gchar *name, gint substeps, const gchar *description, ...)
{
	va_list args;
	g_autofree gchar *desc_formatted = NULL;

	g_return_if_fail(name);
	g_return_if_fail(description);

	va_start(args, description);
	desc_formatted = g_strdup_vprintf(description, args);
	va_end(args);

	r_context_begin_step(name, desc_formatted, substeps);
}

void r_context_begin_step_weighted_formatted(const gchar *name, gint substeps, gint weight, const gchar *description, ...)
{
	va_list args;
	g_autofree gchar *desc_formatted = NULL;

	g_return_if_fail(name);
	g_return_if_fail(description);

	va_start(args, description);
	desc_formatted = g_strdup_vprintf(description, args);
	va_end(args);

	r_context_begin_step_weighted(name, desc_formatted, substeps, weight);
}

void r_context_end_step(const gchar *name, gboolean success)
{
	RaucProgressStep *step;
	GList *step_element;
	RaucProgressStep *parent;

	g_return_if_fail(name);

	/* "stack" should never be NULL at this point */
	g_assert_nonnull(context->progress);

	/* get element from "stack" */
	step_element = context->progress;
	step = step_element->data;
	g_assert_nonnull(step);

	step->percent_done = step->percent_total;

	/* check number of substeps */
	if (step->substeps_done > step->substeps_total)
		g_error("Too many substeps: %s (%d/%d)",
				step->name, step->substeps_done,
				step->substeps_total);

	if (success && step->substeps_done < step->substeps_total)
		g_error("Not enough substeps: %s (%d/%d)",
				step->name, step->substeps_done,
				step->substeps_total);

	/* mark substeps/percentage as done/complete in case of an error */
	if (!success)
		step->substeps_done = step->substeps_total;

	/* ensure that progress step nesting is done correctly */
	g_assert_cmpstr(step->name, ==, name);

	/* increment step count and percentage on parent step */
	if (g_list_next(context->progress)) {
		parent = g_list_next(context->progress)->data;
		parent->substeps_done += step->weight;

		/* clean up explicit percentage */
		if (step->last_explicit_percent != 0)
			r_context_set_step_percentage(step->name, 100);
		else
			parent->percent_done = parent->percent_done
			                       + step->percent_done;

		g_assert_cmpint(step->percent_done, <=,
				parent->percent_done);
	}

	r_context_send_progress(TRUE, success);
	context->progress = g_list_remove_link(context->progress,
			step_element);

	g_list_free(step_element);
	r_context_free_progress_step(step);
}

void r_context_set_step_percentage(const gchar *name, gint custom_percent)
{
	RaucProgressStep *step;
	RaucProgressStep *parent;
	gint percent_difference;

	g_return_if_fail(name);

	g_assert_nonnull(context->progress);

	step = context->progress->data;
	if (!g_list_next(context->progress))
		g_error("Root step does not support setting percentage");
	parent = g_list_next(context->progress)->data;

	/* ensure that progress step nesting is done correctly */
	if (g_strcmp0(step->name, name) != 0)
		g_error("Wrong step context '%s'. Current step is '%s'.", name, step->name);

	/* substeps and setting explicit percentage does not make sense */
	if (step->substeps_total < 0)
		g_error("Setting percentage on substeps > 0 is not supported");

	percent_difference = custom_percent - step->last_explicit_percent;

	/* skip progress update if percentage did not change */
	if (percent_difference < 1)
		return;

	step->percent_done = step->percent_total
	                     * (percent_difference / 100.0f);

	/* pass to parent */
	if (parent)
		parent->percent_done = parent->percent_done
		                       + step->percent_done;

	step->last_explicit_percent = custom_percent;

	/* r_context_step_end sends 100% progress step */
	if (custom_percent != 100)
		r_context_send_progress(FALSE, FALSE);
}

void r_context_inc_step_percentage(const gchar *name)
{
	RaucProgressStep *step = context->progress->data;
	r_context_set_step_percentage(name, step->last_explicit_percent + 1);
}

void r_context_free_progress_step(RaucProgressStep *step)
{
	if (!step)
		return;

	g_free(step->name);
	g_free(step->description);
	g_free(step);
}

void r_context_register_progress_callback(progress_callback progress_cb)
{
	g_return_if_fail(progress_cb);

	g_assert_null(context->progress_callback);

	context->progress_callback = progress_cb;
}

RaucContext *r_context_conf(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		GError *ierror = NULL;

		// let us handle broken pipes explicitly
		signal(SIGPIPE, SIG_IGN);

		if (!network_init(&ierror)) {
			g_warning("%s", ierror->message);
			g_error_free(ierror);
			return NULL;
		}
		if (!signature_init(&ierror)) {
			g_warning("%s", ierror->message);
			g_error_free(ierror);
			return NULL;
		}

		initialized = TRUE;
	}

	if (context == NULL) {
		context = g_new0(RaucContext, 1);
		context->progress = NULL;
		context->install_info = g_new0(RContextInstallationInfo, 1);
	}

	g_assert_false(context->busy);

	context->pending = TRUE;

	return context;
}

const RaucContext *r_context(void)
{
	GError *ierror = NULL;

	if (!context)
		g_error("Context not initialized. Call r_context_conf() first");

	if (context_configuring)
		g_error("Detected call of r_context() while still setting up context! Aborted to avoid infinite recursion!");

	if (context->pending) {
		context_configuring = TRUE;
		if (!r_context_configure(&ierror))
			g_error("Failed to initialize context: %s", ierror->message);
		context_configuring = FALSE;
	}

	return context;
}

void r_context_install_info_free(RContextInstallationInfo *info)
{
	/* contains only reference to existing bundle instance */
	info->mounted_bundle = NULL;
	g_free(info);
}

void r_context_clean(void)
{
	if (context) {
		g_clear_pointer(&context->configpath, g_free);
		g_clear_pointer(&context->certpath, g_free);
		g_clear_pointer(&context->keypath, g_free);
		g_clear_pointer(&context->keyringpath, g_free);
		g_clear_pointer(&context->keyringdirectory, g_free);
		g_clear_pointer(&context->signing_keyringpath, g_free);
		g_clear_pointer(&context->encryption_key, g_free);
		g_clear_pointer(&context->mksquashfs_args, g_free);
		g_clear_pointer(&context->casync_args, g_free);
		g_clear_pointer(&context->recipients, g_strfreev);
		g_clear_pointer(&context->intermediatepaths, g_strfreev);
		g_clear_pointer(&context->mountprefix, g_free);
		g_clear_pointer(&context->bootslot, g_free);
		g_clear_pointer(&context->boot_id, g_free);
		g_clear_pointer(&context->machine_id, g_free);
		g_clear_pointer(&context->system_serial, g_free);
		g_clear_pointer(&context->system_version, g_free);
		g_clear_pointer(&context->system_info, g_hash_table_destroy);

		g_clear_pointer(&context->handlerextra, g_free);

		g_clear_pointer(&context->install_info, r_context_install_info_free);

		g_clear_pointer(&context->config, free_config);

		for (GList *l = context->configoverride; l != NULL; l = l->next) {
			ConfigFileOverride *override = (ConfigFileOverride *)l->data;
			g_clear_pointer(&override->section, g_free);
			g_clear_pointer(&override->name, g_free);
			g_clear_pointer(&override->value, g_free);
			g_clear_pointer(&override, g_free);
		}
		g_clear_pointer(&context->configoverride, g_list_free);

		g_clear_pointer(&context->system_status, r_system_status_free);

		g_clear_pointer(&context, g_free);
	}
}
