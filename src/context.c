#include <gio/gio.h>
#include <string.h>

#include "config_file.h"
#include "context.h"
#include "network.h"
#include "signature.h"

RaucContext *context = NULL;

static const gchar* get_cmdline_bootname(void) {
	GRegex *regex = NULL;
	GMatchInfo *match = NULL;
	char *contents = NULL;
	static const char *bootname = NULL;
	gchar buf[PATH_MAX + 1];
	gchar *realdev = NULL;

	if (bootname != NULL)
		return bootname;

	if (!g_file_get_contents("/proc/cmdline", &contents, NULL, NULL))
		return NULL;

	regex = g_regex_new("rauc\\.slot=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		bootname = g_match_info_fetch(match, 1);
		goto out;
	}
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);

	/* For barebox, we check if the bootstate code set the active slot name
	 * in the command line */
	if (g_strcmp0(context->config->system_bootloader, "barebox") == 0) {
		regex = g_regex_new("(?:bootstate|bootchooser)\\.active=(\\S+)", 0, 0, NULL);
		if (g_regex_match(regex, contents, 0, &match)) {
			bootname = g_match_info_fetch(match, 1);
			goto out;
		}
		g_clear_pointer(&match, g_match_info_free);
		g_clear_pointer(&regex, g_regex_unref);
	}

	regex = g_regex_new("root=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		bootname = g_match_info_fetch(match, 1);
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

	realdev = realpath(bootname, buf);
	if (realdev == NULL) {
		g_message("Failed to resolve realpath for '%s'", bootname);
		goto out;
	}

	if (g_strcmp0(realdev, bootname) != 0) {
		g_debug("Resolved bootname %s to %s", bootname, realdev);

		g_free((gchar*) bootname);
		bootname = g_strdup(realdev);
	}


out:
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&contents, g_free);

	return bootname;
}

static gboolean launch_and_wait_variables_handler(gchar *handler_name, GHashTable *variables, GError **error) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GHashTableIter iter;
	gchar *key = NULL;
	gchar *value = NULL;
	GDataInputStream *datainstream = NULL;
	GInputStream *instream;
	gchar* outline;

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	/* we copy the variables from the hashtable and add them to the
	   subprocess environment */
	g_hash_table_iter_init(&iter, variables);
	while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
                g_subprocess_launcher_setenv(handlelaunch, g_strdup(key), g_strdup(value), 1);
	}

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch,
			&ierror, handler_name,
			NULL,
			NULL);

	if (!handleproc) {
		g_propagate_error(error, ierror);
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(handleproc);
	datainstream = g_data_input_stream_new(instream);

	do {
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline)
			continue;

		if (g_str_has_prefix(outline, "RAUC_")) {
			gchar **split = g_strsplit(outline, "=", 2);

			if (g_strv_length(split) != 2)
				continue;

			g_hash_table_insert(variables, g_strdup(split[0]), g_strdup(split[1]));
			g_strfreev(split);
		}
	} while (outline);

	res = g_subprocess_wait_check(handleproc, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	g_clear_object(&datainstream);
	g_clear_object(&handleproc);
	g_clear_object(&handlelaunch);
	return res;
}

static gchar* get_system_dtb_compatible(GError **error) {
	gchar *contents = NULL;
	GError *ierror = NULL;

	if (!g_file_get_contents("/sys/firmware/devicetree/base/compatible", &contents, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return contents;
}

static gchar* get_variant_from_file(const gchar* filename, GError **error) {
	gchar *contents = NULL;
	GError *ierror = NULL;

	if (!g_file_get_contents(filename, &contents, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return contents;
}


static void r_context_configure(void) {
	gboolean res = TRUE;
	GError *error = NULL;

	g_assert_nonnull(context);
	g_assert_false(context->busy);

	g_clear_pointer(&context->config, free_config);
	res = load_config(context->configpath, &context->config, &error);
	if (!res && error->domain==g_file_error_quark()) {
		g_debug("system config not found, using default values");
		g_clear_error(&error);
		res = default_config(&context->config);
	}
	if (!res) {
		g_error("failed to initialize context: %s", error->message);
		g_clear_error(&error);
	}

	if (context->config->system_variant_type == R_CONFIG_SYS_VARIANT_DTB) {
		gchar *compatible = get_system_dtb_compatible(&error);
		if (!compatible) {
			g_warning("Failed to read dtb compatible: %s", error->message);
			g_clear_error(&error);
		} else {
			g_free(context->config->system_variant);
			context->config->system_variant = compatible;
		}
	} else if (context->config->system_variant_type == R_CONFIG_SYS_VARIANT_FILE) {
		gchar *variant = get_variant_from_file(context->config->system_variant, &error);
		if (!variant) {
			g_warning("Failed to read system variant from file: %s", error->message);
			g_clear_error(&error);
		} else {
			g_free(context->config->system_variant);
			context->config->system_variant = variant;
		}
	}

	if (context->config->systeminfo_handler &&
		g_file_test(context->config->systeminfo_handler, G_FILE_TEST_EXISTS)) {

		GError *ierror = NULL;
		GHashTable *vars = NULL;
		GHashTableIter iter;
		gchar *key = NULL;
		gchar *value = NULL;

		vars = g_hash_table_new(g_str_hash, g_str_equal);

		g_message("Getting Systeminfo: %s", context->config->systeminfo_handler);
		res = launch_and_wait_variables_handler(context->config->systeminfo_handler, vars, &ierror);
		if (!res) {
			g_error("Failed to read system-info variables%s", ierror->message);
			g_clear_error(&ierror);
		}

		g_hash_table_iter_init(&iter, vars);
		while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
			if (g_strcmp0(key, "RAUC_SYSTEM_SERIAL") == 0)
				r_context_conf()->system_serial = g_strdup(value);
		}

		g_clear_pointer(&vars, g_hash_table_unref);
	}

	if (context->bootslot == NULL) {
		context->bootslot = g_strdup(get_cmdline_bootname());
	}

	if (context->mountprefix) {
		g_free(context->config->mount_prefix);
		context->config->mount_prefix = g_strdup(context->mountprefix);
	}

	if (context->keyringpath) {
		context->config->keyring_path = context->keyringpath;
	}

	context->pending = FALSE;
}

gboolean r_context_get_busy(void) {
	if (context == NULL) {
		return FALSE;
	}

	return context->busy;
}

void r_context_set_busy(gboolean busy) {
	g_assert_nonnull(context);
	g_assert(context->busy != busy);

	if (!context->busy && context->pending)
		r_context_configure();

	context->busy = busy;
}

static void r_context_send_progress(gboolean op_finished, gboolean success) {
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

	g_assert_cmpint(percentage, <=, 100);

	/* call installer callback with percentage and message */
	if (op_finished) {
		if (success)
			step->description = g_strdup_printf("%s done.",
							    step->description);
		else
			step->description = g_strdup_printf("%s failed.",
							    step->description);
	}

	/* handle missing callback gracefully */
	if (context->progress_callback)
		context->progress_callback(percentage, step->description,
					   g_list_length(context->progress));
}

void r_context_begin_step(const gchar *name, const gchar *description,
	 		  gint substeps) {

	RaucProgressStep *step = g_new0(RaucProgressStep, 1);
	RaucProgressStep *parent;

	/* set properties */
	step->name = name;
	step->description = description;
	step->substeps_total = substeps;
	step->substeps_done = 0;
	step->percent_done = 0;
	step->last_explicit_percent = 0;

	/* calculate percentage */
	if (context->progress) {
		parent = context->progress->data;
		g_assert_cmpint(parent->substeps_total, >, 0);

		/* nesting check */
		if (parent->substeps_total == parent->substeps_done)
			g_error("Step nesting wrong: %s contains %s exceeding step limit (%d/%d)",
				parent->name, step->name,
				parent->substeps_done + 1,
				parent->substeps_total);

		step->percent_total = parent->percent_total
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

void r_context_end_step(const gchar *name, gboolean success) {
	RaucProgressStep *step;
	GList *step_element;
	RaucProgressStep *parent;

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
		parent->substeps_done++;

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
	g_free(step);
}

void r_context_set_step_percentage(const gchar *name, gint custom_percent) {
	RaucProgressStep *step;
	RaucProgressStep *parent;
	gint percent_difference;

	g_assert_nonnull(context->progress);

	step = context->progress->data;
	parent = g_list_next(context->progress)->data;

	/* ensure that progress step nesting is done correctly */
	g_assert_cmpstr(step->name, ==, name);

	/* substeps and setting explicit percentage does not make sense */
	g_assert_cmpint(step->substeps_total, ==, 0);

	percent_difference = custom_percent - step->last_explicit_percent;

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

void r_context_register_progress_callback(progress_callback progress_cb) {
	g_assert_nonnull(progress_cb);
	g_assert_null(context->progress_callback);

	context->progress_callback = progress_cb;
}

RaucContext *r_context_conf(void) {
	if (context == NULL) {
		network_init();
		signature_init();

		context = g_new0(RaucContext, 1);
		context->configpath = g_strdup("/etc/rauc/system.conf");
		context->progress = NULL;
		context->install_info = g_new0(RContextInstallationInfo, 1);
	}

	g_assert_false(context->busy);

	context->pending = TRUE;

	return context;
}

const RaucContext *r_context(void) {
	g_assert_nonnull(context);

	if (context->pending)
		r_context_configure();

	return context;
}
