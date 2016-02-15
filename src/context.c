#include <config_file.h>
#include <network.h>
#include <signature.h>
#include <gio/gio.h>

#include "context.h"

RaucContext *context = NULL;

static gboolean launch_and_wait_variables_handler(gchar *handler_name, GHashTable *variables, GError **error) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GHashTableIter iter;
	gchar *key = NULL;
	gchar *value = NULL;
	GDataInputStream *datainstream;
	GInputStream *instream;
	gchar* outline;

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	/* we copy the variables from the hashtable and add them to the
	   subprocess environment */
	g_hash_table_iter_init(&iter, variables);
	while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&value)) {
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

static void r_context_configure(void) {
	gboolean res = TRUE;
	GError *error = NULL;

	g_assert_nonnull(context);
	g_assert_false(context->busy);

	g_clear_pointer(&context->config, free_config);
	res = load_config(context->configpath, &context->config, &error);
	if (!res && error->domain==g_file_error_quark()) {
		g_message("system config not found, using default values");
		res = default_config(&context->config);
	} else if (!res) {
		g_error("failed to initialize context: %s", error->message);

	}

	if (&context->config->systeminfo_handler &&
		g_file_test(context->config->systeminfo_handler, G_FILE_TEST_EXISTS)) {

		GError *ierror = NULL;
		GHashTable *vars = NULL;
		GHashTableIter iter;
		gchar *key = NULL;
		gchar *value = NULL;

		vars = g_hash_table_new(g_str_hash, g_str_equal);

		g_print("Getting Systeminfo: %s\n", context->config->systeminfo_handler);
		res = launch_and_wait_variables_handler(context->config->systeminfo_handler, vars, &ierror);
		if (!res) {
			g_error("Failed to read system-info variables%s", ierror->message);
			g_clear_error(&ierror);
		}

		g_hash_table_iter_init(&iter, vars);
		while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&value)) {
			if (g_strcmp0(key, "RAUC_SYSTEM_SERIAL") == 0)
				r_context_conf()->system_serial = g_strdup(value);
		}

		g_clear_pointer(&vars, g_hash_table_unref);
	}

	if (context->mountprefix) {
		g_free(context->config->mount_prefix);
		context->config->mount_prefix = g_strdup(context->mountprefix);
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

RaucContext *r_context_conf(void) {
	if (context == NULL) {
		network_init();
		signature_init();

		context = g_new0(RaucContext, 1);
		context->configpath = g_strdup("/etc/rauc/system.conf");
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
