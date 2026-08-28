#include <errno.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#if ENABLE_JSON
#include <json-glib/json-glib.h>
#endif

#include "context.h"
#include "event_log.h"

static const gchar *supported_event_types[] = {
	"all",
	R_EVENT_LOG_TYPE_BOOT,
	R_EVENT_LOG_TYPE_MARK,
	R_EVENT_LOG_TYPE_INSTALL,
	R_EVENT_LOG_TYPE_SERVICE,
	R_EVENT_LOG_TYPE_WRITE_SLOT,
	NULL
};

gboolean r_event_log_is_supported_type(const gchar *type)
{
	return g_strv_contains(supported_event_types, type);
}

const gchar * r_event_log_level_to_priority(GLogLevelFlags log_level)
{
	if (log_level & G_LOG_LEVEL_ERROR)
		return "3";
	else if (log_level & G_LOG_LEVEL_CRITICAL)
		return "4";
	else if (log_level & G_LOG_LEVEL_WARNING)
		return "4";
	else if (log_level & G_LOG_LEVEL_MESSAGE)
		return "5";
	else if (log_level & G_LOG_LEVEL_INFO)
		return "6";
	else if (log_level & G_LOG_LEVEL_DEBUG)
		return "7";

	/* Default to LOG_NOTICE for custom log levels. */
	return "5";
}

void r_event_log_message(const gchar *type, const gchar *message, ...)
{
	va_list list;
	g_autofree gchar *formatted = NULL;

	g_return_if_fail(message);

	va_start(list, message);
	formatted = g_strdup_vprintf(message, list);
	va_end(list);

	g_log_structured(R_EVENT_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"RAUC_EVENT_TYPE", type,
			"MESSAGE", "%s", formatted);
}

void r_event_log_free_logger(REventLogger *logger)
{
	if (!logger)
		return;

	g_clear_pointer(&logger->name, g_free);
	g_clear_pointer(&logger->filename, g_free);
	g_clear_pointer(&logger->logstream, g_object_unref);
	g_clear_pointer(&logger->events, g_strfreev);

	g_free(logger);

	return;
}

/**
 * Log formatter for json output.
 *
 * Simply converts all log fields into a json object.
 *
 * | {
 * |   "TS": "2023-06-14T21:15:41Z"
 * |   "MESSAGE" : "Booted into rootfs.0 (A)",
 * |   "MESSAGE_ID" : "e60e0addd3454cb8b796eae0d497af96",
 * |   "GLIB_DOMAIN" : "rauc-event",
 * |   "RAUC_EVENT_TYPE" : "boot",
 * |   "BOOT_ID" : "16655d2c-c5ca-48d3-bea8-7b95c803b4b2",
 * |   "BUNDLE_HASH" : "unknown"
 * | }
 * | {
 * |   "TS": "2023-06-14T21:42:41Z"
 * |   "MESSAGE" : "Marked slot rootfs.0 as active.",
 * |   "MESSAGE_ID" : "8b5e7435e1054d86858278e7544fe6da",
 * |   "GLIB_DOMAIN" : "rauc-event",
 * |   "RAUC_EVENT_TYPE" : "mark",
 * |   "SLOT_NAME" : "rootfs.0",
 * |   "BUNDLE_HASH" : "",
 * |   "SLOT_BOOTNAME" : "A"
 * | }
 *
 * @param log_level log level, either from GLogLevelFlags, or a user-defined level
 * @param fields key–value pairs of structured data forming the log message.
 *               [array length=n_fields]
 * @param n_fields number of elements in the fields array
 * @param pretty Whether or not to pretty-print output (have human-readable line breaks)
 *
 * @return newly-allocated formatted string (without trailing newline)
 */
#if ENABLE_JSON
static gchar *event_log_format_fields_json(GLogLevelFlags log_level,
		const GLogField *fields, gsize n_fields, gboolean pretty)
{
	g_autoptr(GDateTime) now = NULL;
	g_autofree gchar *now_formatted = NULL;
	g_autoptr(JsonGenerator) gen = NULL;
	g_autoptr(JsonNode) root = NULL;
	g_autoptr(JsonBuilder) builder = json_builder_new();

	now = g_date_time_new_now_utc();
	now_formatted = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");

	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "TS");
	json_builder_add_string_value(builder, now_formatted);
	for (gsize j = 0; j < n_fields; j++) {
		const GLogField *ifield = &fields[j];

		json_builder_set_member_name(builder, ifield->key);
		json_builder_add_string_value(builder, ifield->value);
	}
	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	json_generator_set_pretty(gen, pretty);
	return json_generator_to_data(gen, NULL);
}
#endif

/**
 * Log formatter for human-readable output.
 *
 * Prints the log message and optionally also the other known log fields in the
 * following scheme:
 *
 * | 2023-06-14T20:18:07Z: Booted into rootfs.0 (A)
 * |                       bundle hash: unknown
 * |                       boot ID: 16655d2c-c5ca-48d3-bea8-7b95c803b4b2
 * | 2023-06-14T20:18:12Z: Marked slot rootfs.0 as active.
 * |                       bundle hash: unknown
 *
 * @param log_level log level, either from GLogLevelFlags, or a user-defined level
 * @param fields key–value pairs of structured data forming the log message.
 *               [array length=n_fields]
 * @param n_fields number of elements in the fields array
 * @param verbose whether or not to print known log fields, too.
 *
 * @return newly-allocated formatted string (without trailing newline)
 */
static gchar *event_log_format_fields_readable(GLogLevelFlags log_level,
		const GLogField *fields, gsize n_fields, gboolean verbose)
{
	g_autoptr(GDateTime) now = NULL;
	g_autofree gchar *now_formatted = NULL;
	GString *gstring;

	gstring = g_string_new(NULL);
	now = g_date_time_new_now_utc();
	now_formatted = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");
	g_string_append_printf(gstring, "%s: ", now_formatted);

	for (gsize j = 0; j < n_fields; j++) {
		const GLogField *ifield = &fields[j];
		const gchar *message = NULL;

		/* print message */
		if (g_strcmp0(ifield->key, "MESSAGE") == 0) {
			message = ifield->value;
			g_string_append_printf(gstring, "%s", message);
			break;
		}
	}

	/* skip other fields if non-verbose */
	if (!verbose)
		return g_string_free(gstring, FALSE);

	/* collect verbose fields in order of appearance */
	for (gsize j = 0; j < n_fields; j++) {
		const GLogField *ifield = &fields[j];
		const gchar *key = NULL;
		const gchar *value = NULL;

		if (g_strcmp0(ifield->key, "TRANSACTION_ID") == 0) {
			key = "transaction ID";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "BOOT_ID") == 0) {
			key = "boot ID";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "BUNDLE_HASH") == 0) {
			key = "bundle hash";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "BUNDLE_VERSION") == 0) {
			key = "bundle version";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "BUNDLE_NAME") == 0) {
			key = "bundle name";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "SLOT_NAME") == 0) {
			key = "slot";
			value = ifield->value;
		} else if (g_strcmp0(ifield->key, "SLOT_BOOTNAME") == 0) {
			key = "bootname";
			value = ifield->value;
		}

		if (key) {
			g_string_append_printf(gstring, "\n                      %s: %s", key, value);
		}
	}

	return g_string_free(gstring, FALSE);
}

/**
 * Rotates log files.
 *
 * If a maximum size is configured and the loggers current size + provided
 * 'next_len' exceed this maximum size, the method will close the current
 * output stream, and rename the file to add a .1 suffix.
 *
 * All previously existing rotation files will be rotated by +1.
 *
 * If max-files is set, rotation is limited to max-files files.
 *
 * @param logger Logger to rotate file for
 * @param next_len Length of next data to add.
 *        This is used to determine if the log file needs to be rotated.
 * @param error return location for a GError or NULL.
 *
 * @return TRUE if rotation succeeded (or was a no-op). FALSE in case of a failure.
 */
static gboolean rotate_logfiles(REventLogger* logger, goffset next_len, GError **error)
{
	g_autoptr(GFile) logfile = NULL;
	g_autofree gchar *rotfile = NULL;
	g_autoptr(GError) ierror = NULL;

	g_return_val_if_fail(logger, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* method is no-op if no maxsize is configured */
	if (!logger->maxsize)
		return TRUE;

	/* return if size limit not reached yet */
	if (logger->filesize + next_len <= logger->maxsize)
		return TRUE;

	/* Close open stream */
	g_clear_pointer(&logger->logstream, g_object_unref);

	/* iterate through the list of potentially existing rotation files and move
	 * all (existing ones) but the last one. This will override (and thus drop)
	 * the last rotation file */
	g_assert(logger->maxfiles >= 1);
	for (guint file_num = logger->maxfiles - 1; file_num > 0; file_num--) {
		g_autofree gchar *from_file = g_strdup_printf("%s.%d", logger->filename, file_num - 1);
		g_autofree gchar *to_file = g_strdup_printf("%s.%d", logger->filename, file_num);

		/* rotate .N-1 to .N */
		if (g_rename(from_file, to_file) == -1) {
			int err = errno;
			if (err == ENOENT) {
				/* skip non-existing 'from' files */
				continue;
			} else {
				g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err), "Failed to rotate log file: %s", g_strerror(err));
				return FALSE;
			}
		}
	}

	/* rotate current log file as next .1 file */
	rotfile = g_strdup_printf("%s.1", logger->filename);
	if (g_rename(logger->filename, rotfile) == -1) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err), "Failed to rotate log file: %s", g_strerror(err));
		return FALSE;
	}

	/* re-open log file */
	logfile = g_file_new_for_path(logger->filename);
	logger->logstream = g_file_append_to(logfile, G_FILE_CREATE_NONE, NULL, &ierror);
	if (!logger->logstream) {
		g_propagate_prefixed_error(error, ierror, "Failed to open log file for appending: ");
		return FALSE;
	}
	logger->filesize = 0;

	return TRUE;
}

static void event_log_writer_file(REventLogger* logger, const GLogField *fields, gsize n_fields)
{
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *formatted = NULL;
	g_autofree gchar *output = NULL;
	gsize written = 0;

	if (logger->broken)
		return;

	if (!logger->logstream)
		g_error("Called log writer on uninitialized logger '%s'", logger->name);

	switch (logger->format) {
		case R_EVENT_LOGFMT_READABLE:
			formatted = event_log_format_fields_readable(G_LOG_LEVEL_MESSAGE, fields, n_fields, TRUE);
			break;
		case R_EVENT_LOGFMT_READABLE_SHORT:
			formatted = event_log_format_fields_readable(G_LOG_LEVEL_MESSAGE, fields, n_fields, FALSE);
			break;
		case R_EVENT_LOGFMT_JSON:
#if ENABLE_JSON
			formatted = event_log_format_fields_json(G_LOG_LEVEL_MESSAGE, fields, n_fields, FALSE);
#else
			g_error("Compiled without JSON support");
#endif
			break;
		case R_EVENT_LOGFMT_JSON_PRETTY:
#if ENABLE_JSON
			formatted = event_log_format_fields_json(G_LOG_LEVEL_MESSAGE, fields, n_fields, TRUE);
#else
			g_error("Compiled without JSON support");
#endif
			break;
		default:
			g_error("Unknown log format");
	}
	output = g_strdup_printf("%s\n", formatted);

	/* Once we know how much to write, we can use this information for trimming */
	if (!rotate_logfiles(logger, strlen(output), &ierror)) {
		g_warning("Failed to rotate log files: %s", ierror->message);
		g_warning("Deactivating broken logger %s", logger->name);
		logger->broken = TRUE;
		return;
	}

	if (!g_output_stream_write_all(G_OUTPUT_STREAM(logger->logstream), output, strlen(output), &written, NULL, &ierror)) {
		g_warning("Failed to write log file '%s': %s", logger->filename, ierror->message);
		g_warning("Deactivating broken logger '%s'", logger->name);
		logger->broken = TRUE;
		return;
	}

	logger->filesize += written;
}

GLogWriterOutput r_event_log_writer(GLogLevelFlags log_level, const GLogField *fields, gsize n_fields, gpointer user_data)
{
	const gchar *log_domain = NULL;
	const gchar *event_type = NULL;

	/* Always log to default location, too */
	g_log_writer_default(log_level, fields, n_fields, user_data);

	/* get log domain */
	for (gsize i = 0; i < n_fields; i++) {
		if (g_strcmp0(fields[i].key, "GLIB_DOMAIN") == 0) {
			log_domain = fields[i].value;
			break;
		}
	}

	/* We are interested in "rauc-event" domains only */
	if (!log_domain || g_strcmp0(log_domain, R_EVENT_LOG_DOMAIN) != 0) {
		return G_LOG_WRITER_HANDLED;
	}

	/* get event type */
	for (gsize i = 0; i < n_fields; i++) {
		if (g_strcmp0(fields[i].key, "RAUC_EVENT_TYPE") == 0) {
			event_type = fields[i].value;
			break;
		}
	}

	/* iterate over registered event loggers */
	for (GList *l = r_context()->config->loggers; l != NULL; l = l->next) {
		REventLogger* logger = l->data;

		if (logger->broken)
			continue;

		/* Filter out by event type */
		if ((g_strcmp0(logger->events[0], "all") != 0) &&
		    !g_strv_contains((const gchar * const*)logger->events, event_type)) {
			continue;
		}

		logger->writer(logger, fields, n_fields);
	}

	return G_LOG_WRITER_HANDLED;
}

void r_event_log_setup_logger(REventLogger *logger)
{
	g_autoptr(GFile) logfile = NULL;
	g_autoptr(GError) ierror = NULL;

	g_return_if_fail(logger);

	if (logger->configured) {
		g_message("Logger %s already configured", logger->name);
		return;
	}

	g_info("Setting up logger %s for %s ..", logger->name, logger->filename);

	logger->writer = &event_log_writer_file;

	logfile = g_file_new_for_path(logger->filename);
	logger->logstream = g_file_append_to(logfile, G_FILE_CREATE_NONE, NULL, &ierror);
	if (!logger->logstream) {
		g_warning("Failed to open log file for appending: %s", ierror->message);
		g_warning("Deactivating broken logger '%s'", logger->name);
		logger->broken = TRUE;
		return;
	}

	logger->filesize = g_seekable_tell(G_SEEKABLE(logger->logstream));

	logger->configured = TRUE;

	return;
}
