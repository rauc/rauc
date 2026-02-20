#pragma once

#include <glib.h>
#include <gio/gio.h>

/**
 * @file event_log.h
 * @brief Implementation of structured event log handling for RAUC
 *
 * Structured glib log message with the special domain (GLIB_DOMAIN)
 * 'rauc-event' will be written to files by registered loggers.
 *
 * Required fields are:
 *
 * * "GLIB_DOMAIN": Must be "rauc-event"
 * * "RAUC_EVENT_TYPE": The type of event. Will be used for filtering by loggers
 * * "MESSAGE" : The log message
 * * "MESSAGE_ID" : The ID of the message. Must be unique per message type.
 *
 * Optional fields for providing context information are:
 *
 * * "BOOT_ID" : The boot ID associated with the log message
 * * "BUNDLE_HASH" : The bundle hash associated with the log message
 * * "BUNDLE_VERSION" : The bundle version associated with the log message
 * * "TRANSACTION_ID" : The transaction ID associated with the log message
 * * "SLOT_NAME" : The slot name associated with the log message
 * * "SLOT_BOOTNAME" : The bootname associated with the log message
 *
 * To log events, modules should define their own logging method that creates
 * a log structure array and calls g_log_structured_array().
 */

#define R_EVENT_LOG_DOMAIN "rauc-event"

/* Event log type for system boot detection */
#define R_EVENT_LOG_TYPE_BOOT "boot"
/* Event log type for slot marking (good,bad,active) */
#define R_EVENT_LOG_TYPE_MARK "mark"
/* Event log type for installation start or termination */
#define R_EVENT_LOG_TYPE_INSTALL "install"
/* Event log type for background service start or stop */
#define R_EVENT_LOG_TYPE_SERVICE "service"
/* Event log type for slot updates */
#define R_EVENT_LOG_TYPE_WRITE_SLOT "writeslot"

typedef struct _REventLogger REventLogger;

typedef enum {
	/* Readable, timestamped output, including "MESSAGE" and all known log fields */
	R_EVENT_LOGFMT_READABLE,
	/* Readable, timestamped output, containing only "MESSAGE" field */
	R_EVENT_LOGFMT_READABLE_SHORT,
	/* JSON-formatted output */
	R_EVENT_LOGFMT_JSON,
	/* Same as R_EVENT_LOGFMT_JSON but with newlines for readability */
	R_EVENT_LOGFMT_JSON_PRETTY,
} REventLogFormat;

typedef struct _REventLogger {
	/* configured information */
	gchar *name;
	gchar *filename;
	gchar **events;
	REventLogFormat format;
	goffset maxsize;
	guint maxfiles;
	/* runtime information */
	gboolean configured;
	gboolean broken;
	goffset filesize;
	GFileOutputStream *logstream;
	void (*writer)(REventLogger *logger, const GLogField *fields, gsize n_fields);
} REventLogger;

/**
 * Returns log level to use for "PRIORITY" field of structured log array
 *
 * @param log_level log level
 *
 * @return static string representing the log priority.
 */
const gchar *r_event_log_level_to_priority(GLogLevelFlags log_level);

/**
 * Tests type string for being a supported event log type.
 *
 * @param type Type string to test
 *
 * @return TRUE if supported, FALSE otherwise
 */
gboolean r_event_log_is_supported_type(const gchar *type);

/**
 * Custom structured logging function.
 *
 * To be used for g_log_set_writer_func() to set globally as the glib logger.
 *
 * All log messages will be forwarded to g_log_writer_default() first.
 *
 * Log messages of GLIB_DOMAIN 'rauc-event' will then be passed to event
 * logging where they are filtered by RAUC_EVENT_TYPE and forwarded to the
 * respective handlers registered for this event type.
 *
 * @param log_level log level, either from GLogLevelFlags, or a user-defined level
 * @param fields key–value pairs of structured data forming the log message.
 * @param n_fields number of elements in the fields array
 * @param user_data user data passed to g_log_set_writer_func()
 *
 * @return G_LOG_WRITER_HANDLED on success, G_LOG_WRITER_UNHANDLED otherwise
 */
GLogWriterOutput r_event_log_writer(GLogLevelFlags log_level, const GLogField *fields, gsize n_fields, gpointer user_data);

/**
 * Sets up a logger.
 *
 * Attempts to open the log file under the given filename and to query the
 * size.
 *
 * If setting up the logger fails, it will be marked as 'broken'.
 *
 * @param logger Logger to set up
 */
void r_event_log_setup_logger(REventLogger *logger);

/**
 * Frees event logging structure.
 *
 * @param config Logger to free
 */
void r_event_log_free_logger(REventLogger *logger);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(REventLogger, r_event_log_free_logger);

/**
 * Simple Logging convenience method.
 *
 * @param type Event type string
 * @param message Message to log
 */
void r_event_log_message(const gchar *type, const gchar *message, ...)
__attribute__((__format__(__printf__, 2, 3)));
