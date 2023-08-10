#pragma once

#include <gio/gio.h>
#include <glib.h>

/* These functions can be used by slot and artifact update handlers. */

/**
 * Copies data from an input stream to an output stream, while generating
 * progress updates.
 *
 * @param in_stream input stream
 * @param out_stream output stream
 * @param size expected size of the data to copy
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if copying was successful, FALSE otherwise
 */

gboolean r_copy_stream_with_progress(GInputStream *in_stream, GOutputStream *out_stream,
		goffset size, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
