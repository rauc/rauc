#pragma once

#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>
#include <glib.h>

/* These functions can be used by slot and artifact update handlers. */

/**
 * Opens a device for writing and returns a GUnixOutputStream for it.
 * Optionally, the FD is returned as well.
 *
 * @param filename the device to be opened
 * @param fd the associated file descriptor, for use with ioctls
 * @param error return location for a GError, or NULL
 *
 * @return the new GUnixOutputStream if successful, NULL otherwise
 */
GUnixOutputStream *r_unix_output_stream_open_device(const gchar *filename, int *fd, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a file for writing and returns a GUnixOutputStream for it.
 * Optionally, the FD is returned as well.
 *
 * This method ensures that the file is newly created by us.
 *
 * @param filename the file to be opened
 * @param mode the access mode for the new file
 * @param fd the associated file descriptor, for use with ioctls
 * @param error return location for a GError, or NULL
 *
 * @return the new GUnixOutputStream if successful, NULL otherwise
 */
GUnixOutputStream *r_unix_output_stream_create_file(const gchar *filename, int *fd, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Opens a file for reading and returns a GUnixInputStream for it.
 * Optionally, the FD is returned as well.
 *
 * @param filename the file to be opened
 * @param fd the associated file descriptor, for use with ioctls
 * @param error return location for a GError, or NULL
 *
 * @return the new GUnixInputStream if successful, NULL otherwise
 */
GUnixInputStream *r_open_unix_input_stream(const gchar *filename, int *fd, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
