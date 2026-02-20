#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "update_handler.h"
#include "update_utils.h"
#include "context.h"

static GUnixOutputStream *open_unix_output_stream(const gchar *filename, int flags, int mode, int *fd, GError **error)
{
	GUnixOutputStream *outstream = NULL;
	int fd_out;

	fd_out = g_open(filename, O_WRONLY | flags, mode);

	if (fd_out == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to open output file/device %s failed: %s", filename, strerror(errno));
		return NULL;
	}

	outstream = G_UNIX_OUTPUT_STREAM(g_unix_output_stream_new(fd_out, TRUE));
	if (outstream == NULL) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to create stream for output device %s", filename);
		return NULL;
	}

	if (fd != NULL)
		*fd = fd_out;

	return outstream;
}

/* the fd will only live as long as the returned output stream */
GUnixOutputStream *r_unix_output_stream_open_device(const gchar *filename, int *fd, GError **error)
{
	g_return_val_if_fail(filename, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	return open_unix_output_stream(filename, O_EXCL, 0, fd, error);
}

/* the fd will only live as long as the returned output stream */
GUnixOutputStream *r_unix_output_stream_create_file(const gchar *filename, int *fd, GError **error)
{
	g_return_val_if_fail(filename, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	return open_unix_output_stream(filename, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, fd, error);
}

/* the fd will only live as long as the returned input stream */
GUnixInputStream *r_open_unix_input_stream(const gchar *filename, int *fd, GError **error)
{
	GUnixInputStream *instream = NULL;
	int fd_out;

	g_return_val_if_fail(filename, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	fd_out = g_open(filename, O_RDONLY);
	if (fd_out < 0) {
		int err = errno;
		g_set_error(error, G_IO_ERROR, g_io_error_from_errno(err),
				"Failed to open file %s: %s", filename, g_strerror(err));
		return NULL;
	}

	instream = G_UNIX_INPUT_STREAM(g_unix_input_stream_new(fd_out, TRUE));
	if (instream == NULL) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to create stream for file %s", filename);
		return NULL;
	}

	if (fd != NULL)
		*fd = fd_out;

	return instream;
}

gboolean r_copy_stream_with_progress(GInputStream *in_stream, GOutputStream *out_stream,
		goffset size, GError **error)
{
	GError *ierror = NULL;
	gsize out_size = 0;
	goffset sum_size = 0;
	gchar buffer[8192];
	gssize in_size;

	g_return_val_if_fail(in_stream, FALSE);
	g_return_val_if_fail(out_stream, FALSE);
	g_return_val_if_fail(size >= 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* no-op for zero-sized images */
	if (size == 0)
		return TRUE;

	do {
		gboolean ret;

		in_size = g_input_stream_read(in_stream,
				buffer, 8192, NULL, &ierror);
		if (in_size == -1) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		ret = g_output_stream_write_all(out_stream, buffer,
				in_size, &out_size, NULL, &ierror);
		if (!ret) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		sum_size += out_size;

		/* emit progress info (but only when in progress context) */
		if (r_context()->progress)
			r_context_set_step_percentage("copy_image", sum_size * 100 / size);
	} while (out_size);

	return TRUE;
}
