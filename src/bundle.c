#include <gio/gio.h>

#include <config.h>
#include <signature.h>
#include <mount.h>
#include "bundle.h"

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;

	sproc = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE,
				 &error, CMD_MKSQUASHFS,
				 contentdir,
				 bundlename,
				 "-all-root",
				 NULL);
	if (sproc == NULL) {
		g_warning("failed to start mksquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &error);
	if (!res) {
		g_warning("failed to run mksquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean unsquashfs(const gchar *bundlename, const gchar *contentdir) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;

	sproc = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE,
				 &error, CMD_UNSQUASHFS,
				 "-dest", contentdir,
				 bundlename,
				 NULL);
	if (sproc == NULL) {
		g_warning("failed to start unsquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &error);
	if (!res) {
		g_warning("failed to run unsquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean output_stream_write_uint64_all(GOutputStream *stream,
                                              guint64 data,
                                              GCancellable *cancellable,
                                              GError **error)
{
	gsize bytes_written;
	gboolean res;

	data = GUINT64_TO_BE(data);
	res = g_output_stream_write_all(stream, &data, sizeof(data), &bytes_written,
					 cancellable, error);
	g_assert(bytes_written == sizeof(data));
	return res;
}

static gboolean input_stream_read_uint64_all(GInputStream *stream,
                                             guint64 *data,
                                             GCancellable *cancellable,
                                             GError **error)
{
	guint64 tmp;
	gsize bytes_read;
	gboolean res;

	res = g_input_stream_read_all(stream, &tmp, sizeof(tmp), &bytes_read,
		                      cancellable, error);
	g_assert(bytes_read == sizeof(tmp));
	*data = GUINT64_FROM_BE(tmp);
	return res;
}

static gboolean output_stream_write_bytes_all(GOutputStream *stream,
                                              GBytes *bytes,
                                              GCancellable *cancellable,
                                              GError **error)
{
	const void *buffer;
	gsize count, bytes_written;

	buffer = g_bytes_get_data(bytes, &count);
	return g_output_stream_write_all(stream, buffer, count, &bytes_written,
					 cancellable, error);
}

static gboolean input_stream_read_bytes_all(GInputStream *stream,
		                            GBytes **bytes,
                                            gsize count,
                                            GCancellable *cancellable,
                                            GError **error)
{
	void *buffer = g_malloc0(count);
	gsize bytes_read;
	gboolean res;

	res = g_input_stream_read_all(stream, buffer, count, &bytes_read,
		                      cancellable, error);
	if (!res) {
		g_free(buffer);
		return res;
	}
	g_assert(bytes_read == count);
	*bytes = g_bytes_new_take(buffer, count);
	return TRUE;
}

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir) {
	GBytes *sig = NULL;
	GFile *bundlefile = NULL;
	GFileOutputStream *bundlestream = NULL;
	gboolean res = FALSE;
	guint64 offset;

	res = mksquashfs(bundlename, contentdir);
	if (!res)
		goto out;

	sig = cms_sign_file(bundlename,
			    "test/openssl-ca/rel/release-1.cert.pem",
			    "test/openssl-ca/rel/private/release-1.pem");
	if (sig == NULL)
		goto out;

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_append_to(bundlefile, G_FILE_CREATE_NONE, NULL, NULL);
	if (bundlestream == NULL) {
		g_warning("failed to open bundle for appending");
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      0, G_SEEK_END, NULL, NULL);
	if (!res) {
		g_warning("failed to seek to end of bundle");
		goto out;
	}

	offset = g_seekable_tell((GSeekable *)bundlestream);
	res = output_stream_write_bytes_all((GOutputStream *)bundlestream, sig, NULL, NULL);
	if (!res) {
		g_warning("failed to append signature to bundle");
		goto out;
	}


	offset = g_seekable_tell((GSeekable *)bundlestream) - offset;
	res = output_stream_write_uint64_all((GOutputStream *)bundlestream, offset, NULL, NULL);
	if (!res) {
		g_warning("failed to append signature size to bundle");
		goto out;
	}


	res = TRUE;
out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	return res;
}

static gboolean check_bundle(const gchar *bundlename, gsize *size) {
	GBytes *sig = NULL;
	GFile *bundlefile = NULL;
	GFileInputStream *bundlestream = NULL;
	guint64 sigsize;
	goffset offset;
	gboolean res = FALSE;

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_read(bundlefile, NULL, NULL);
	if (bundlestream == NULL) {
		g_warning("failed to open bundle for appending");
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      -sizeof(sigsize), G_SEEK_END, NULL, NULL);
	if (!res) {
		g_warning("failed to seek to end of bundle");
		goto out;
	}
	offset = g_seekable_tell((GSeekable *)bundlestream);

	res = input_stream_read_uint64_all(G_INPUT_STREAM(bundlestream),
			                   &sigsize, NULL, NULL);
	if (!res) {
		g_warning("failed to read signature size from bundle");
		goto out;
	}

	offset -= sigsize;
	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      offset, G_SEEK_SET, NULL, NULL);
	if (!res) {
		g_warning("failed to seek to start of bundle signature");
		goto out;
	}

	res = input_stream_read_bytes_all(G_INPUT_STREAM(bundlestream),
			                  &sig, sigsize, NULL, NULL);
	if (!res) {
		g_warning("failed to read signature from bundle");
		goto out;
	}

	/* the squashfs image size is in offset */
	res = cms_verify_file(bundlename, sig, offset);
	if (!res)
		goto out;

	*size = offset;

	res = TRUE;
out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	return res;
}

gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir) {
	gsize size;
	gboolean res = FALSE;

	res = check_bundle(bundlename, &size);
	if (!res)
		goto out;

	res = unsquashfs(bundlename, outputdir);
	if (!res)
		goto out;

	res = TRUE;
out:
	return res;
}

gboolean mount_bundle(const gchar *bundlename, const gchar *mountpoint) {
	gsize size;
	gboolean res = FALSE;

	res = check_bundle(bundlename, &size);
	if (!res)
		goto out;

	res = mount_loop(bundlename, mountpoint, size);
	if (!res)
		goto out;

	res = TRUE;
out:
	return res;
}

gboolean umount_bundle(const gchar *bundlename) {
	gboolean res = FALSE;

	res = umount_loop(bundlename);
	if (!res)
		goto out;

	res = TRUE;
out:
	return res;
}
