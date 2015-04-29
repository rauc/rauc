#include <gio/gio.h>

#include <config.h>
#include <signature.h>
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

static gboolean output_stream_write_uint64_all(GOutputStream *stream,
                                              guint64 data,
                                              GCancellable *cancellable,
                                              GError **error)
{
	gsize written;
	gboolean res;

	data = GUINT64_TO_BE(data);
	res = g_output_stream_write_all(stream, &data, sizeof(data), &written,
					 cancellable, error);
	g_assert(written == sizeof(data));
	return res;
}

static gboolean output_stream_write_bytes_all(GOutputStream *stream,
                                              GBytes *bytes,
                                              GCancellable *cancellable,
                                              GError **error)
{
	const void *buffer;
	gsize count, written;

	buffer = g_bytes_get_data(bytes, &count);
	return g_output_stream_write_all(stream, buffer, count, &written,
					 cancellable, error);
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
