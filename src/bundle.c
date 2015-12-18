#include <gio/gio.h>

#include <config.h>
#include <context.h>
#include <signature.h>
#include <mount.h>
#include "bundle.h"

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir, GError **error) {
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	if (g_file_test (bundlename, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", bundlename);
		goto out;
	}

	sproc = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_SILENCE,
				 &ierror, "mksquashfs",
				 contentdir,
				 bundlename,
				 "-all-root",
				 "-noappend",
				 "-no-progress",
				 "-no-xattrs",
				 NULL);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start mksquashfs");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run mksquashfs");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean unsquashfs(const gchar *bundlename, const gchar *contentdir, const gchar *extractfile, GError **error) {
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(7, g_free);

	g_ptr_array_add(args, g_strdup("unsquashfs"));
	g_ptr_array_add(args, g_strdup("-dest"));
	g_ptr_array_add(args, g_strdup(contentdir));
	g_ptr_array_add(args, g_strdup(bundlename));

	if (extractfile) {
		g_ptr_array_add(args, g_strdup("-e"));
		g_ptr_array_add(args, g_strdup(extractfile));
	}

	g_ptr_array_add(args, NULL);

	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
				 G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start unsquashfs");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run unsquashfs");
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

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error) {
	GError *ierror = NULL;
	GBytes *sig = NULL;
	GFile *bundlefile = NULL;
	GFileOutputStream *bundlestream = NULL;
	gboolean res = FALSE;
	guint64 offset;

	g_assert_nonnull(r_context()->certpath);
	g_assert_nonnull(r_context()->keypath);

	res = mksquashfs(bundlename, contentdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	sig = cms_sign_file(bundlename,
			    r_context()->certpath,
			    r_context()->keypath,
			    &ierror);
	if (sig == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed signing bundle");
		goto out;
	}

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_append_to(bundlefile, G_FILE_CREATE_NONE, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for appending");
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      0, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle");
		goto out;
	}

	offset = g_seekable_tell((GSeekable *)bundlestream);
	res = output_stream_write_bytes_all((GOutputStream *)bundlestream, sig, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature to bundle");
		goto out;
	}


	offset = g_seekable_tell((GSeekable *)bundlestream) - offset;
	res = output_stream_write_uint64_all((GOutputStream *)bundlestream, offset, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature size to bundle");
		goto out;
	}


	res = TRUE;
out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	return res;
}

gboolean check_bundle(const gchar *bundlename, gsize *size, GError **error) {
	GError *ierror = NULL;
	GBytes *sig = NULL;
	GFile *bundlefile = NULL;
	GFileInputStream *bundlestream = NULL;
	guint64 sigsize;
	goffset offset;
	gboolean res = FALSE;

	if (!r_context()->config->keyring_path) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "No keyring file provided");
		goto out;
	}

	g_message("Reading bundle: %s", bundlename);

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_read(bundlefile, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for reading");
		goto out;
	}

	offset = sizeof(sigsize);
	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      -offset, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle");
		goto out;
	}
	offset = g_seekable_tell((GSeekable *)bundlestream);

	res = input_stream_read_uint64_all(G_INPUT_STREAM(bundlestream),
			                   &sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to read signature size from bundle");
		goto out;
	}

	offset -= sigsize;

	if (size)
		*size = offset;

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      offset, G_SEEK_SET, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to start of bundle signature");
		goto out;
	}

	res = input_stream_read_bytes_all(G_INPUT_STREAM(bundlestream),
			                  &sig, sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to read signature from bundle");
		goto out;
	}

	g_message("Verifying bundle... ");
	/* the squashfs image size is in offset */
	res = cms_verify_file(bundlename, sig, offset, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	return res;
}

gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir, gboolean verify, GError **error) {
	GError *ierror = NULL;
	gsize size;
	gboolean res = FALSE;

	if (verify) {
		res = check_bundle(bundlename, &size, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = check_bundle(bundlename, &size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = unsquashfs(bundlename, outputdir, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean extract_file_from_bundle(const gchar *bundlename, const gchar *outputdir, const gchar *file, gboolean verify, GError **error) {
	GError *ierror = NULL;
	gsize size;
	gboolean res = FALSE;

	if (verify) {
		res = check_bundle(bundlename, &size, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = unsquashfs(bundlename, outputdir, file, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean mount_bundle(const gchar *bundlename, const gchar *mountpoint, gboolean verify, GError **error) {
	GError *ierror = NULL;
	gsize size;
	gboolean res = FALSE;

	if (verify) {
		res = check_bundle(bundlename, &size, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = r_mount_loop(bundlename, mountpoint, size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean umount_bundle(const gchar *bundlename, GError **error) {
	GError *ierror = NULL;
	gboolean res = FALSE;

	res = r_umount(bundlename, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}
