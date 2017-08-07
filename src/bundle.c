#include <config.h>

#include <gio/gio.h>

#include "bundle.h"
#include "context.h"
#include "mount.h"
#include "signature.h"

GQuark
r_bundle_error_quark (void)
{
  return g_quark_from_static_string ("r-bundle-error-quark");
}

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir, GError **error) {
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	r_context_begin_step("mksquashfs", "Creating squashfs", 0);

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
				"Failed to start mksquashfs: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run mksquashfs: ");
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("mksquashfs", res);
	return res;
}

static gboolean unsquashfs(const gchar *bundlename, const gchar *contentdir, const gchar *extractfile, GError **error) {
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(7, g_free);

	r_context_begin_step("unsquashfs", "Uncompressing squashfs", 0);

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
				"Failed to start unsquashfs: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run unsquashfs: ");
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("unsquashfs", res);
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
	void *buffer = NULL;
	gsize bytes_read;
	gboolean res;

	g_assert_cmpint(count, !=, 0);

	buffer = g_malloc0(count);

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
				"failed signing bundle: ");
		res = FALSE;
		goto out;
	}

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_append_to(bundlefile, G_FILE_CREATE_NONE, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for appending: ");
		res = FALSE;
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      0, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		goto out;
	}

	offset = g_seekable_tell((GSeekable *)bundlestream);
	res = output_stream_write_bytes_all((GOutputStream *)bundlestream, sig, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature to bundle: ");
		goto out;
	}


	offset = g_seekable_tell((GSeekable *)bundlestream) - offset;
	res = output_stream_write_uint64_all((GOutputStream *)bundlestream, offset, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature size to bundle: ");
		goto out;
	}

out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	return res;
}

gboolean check_bundle(const gchar *bundlename, gsize *size, gboolean verify, GError **error) {
	GError *ierror = NULL;
	GBytes *sig = NULL;
	GFile *bundlefile = NULL;
	GFileInputStream *bundlestream = NULL;
	guint64 sigsize;
	goffset offset;
	gboolean res = FALSE;

	r_context_begin_step("check_bundle", "Checking bundle", verify);

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
				"failed to open bundle for reading: ");
		goto out;
	}

	offset = sizeof(sigsize);
	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			      -offset, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		goto out;
	}
	offset = g_seekable_tell((GSeekable *)bundlestream);

	res = input_stream_read_uint64_all(G_INPUT_STREAM(bundlestream),
			                   &sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to read signature size from bundle: ");
		goto out;
	}

	if (sigsize == 0) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"signature size is 0");
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should be smaller than bundle size */
	if (sigsize > (guint64)offset) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"signature size (%"G_GUINT64_FORMAT") exceeds bundle size", sigsize);
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should be smaller than 64kiB */
	if (sigsize > 0x4000000) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"signature size (%"G_GUINT64_FORMAT") exceeds 64KiB", sigsize);
		res = FALSE;
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
				"failed to seek to start of bundle signature: ");
		goto out;
	}

	res = input_stream_read_bytes_all(G_INPUT_STREAM(bundlestream),
			                  &sig, sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to read signature from bundle: ");
		goto out;
	}

	if (verify) {
		g_message("Verifying bundle... ");
		/* the squashfs image size is in offset */
		res = cms_verify_file(bundlename, sig, offset, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = TRUE;
out:
	g_clear_object(&bundlestream);
	g_clear_object(&bundlefile);
	g_clear_pointer(&sig, g_bytes_unref);
	r_context_end_step("check_bundle", res);
	return res;
}

gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir, gboolean verify, GError **error) {
	GError *ierror = NULL;
	gsize size;
	gboolean res = FALSE;

	r_context_begin_step("extract_bundle", "Extracting bundle", 2);

	res = check_bundle(bundlename, &size, verify, &ierror);
	if (!res) {
		if (g_error_matches(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE)) {
			g_propagate_prefixed_error(error, ierror, "Invalid Bundle: ");
		} else {
			g_propagate_error(error, ierror);
		}
		goto out;
	}

	res = unsquashfs(bundlename, outputdir, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("extract_bundle", res);
	return res;
}

gboolean extract_file_from_bundle(const gchar *bundlename, const gchar *outputdir, const gchar *file, gboolean verify, GError **error) {
	GError *ierror = NULL;
	gsize size;
	gboolean res = FALSE;

	if (verify) {
		res = check_bundle(bundlename, &size, verify, &ierror);
		if (!res) {
			if (g_error_matches(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE)) {
				g_propagate_prefixed_error(error, ierror, "Invalid Bundle: ");
			} else {
				g_propagate_error(error, ierror);
			}
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

	res = check_bundle(bundlename, &size, verify, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
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
