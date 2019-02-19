#include <errno.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <string.h>

#include "bundle.h"
#include "context.h"
#include "mount.h"
#include "signature.h"
#include "utils.h"
#include "network.h"

GQuark
r_bundle_error_quark(void)
{
	return g_quark_from_static_string("r-bundle-error-quark");
}

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	r_context_begin_step("mksquashfs", "Creating squashfs", 0);

	if (g_file_test(bundlename, G_FILE_TEST_EXISTS)) {
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

static gboolean unsquashfs(const gchar *bundlename, const gchar *contentdir, const gchar *extractfile, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
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

	r_debug_subprocess(args);
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

static gboolean casync_make_arch(const gchar *idxpath, const gchar *contentpath, const gchar *store, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(15, g_free);
	GPtrArray *iargs = g_ptr_array_new_full(15, g_free);
	const gchar *tmpdir = NULL;

	tmpdir = g_dir_make_tmp("arch-XXXXXX", &ierror);
	if (tmpdir == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to create tmp dir: ");
		goto out;
	}

	/* Inner process call (argument of fakroot sh -c) */
	g_ptr_array_add(iargs, g_strdup("tar"));
	g_ptr_array_add(iargs, g_strdup("xf"));
	g_ptr_array_add(iargs, g_strdup(contentpath));
	g_ptr_array_add(iargs, g_strdup("-C"));
	g_ptr_array_add(iargs, g_strdup(tmpdir));
	g_ptr_array_add(iargs, g_strdup("--numeric-owner"));
	g_ptr_array_add(iargs, g_strdup("&&"));
	g_ptr_array_add(iargs, g_strdup("casync"));
	g_ptr_array_add(iargs, g_strdup("make"));
	g_ptr_array_add(iargs, g_strdup("--with=unix"));
	g_ptr_array_add(iargs, g_strdup(idxpath));
	g_ptr_array_add(iargs, g_strdup(tmpdir));
	if (store) {
		g_ptr_array_add(iargs, g_strdup("--store"));
		g_ptr_array_add(iargs, g_strdup(store));
	}
	g_ptr_array_add(iargs, NULL);

	/* Outer process calll */
	g_ptr_array_add(args, g_strdup("fakeroot"));
	g_ptr_array_add(args, g_strdup("sh"));
	g_ptr_array_add(args, g_strdup("-c"));
	g_ptr_array_add(args, g_strjoinv(" ", (gchar**) g_ptr_array_free(iargs, FALSE)));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start casync: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run casync: ");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean casync_make_blob(const gchar *idxpath, const gchar *contentpath, const gchar *store, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("casync"));
	g_ptr_array_add(args, g_strdup("make"));
	g_ptr_array_add(args, g_strdup(idxpath));
	g_ptr_array_add(args, g_strdup(contentpath));
	if (store) {
		g_ptr_array_add(args, g_strdup("--store"));
		g_ptr_array_add(args, g_strdup(store));
	}
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start casync: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run casync: ");
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

#define SQUASHFS_MAGIC			0x73717368

/* Attempts to read and verify the squashfs magic to verify having a valid bundle */
static gboolean input_stream_check_bundle_identifier(GInputStream *stream, GError **error)
{
	GError *ierror = NULL;
	guint32 squashfs_id;
	gboolean res;
	gsize bytes_read;

	res = g_input_stream_read_all(stream, &squashfs_id, sizeof(squashfs_id), &bytes_read, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (bytes_read != sizeof(squashfs_id)) {
		g_set_error(error,
				G_IO_ERROR,
				G_IO_ERROR_PARTIAL_INPUT,
				"Only %"G_GSIZE_FORMAT " of %zu bytes read",
				bytes_read,
				sizeof(squashfs_id));
		return FALSE;
	}

	if (squashfs_id != SQUASHFS_MAGIC) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_IDENTIFIER, "Invalid identifier. Did you pass a valid RAUC bundle?");
		return FALSE;
	}

	return TRUE;
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
	g_autofree void *buffer = NULL;
	gsize bytes_read;
	gboolean res;

	g_assert_cmpint(count, !=, 0);

	buffer = g_malloc0(count);

	res = g_input_stream_read_all(stream, buffer, count, &bytes_read,
			cancellable, error);
	if (!res) {
		return res;
	}
	g_assert(bytes_read == count);
	*bytes = g_bytes_new_take(g_steal_pointer(&buffer), count);
	return TRUE;
}

static gboolean sign_bundle(const gchar *bundlename, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GBytes) sig = NULL;
	g_autoptr(GFile) bundlefile = NULL;
	g_autoptr(GFileOutputStream) bundlestream = NULL;
	guint64 offset;

	g_assert_nonnull(r_context()->certpath);
	g_assert_nonnull(r_context()->keypath);

	sig = cms_sign_file(bundlename,
			r_context()->certpath,
			r_context()->keypath,
			r_context()->intermediatepaths,
			&ierror);
	if (sig == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed signing bundle: ");
		return FALSE;
	}

	bundlefile = g_file_new_for_path(bundlename);
	bundlestream = g_file_append_to(bundlefile, G_FILE_CREATE_NONE, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for appending: ");
		return FALSE;
	}

	if (!g_seekable_seek(G_SEEKABLE(bundlestream),
			0, G_SEEK_END, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		return FALSE;
	}

	offset = g_seekable_tell((GSeekable *)bundlestream);
	if (!output_stream_write_bytes_all((GOutputStream *)bundlestream, sig, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature to bundle: ");
		return FALSE;
	}


	offset = g_seekable_tell((GSeekable *)bundlestream) - offset;
	if (!output_stream_write_uint64_all((GOutputStream *)bundlestream, offset, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature size to bundle: ");
		return FALSE;
	}

	return TRUE;
}

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	res = mksquashfs(bundlename, contentdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = sign_bundle(bundlename, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		g_remove(bundlename);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean truncate_bundle(const gchar *inpath, const gchar *outpath, gsize size, GError **error)
{
	g_autoptr(GFile) infile = NULL;
	g_autoptr(GFile) outfile = NULL;
	g_autoptr(GFileInputStream) instream = NULL;
	g_autoptr(GFileOutputStream) outstream = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	gssize ssize;

	infile = g_file_new_for_path(inpath);
	outfile = g_file_new_for_path(outpath);

	instream = g_file_read(infile, NULL, &ierror);
	if (instream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for reading: ");
		res = FALSE;
		goto out;
	}
	outstream = g_file_create(outfile, G_FILE_CREATE_NONE, NULL,
			&ierror);
	if (outstream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for writing: ");
		res = FALSE;
		goto out;
	}

	ssize = g_output_stream_splice(
			(GOutputStream*)outstream,
			(GInputStream*)instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
			NULL, &ierror);
	if (ssize == -1) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto out;
	}

	res = g_seekable_truncate(G_SEEKABLE(outstream), size, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean resign_bundle(RaucBundle *bundle, const gchar *outpath, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);

	res = truncate_bundle(bundle->path, outpath, bundle->size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = sign_bundle(outpath, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		g_remove(outpath);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean image_is_archive(RaucImage* image)
{
	if (g_pattern_match_simple("*.tar*", image->filename) ||
	    g_pattern_match_simple("*.catar", image->filename)) {
		return TRUE;
	}

	return FALSE;
}

static gboolean convert_to_casync_bundle(RaucBundle *bundle, const gchar *outbundle, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *contentdir = NULL;
	g_autofree gchar *mfpath = NULL;
	g_autofree gchar *storepath = NULL;
	gchar *basepath = NULL;
	g_autoptr(RaucManifest) manifest = NULL;

	g_return_val_if_fail(bundle, FALSE);
	g_return_val_if_fail(outbundle, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	basepath = g_strndup(outbundle, strlen(outbundle) - 6);
	storepath = g_strconcat(basepath, ".castr", NULL);
	g_free(basepath);

	/* Assure bundle destination path doe not already exist */
	if (g_file_test(outbundle, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "Destination bundle '%s' already exists", outbundle);
		res = FALSE;
		goto out;
	}

	if (g_file_test(storepath, G_FILE_TEST_EXISTS)) {
		g_warning("Store path '%s' already exists, appending new chunks", outbundle);
	}

	/* Set up tmp dir for conversion */
	tmpdir = g_dir_make_tmp("rauc-casync-XXXXXX", &ierror);
	if (tmpdir == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to create tmp dir: ");
		res = FALSE;
		goto out;
	}

	contentdir = g_build_filename(tmpdir, "content", NULL);
	mfpath = g_build_filename(contentdir, "manifest.raucm", NULL);

	/* Extract input bundle to content/ dir */
	res = extract_bundle(bundle, contentdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* Load manifest from content/ dir */
	res = load_manifest_file(mfpath, &manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* Iterate over each image and convert */
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;
		g_autofree gchar *imgpath = NULL;
		g_autofree gchar *idxfile = NULL;
		g_autofree gchar *idxpath = NULL;

		imgpath = g_build_filename(contentdir, image->filename, NULL);

		if (image_is_archive(image)) {
			idxfile = g_strconcat(image->filename, ".caidx", NULL);
			idxpath = g_build_filename(contentdir, idxfile, NULL);

			g_message("Converting %s to directory tree idx %s", image->filename, idxfile);

			res = casync_make_arch(idxpath, imgpath, storepath, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
		} else {

			idxfile = g_strconcat(image->filename, ".caibx", NULL);
			idxpath = g_build_filename(contentdir, idxfile, NULL);

			g_message("Converting %s to blob idx %s", image->filename, idxfile);

			/* Generate index for content */
			res = casync_make_blob(idxpath, imgpath, storepath, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
		}

		/* Rewrite manifest filename */
		g_free(image->filename);
		image->filename = g_steal_pointer(&idxfile);

		/* Remove original file */
		if (g_remove(imgpath) != 0) {
			g_warning("Failed removing %s", imgpath);
		}
	}

	/* Rewrite manifest to content/ dir */
	res = save_manifest_file(mfpath, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = create_bundle(outbundle, contentdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	/* Remove temporary bundle creation directory */
	if (tmpdir)
		rm_tree(tmpdir, NULL);
	return res;
}

gboolean create_casync_bundle(RaucBundle *bundle, const gchar *outbundle, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	res = convert_to_casync_bundle(bundle, outbundle, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = sign_bundle(outbundle, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean is_remote_scheme(const gchar *scheme)
{
	return (g_strcmp0(scheme, "http") == 0) ||
	       (g_strcmp0(scheme, "https") == 0) ||
	       (g_strcmp0(scheme, "sftp") == 0) ||
	       (g_strcmp0(scheme, "ftp") == 0);
}

gboolean check_bundle(const gchar *bundlename, RaucBundle **bundle, gboolean verify, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GFile) bundlefile = NULL;
	g_autoptr(GFileInputStream) bundlestream = NULL;
	guint64 sigsize;
	goffset offset;
	gboolean res = FALSE;
	g_autoptr(RaucBundle) ibundle = g_new0(RaucBundle, 1);
	gchar *bundlescheme = NULL;

	g_return_val_if_fail(bundle == NULL || *bundle == NULL, FALSE);

	r_context_begin_step("check_bundle", "Checking bundle", verify);

	/* Download Bundle to temporary location if remote URI is given */
	bundlescheme = g_uri_parse_scheme(bundlename);
	if (is_remote_scheme(bundlescheme)) {
#if ENABLE_NETWORK
		ibundle->origpath = g_strdup(bundlename);
		ibundle->path = g_build_filename(g_get_tmp_dir(), "_download.raucb", NULL);

		g_message("Remote URI detected, downloading bundle to %s...", ibundle->path);
		res = download_file(ibundle->path, ibundle->origpath, r_context()->config->max_bundle_download_size, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Failed to download bundle %s: ", ibundle->origpath);
			goto out;
		}
		g_debug("Downloaded temp bundle to %s", ibundle->path);
#else
		g_warning("Mounting remote bundle not supported, recompile with --enable-network");
#endif
	} else {
		ibundle->path = g_strdup(bundlename);
	}

	/* Determine store path for casync, defaults to bundle */
	if (r_context()->config->store_path) {
		ibundle->storepath = r_context()->config->store_path;
	} else {
		gchar *strprfx;

		if (ibundle->origpath)
			strprfx = g_strndup(ibundle->origpath, strlen(ibundle->origpath) - 6);
		else
			strprfx = g_strndup(ibundle->path, strlen(ibundle->path) - 6);
		ibundle->storepath = g_strconcat(strprfx, ".castr", NULL);

		g_free(strprfx);
	}

	if (verify && !r_context()->config->keyring_path && !r_context()->config->keyring_directory) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_KEYRING, "No keyring file or directory provided");
		res = FALSE;
		goto out;
	}

	g_message("Reading bundle: %s", ibundle->path);

	bundlefile = g_file_new_for_path(ibundle->path);
	bundlestream = g_file_read(bundlefile, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to open bundle for reading: ");
		res = FALSE;
		goto out;
	}

	res = input_stream_check_bundle_identifier(G_INPUT_STREAM(bundlestream), &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to check bundle identifier: ");
		goto out;
	}

	offset = sizeof(sigsize);
	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			-offset, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to seek to end of bundle: ");
		goto out;
	}
	offset = g_seekable_tell((GSeekable *)bundlestream);

	res = input_stream_read_uint64_all(G_INPUT_STREAM(bundlestream),
			&sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read signature size from bundle: ");
		goto out;
	}

	if (sigsize == 0) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size is 0");
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should be smaller than bundle size */
	if (sigsize > (guint64)offset) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size (%"G_GUINT64_FORMAT ") exceeds bundle size", sigsize);
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should be smaller than 64kiB */
	if (sigsize > 0x4000000) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size (%"G_GUINT64_FORMAT ") exceeds 64KiB", sigsize);
		res = FALSE;
		goto out;
	}

	offset -= sigsize;

	ibundle->size = offset;

	res = g_seekable_seek(G_SEEKABLE(bundlestream),
			offset, G_SEEK_SET, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to seek to start of bundle signature: ");
		goto out;
	}

	res = input_stream_read_bytes_all(G_INPUT_STREAM(bundlestream),
			&ibundle->sigdata, sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read signature from bundle: ");
		goto out;
	}

	if (verify) {
		CMS_ContentInfo *cms = NULL;
		X509_STORE *store = NULL;

		g_message("Verifying bundle... ");
		/* the squashfs image size is in offset */
		res = cms_verify_file(ibundle->path, ibundle->sigdata, offset, &cms, &store, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}

		res = cms_get_cert_chain(cms, store, &ibundle->verified_chain, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}

		X509_STORE_free(store);
		CMS_ContentInfo_free(cms);
	}

	if (bundle)
		*bundle = g_steal_pointer(&ibundle);

	res = TRUE;
out:
	r_context_end_step("check_bundle", res);
	return res;
}

gboolean extract_bundle(RaucBundle *bundle, const gchar *outputdir, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);

	r_context_begin_step("extract_bundle", "Extracting bundle", 1);

	res = unsquashfs(bundle->path, outputdir, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("extract_bundle", res);
	return res;
}

gboolean extract_file_from_bundle(RaucBundle *bundle, const gchar *outputdir, const gchar *file, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);

	res = unsquashfs(bundle->path, outputdir, file, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean mount_bundle(RaucBundle *bundle, GError **error)
{
	gchar *mount_point = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_null(bundle->mount_point);

	mount_point = r_create_mount_point("bundle", &ierror);
	if (!mount_point) {
		res = FALSE;
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed creating mount point: ");
		goto out;
	}

	g_message("Mounting bundle '%s' to '%s'", bundle->path, mount_point);

	res = r_mount_loop(bundle->path, mount_point, bundle->size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		g_rmdir(mount_point);
		g_free(mount_point);
		goto out;
	}

	bundle->mount_point = mount_point;

	res = TRUE;
out:
	return res;
}

gboolean umount_bundle(RaucBundle *bundle, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_nonnull(bundle->mount_point);

	res = r_umount(bundle->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	g_rmdir(bundle->mount_point);
	g_clear_pointer(&bundle->mount_point, g_free);

	res = TRUE;
out:
	return res;
}

void free_bundle(RaucBundle *bundle)
{
	g_return_if_fail(bundle);

	/* In case of a temporary donwload artifact, remove it. */
	if (bundle->origpath)
		if (g_remove(bundle->path) == -1) {
			g_warning("Failed removing download artifact %s: %s\n", bundle->path, g_strerror(errno));
		}

	g_free(bundle->path);
	g_bytes_unref(bundle->sigdata);
	g_free(bundle->mount_point);
	if (bundle->verified_chain)
		sk_X509_pop_free(bundle->verified_chain, X509_free);
	g_free(bundle);
}
