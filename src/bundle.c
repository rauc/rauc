#include <errno.h>
#include <gio/gio.h>
#include <gio/gfiledescriptorbased.h>
#include <gio/gunixmounts.h>
#include <glib/gstdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <unistd.h>

#include "bundle.h"
#include "config_file.h"
#include "context.h"
#include "crypt.h"
#include "manifest.h"
#include "mount.h"
#include "signature.h"
#include "utils.h"
#include "network.h"
#include "dm.h"
#include "verity_hash.h"
#include "nbd.h"
#include "hash_index.h"

/* from statfs(2) man page, as linux/magic.h may not have all of them */
#ifndef AFS_SUPER_MAGIC
#define AFS_SUPER_MAGIC 0x5346414f
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683e
#endif
#ifndef CRAMFS_MAGIC
#define CRAMFS_MAGIC 0x28cd3d45
#endif
#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC 0x2011bab0
#endif
#ifndef EXT4_SUPER_MAGIC /* also covers ext2/3 */
#define EXT4_SUPER_MAGIC 0xef53
#endif
#ifndef F2FS_SUPER_MAGIC
#define F2FS_SUPER_MAGIC 0xf2f52010
#endif
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
#ifndef HOSTFS_SUPER_MAGIC
#define HOSTFS_SUPER_MAGIC 0x00c0ffee
#endif
#ifndef ISOFS_SUPER_MAGIC
#define ISOFS_SUPER_MAGIC 0x9660
#endif
#ifndef JFFS2_SUPER_MAGIC
#define JFFS2_SUPER_MAGIC 0x72b6
#endif
#ifndef MSDOS_SUPER_MAGIC
#define MSDOS_SUPER_MAGIC 0x4d44
#endif
#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC 0x6969
#endif
#ifndef NTFS_SB_MAGIC
#define NTFS_SB_MAGIC 0x5346544e
#endif
#ifndef NTFS3_SUPER_MAGIC
#define NTFS3_SUPER_MAGIC 0x7366746e
#endif
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif
#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC 0x858458f6
#endif
#ifndef ROMFS_MAGIC
#define ROMFS_MAGIC 0x7275
#endif
#ifndef SQUASHFS_MAGIC
#define SQUASHFS_MAGIC 0x73717368
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif
#ifndef UBIFS_SUPER_MAGIC
#define UBIFS_SUPER_MAGIC 0x24051905
#endif
#ifndef UDF_SUPER_MAGIC
#define UDF_SUPER_MAGIC 0x15013346
#endif
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif
#ifndef ZFS_SUPER_MAGIC
/* Taken from https://github.com/openzfs/zfs/blob/master/include/sys/fs/zfs.h#L1198 */
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

GQuark
r_bundle_error_quark(void)
{
	return g_quark_from_static_string("r-bundle-error-quark");
}

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir, gboolean keep_metadata, const gchar *fakeroot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(7, g_free);

	g_return_val_if_fail(bundlename != NULL, FALSE);
	g_return_val_if_fail(contentdir != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("mksquashfs", "Creating squashfs", 0);

	if (g_file_test(bundlename, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", bundlename);
		goto out;
	}

	r_fakeroot_add_args(args, fakeroot);

	g_ptr_array_add(args, g_strdup("mksquashfs"));
	g_ptr_array_add(args, g_strdup(contentdir));
	g_ptr_array_add(args, g_strdup(bundlename));
	g_ptr_array_add(args, g_strdup("-noappend"));
	g_ptr_array_add(args, g_strdup("-no-progress"));
	if (!keep_metadata) {
		g_ptr_array_add(args, g_strdup("-all-root"));
		g_ptr_array_add(args, g_strdup("-no-xattrs"));
	}
	g_ptr_array_add(args, g_strdup("-quiet"));

	if (r_context()->mksquashfs_args != NULL) {
		g_auto(GStrv) mksquashfs_argvp = NULL;
		res = g_shell_parse_argv(r_context()->mksquashfs_args, NULL, &mksquashfs_argvp, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to parse mksquashfs extra args: ");
			goto out;
		}
		r_ptr_array_addv(args, mksquashfs_argvp, TRUE);
	}
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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

static gboolean unsquashfs(gint fd, const gchar *contentdir, const gchar *extractfile, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(7, g_free);

	g_return_val_if_fail(contentdir != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("unsquashfs", "Uncompressing squashfs", 0);

	g_ptr_array_add(args, g_strdup("unsquashfs"));
	g_ptr_array_add(args, g_strdup("-dest"));
	g_ptr_array_add(args, g_strdup(contentdir));
	g_ptr_array_add(args, g_strdup_printf("/proc/%jd/fd/%d", (intmax_t)getpid(), fd));

	if (extractfile) {
		g_ptr_array_add(args, g_strdup(extractfile));
	}

	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
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

static gboolean check_pseudo_active(void)
{
	if (!g_getenv("PSEUDO_LOCALSTATEDIR"))
		return FALSE;

	const gchar *tmp = g_getenv("PSEUDO_DISABLED");
	if (g_strcmp0(tmp, "1") == 0)
		return FALSE;

	return TRUE;
}

static gboolean casync_make_blob(const gchar *idxpath, const gchar *contentpath, const gchar *store, GError **error);

static gboolean casync_make_arch(const gchar *idxpath, const gchar *contentpath, const gchar *store, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);
	g_autoptr(GPtrArray) iargs = g_ptr_array_new_full(15, g_free);
	g_autofree gchar *tmpdir = NULL;

	g_return_val_if_fail(idxpath != NULL, FALSE);
	g_return_val_if_fail(contentpath != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->use_desync) {
		/* Desync is able to handle tar and catar archives directly, there is
		 * no need to manually extract them. */
		return casync_make_blob(idxpath, contentpath, store, error);
	}

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

	if (r_context()->casync_args != NULL) {
		g_auto(GStrv) casync_argvp = NULL;
		res = g_shell_parse_argv(r_context()->casync_args, NULL, &casync_argvp, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to parse casync extra args: ");
			goto out;
		}
		r_ptr_array_addv(iargs, casync_argvp, TRUE);
	}
	g_ptr_array_add(iargs, NULL);

	/* Outer process call */
	if (!check_pseudo_active()) {
		g_ptr_array_add(args, g_strdup("fakeroot"));
	}
	g_ptr_array_add(args, g_strdup("sh"));
	g_ptr_array_add(args, g_strdup("-c"));
	g_ptr_array_add(args, g_strjoinv(" ", (gchar**) iargs->pdata));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
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
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_return_val_if_fail(idxpath != NULL, FALSE);
	g_return_val_if_fail(contentpath != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->use_desync) {
		g_autofree gchar *desync_store = NULL;

		if (store) {
			desync_store = g_strdup(store);
		} else {
			/* With casync the default store is a directory called "default.castr",
			 * instead, with desync, the default is to skip the store altogether.
			 * Imitate casync behavior by using "default.castr" if a store was not
			 * provided. */
			desync_store = g_build_filename(g_path_get_dirname(idxpath), "default.castr", NULL);
		}

		/* Desync fails if the store directory is missing. */
		if (!g_file_test(desync_store, G_FILE_TEST_IS_DIR)) {
			gint ret_mkdir;
			ret_mkdir = g_mkdir_with_parents(desync_store, 0755);

			if (ret_mkdir != 0) {
				int err = errno;
				g_set_error(
						error,
						G_FILE_ERROR,
						g_file_error_from_errno(err),
						"Failed creating Desync store directory '%s': %s",
						desync_store,
						g_strerror(err));
				res = FALSE;
				goto out;
			}
		}

		g_ptr_array_add(args, g_strdup("desync"));
		g_ptr_array_add(args, g_strdup("make"));
		g_ptr_array_add(args, g_strdup("--store"));
		g_ptr_array_add(args, g_steal_pointer(&desync_store));
		g_ptr_array_add(args, g_strdup(idxpath));
		g_ptr_array_add(args, g_strdup(contentpath));
	} else {
		g_ptr_array_add(args, g_strdup("casync"));
		g_ptr_array_add(args, g_strdup("make"));
		g_ptr_array_add(args, g_strdup(idxpath));
		g_ptr_array_add(args, g_strdup(contentpath));
		if (store) {
			g_ptr_array_add(args, g_strdup("--store"));
			g_ptr_array_add(args, g_strdup(store));
		}
	}

	if (r_context()->casync_args != NULL) {
		g_auto(GStrv) casync_argvp = NULL;
		res = g_shell_parse_argv(r_context()->casync_args, NULL, &casync_argvp, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to parse casync extra args: ");
			goto out;
		}
		r_ptr_array_addv(args, casync_argvp, TRUE);
	}
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
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

static gboolean image_is_archive(RaucImage* image)
{
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(image->filename, FALSE);

	if (g_pattern_match_simple("*.tar*", image->filename) ||
	    g_pattern_match_simple("*.catar", image->filename)) {
		return TRUE;
	}

	return FALSE;
}

static gboolean generate_adaptive_data(RaucManifest *manifest, const gchar *dir, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(dir, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		g_autofree gchar *imagepath = g_build_filename(dir, image->filename, NULL);

		if (!image->adaptive)
			continue;

		for (gchar **method = image->adaptive; *method != NULL; method++) {
			if (g_str_equal(*method, "block-hash-index")) {
				/* Use a filename of bundle/<image-name>.block-hash-index. */
				g_autofree gchar *indexname = g_strconcat(image->filename, ".block-hash-index", NULL);
				g_autofree gchar *indexpath = g_build_filename(dir, indexname, NULL);
				g_autoptr(RaucHashIndex) index = NULL;
				g_auto(filedesc) fd = -1;

				if (image_is_archive(image)) {
					g_warning("Generating block hash index requires a block device image but %s looks like an archive", image->filename);
				}

				fd = g_open(imagepath, O_RDONLY | O_CLOEXEC);
				if (fd < 0) {
					int err = errno;
					g_set_error(
							error,
							G_IO_ERROR,
							g_io_error_from_errno(err),
							"Failed to open image: %s", image->filename);
					return FALSE;
				}

				index = r_hash_index_open("image", fd, NULL, &ierror);
				if (!index) {
					g_propagate_prefixed_error(
							error,
							ierror,
							"Failed to generate hash index for %s: ", image->filename);
					return FALSE;
				}

				if (!r_hash_index_export(index, indexpath, &ierror)) {
					g_propagate_prefixed_error(
							error,
							ierror,
							"Failed to write hash index for %s: ", image->filename);
					return FALSE;
				}

				g_debug("Created block-hash-index for image %s", image->filename);
			} else if (g_str_equal(*method, "adaptive-test-method")) {
				g_debug("Ignoring adaptive-test-method for image %s", image->filename);
			} else {
				g_set_error(
						error,
						R_BUNDLE_ERROR,
						R_BUNDLE_ERROR_PAYLOAD,
						"Unsupported adaptive method: %s", *method);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gchar *convert_tar_extract(RaucImage *image, const gchar *dir, const gchar *fakeroot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(image, NULL);
	g_return_val_if_fail(dir, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autofree gchar *file_path = g_build_filename(dir, image->filename, NULL);
	g_autofree gchar *converted = g_strdup_printf("%s.extracted", image->filename);
	g_autofree gchar *converted_path = g_build_filename(dir, converted, NULL);

	if (g_mkdir(converted_path, S_IRWXU)) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"failed to create directory '%s': %s", converted_path, g_strerror(err));
		return NULL;
	}

	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);
	r_fakeroot_add_args(args, fakeroot);

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("--numeric-owner"));
	// TODO add support for --acl --selinux --xattrs via fakeroot or pseudo
	g_ptr_array_add(args, g_strdup("-xf"));
	g_ptr_array_add(args, g_strdup(file_path));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(converted_path));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "failed to run tar extract: ");
		return NULL;
	}

	return g_steal_pointer(&converted);
}

#if ENABLE_COMPOSEFS == 1
static gchar *convert_composefs(RaucImage *image, const gchar *dir, const gchar *tar_extracted_path, const gchar *fakeroot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(image, NULL);
	g_return_val_if_fail(dir, NULL);
	g_return_val_if_fail(tar_extracted_path, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autofree gchar *converted = g_strdup_printf("%s.cfs", image->filename);
	g_autofree gchar *converted_path = g_build_filename(dir, converted, NULL);
	g_autofree gchar *converted_image_path = g_build_filename(converted_path, "image.cfs", NULL);
	g_autofree gchar *store_path = g_build_filename(dir, ".rauc-cfs-store", NULL);

	/* Create a directory in the bundle so we can keep additional metadata, like
	 * a signature over the image digest.
	 */
	if (g_mkdir(converted_path, S_IRWXU)) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"failed to create directory '%s': %s", converted_path, g_strerror(err));
		return NULL;
	}

	if (g_mkdir_with_parents(store_path, S_IRWXU)) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"failed to create directory '%s': %s", store_path, g_strerror(err));
		return NULL;
	}

	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);
	r_fakeroot_add_args(args, fakeroot);

	g_ptr_array_add(args, g_strdup("mkcomposefs"));
	g_ptr_array_add(args, g_strdup_printf("--digest-store=%s", store_path));
	/* TODO mkcomposefs fails to read xattrs from broken symlinks under pseudo. */
	g_ptr_array_add(args, g_strdup("--skip-xattrs"));
	g_ptr_array_add(args, g_strdup(tar_extracted_path));
	g_ptr_array_add(args, g_strdup(converted_image_path));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "failed to run mkcomposefs: ");
		return NULL;
	}

	return g_steal_pointer(&converted);
}
#endif

static gboolean convert_images(RaucManifest *manifest, const gchar *dir, const gchar *fakeroot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(dir, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;

		if (image->converted && image->converted->len == 0) {
			g_set_error(
					error,
					R_BUNDLE_ERROR,
					R_BUNDLE_ERROR_PAYLOAD,
					"Manifest already contains converted images for '%s'", image->slotclass);
			return FALSE;
		}

		if (!image->convert)
			continue;

		g_autofree gchar *tar_extracted = NULL;
		g_autofree gchar *tar_extracted_path = NULL;
		/* extract tar early if we need it for other outputs */
		if (g_strv_contains((const gchar * const *)image->convert, "tar-extract") ||
		    g_strv_contains((const gchar * const *)image->convert, "composefs")) {
			g_debug("extracting tar artifact image '%s'", image->filename);
			tar_extracted = convert_tar_extract(image, dir, fakeroot, &ierror);
			if (!tar_extracted) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
			tar_extracted_path = g_build_filename(dir, tar_extracted, NULL);
		}

		gboolean keep = FALSE;
		g_autoptr(GPtrArray) converted = g_ptr_array_new_with_free_func(g_free);
		for (gchar **method = image->convert; *method != NULL; method++) {
			gchar *converted_filename = NULL;
			if (g_str_equal(*method, "tar-extract")) {
				converted_filename = g_strdup(tar_extracted);
			} else if (g_str_equal(*method, "composefs")) {
#if ENABLE_COMPOSEFS == 1
				g_debug("converting '%s' to composefs image", tar_extracted_path);
				converted_filename = convert_composefs(image, dir, tar_extracted_path, fakeroot, &ierror);
				if (!converted_filename) {
					g_propagate_error(error, ierror);
					return FALSE;
				}
#else
				g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSUPPORTED,
						"Convert method 'composefs' not enabled, recompile with -Dcomposefs=enabled");
				return FALSE;
#endif
			} else if (g_str_equal(*method, "keep")) {
				g_debug("keeping input artifact image '%s'", image->filename);
				keep = TRUE;
				converted_filename = g_strdup(image->filename);
			} else {
				g_set_error(
						error,
						R_BUNDLE_ERROR,
						R_BUNDLE_ERROR_PAYLOAD,
						"Unsupported convert method: %s", *method);
				return FALSE;
			}

			g_assert(converted_filename != NULL);
			g_ptr_array_add(converted, converted_filename);
		}

		if (tar_extracted_path && !g_strv_contains((const gchar * const *)image->convert, "tar-extract")) {
			if (!rm_tree(tar_extracted_path, &ierror)) {
				g_propagate_prefixed_error(error, ierror, "Failed to remove files extracted from tar: ");
				return FALSE;
			}
		}

		if (!keep) {
			g_autofree gchar *file_path = g_build_filename(dir, image->filename, NULL);
			g_debug("removing input artifact image '%s' after conversion", image->filename);
			if (g_unlink(file_path) != 0) {
				int err = errno;
				g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
						"Failed to remove input artifact image after conversion '%s': %s\n",
						file_path, g_strerror(errno));
				return FALSE;
			}
		}

		g_clear_pointer(&image->converted, g_ptr_array_unref);
		image->converted = g_steal_pointer(&converted);
	}

	return TRUE;
}

static gboolean output_stream_write_uint64_all(GOutputStream *stream,
		guint64 data,
		GCancellable *cancellable,
		GError **error)
{
	gsize bytes_written;

	data = GUINT64_TO_BE(data);
	if (!g_output_stream_write_all(stream, &data, sizeof(data), &bytes_written,
			cancellable, error))
		return FALSE;

	g_assert(bytes_written == sizeof(data));
	return TRUE;
}

static gboolean input_stream_read_uint64_all(GInputStream *stream,
		guint64 *data,
		GCancellable *cancellable,
		GError **error)
{
	guint64 tmp;
	gsize bytes_read;

	if (!g_input_stream_read_all(stream, &tmp, sizeof(tmp), &bytes_read,
			cancellable, error))
		return FALSE;

	g_assert(bytes_read == sizeof(tmp));
	*data = GUINT64_FROM_BE(tmp);
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
	gsize bytes_read;

	g_assert_cmpint(count, !=, 0);

	g_autofree void *buffer = g_malloc0(count);

	if (!g_input_stream_read_all(stream, buffer, count, &bytes_read,
			cancellable, error)) {
		return FALSE;
	}

	g_assert(bytes_read == count);
	*bytes = g_bytes_new_take(g_steal_pointer(&buffer), count);
	return TRUE;
}

static gboolean create_verity(const gchar *bundlename, RaucManifest *manifest, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundlename != NULL, FALSE);
	g_return_val_if_fail(manifest != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GFile) bundlefile = g_file_new_for_path(bundlename);
	g_autoptr(GFileIOStream) bundlestream = g_file_open_readwrite(bundlefile, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for signing: ");
		return FALSE;
	}

	GOutputStream *bundleoutstream = NULL; /* owned by the bundle stream */
	bundleoutstream = g_io_stream_get_output_stream(G_IO_STREAM(bundlestream));
	int bundlefd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(bundleoutstream));

	/* check we have a clean manifest */
	g_assert(manifest->bundle_verity_salt == NULL);
	g_assert(manifest->bundle_verity_hash == NULL);
	g_assert(manifest->bundle_verity_size == 0);

	if (!g_seekable_seek(G_SEEKABLE(bundlestream),
			0, G_SEEK_END, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		return FALSE;
	}

	guint64 offset = g_seekable_tell(G_SEEKABLE(bundlestream));
	g_debug("Payload size: %" G_GUINT64_FORMAT " bytes.", offset);
	/* dm-verity hash table generation */
	guint8 salt[32] = {0};
	if (RAND_bytes((unsigned char *)&salt, sizeof(salt)) != 1) {
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_VERITY,
				"failed to generate verity salt");
		return FALSE;
	}
	if (offset % 4096 != 0) {
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_VERITY,
				"squashfs size (%"G_GUINT64_FORMAT ") is not a multiple of 4096 bytes", offset);
		return FALSE;
	}
	if (offset <= 4096) {
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_VERITY,
				"squashfs size (%"G_GUINT64_FORMAT ") must be larger than 4096 bytes", offset);
		return FALSE;
	}

	guint8 hash[32] = {0};
	uint64_t combined_size = 0;
	if (r_verity_hash_create(bundlefd, offset/4096, &combined_size, hash, salt) != 0) {
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_VERITY,
				"failed to generate verity hash tree");
		return FALSE;
	}
	/* for a squashfs <= 4096 bytes, we don't have a hash table */
	g_assert(combined_size*4096 > (uint64_t)offset);
	guint64 verity_size = combined_size*4096 - offset;
	g_assert(verity_size % 4096 == 0);

	manifest->bundle_verity_salt = r_hex_encode(salt, sizeof(salt));
	manifest->bundle_verity_hash = r_hex_encode(hash, sizeof(hash));
	manifest->bundle_verity_size = verity_size;

	return TRUE;
}

static gboolean append_signature_to_bundle(const gchar *bundlename, GBytes *sig, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundlename, FALSE);
	g_return_val_if_fail(sig, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GFile) bundlefile = g_file_new_for_path(bundlename);
	g_autoptr(GFileIOStream) bundlestream = g_file_open_readwrite(bundlefile, NULL, &ierror);
	if (bundlestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for signing: ");
		return FALSE;
	}

	GOutputStream *bundleoutstream = NULL; /* owned by the bundle stream */
	bundleoutstream = g_io_stream_get_output_stream(G_IO_STREAM(bundlestream));

	if (!g_seekable_seek(G_SEEKABLE(bundlestream),
			0, G_SEEK_END, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		return FALSE;
	}

	guint64 offset = g_seekable_tell(G_SEEKABLE(bundlestream));
	g_debug("Signature offset: %" G_GUINT64_FORMAT " bytes.", offset);
	if (!output_stream_write_bytes_all(bundleoutstream, sig, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature to bundle: ");
		return FALSE;
	}

	offset = g_seekable_tell(G_SEEKABLE(bundlestream)) - offset;
	if (offset > DEFAULT_MAX_BUNDLE_SIGNATURE_SIZE) {
		g_autofree gchar* formatted_sigsize = g_format_size_full(offset, G_FORMAT_SIZE_IEC_UNITS);
		g_autofree gchar* formatted_defaultsize = g_format_size_full(DEFAULT_MAX_BUNDLE_SIGNATURE_SIZE, G_FORMAT_SIZE_IEC_UNITS);
		g_message("Resulting signature size of %s exceeds default of %s. Make sure to set 'max-bundle-signature-size' in your target's system.conf to a sufficiently high value.", formatted_sigsize, formatted_defaultsize);
	}
	if (!output_stream_write_uint64_all(bundleoutstream, offset, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to append signature size to bundle: ");
		return FALSE;
	}

	offset = g_seekable_tell(G_SEEKABLE(bundlestream));
	g_debug("Bundle size: %" G_GUINT64_FORMAT " bytes.", offset);

	return TRUE;
}

static GBytes *append_signature(GBytes *input_sig, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(input_sig, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_nonnull(r_context()->certpath);
	g_assert_nonnull(r_context()->keypath);

	g_autoptr(GBytes) output_sig = cms_append_signature(input_sig,
			r_context()->certpath,
			r_context()->keypath,
			r_context()->intermediatepaths,
			&ierror);
	if (output_sig == NULL) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return g_steal_pointer(&output_sig);
}

static GBytes *generate_bundle_signature(const gchar *bundlename, RaucManifest *manifest, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundlename, NULL);
	g_return_val_if_fail(manifest, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_assert_nonnull(r_context()->certpath);
	g_assert_nonnull(r_context()->keypath);

	g_autoptr(GBytes) sig = NULL;
	if (manifest->bundle_format == R_MANIFEST_FORMAT_PLAIN) {
		if (!check_manifest_internal(manifest, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"cannot sign bundle containing inconsistent manifest: ");
			return NULL;
		}

		sig = cms_sign_file(bundlename,
				r_context()->certpath,
				r_context()->keypath,
				r_context()->intermediatepaths,
				&ierror);
		if (sig == NULL) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to sign bundle: ");
			return NULL;
		}
	} else if ((manifest->bundle_format == R_MANIFEST_FORMAT_VERITY) || (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT)) {
		if (!check_manifest_external(manifest, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"cannot sign inconsistent manifest: ");
			return NULL;
		}

		sig = cms_sign_manifest(manifest,
				r_context()->certpath,
				r_context()->keypath,
				r_context()->intermediatepaths,
				&ierror);
		if (sig == NULL) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to sign manifest: ");
			return NULL;
		}
	} else {
		g_error("unsupported bundle format");
		return NULL;
	}

	return g_steal_pointer(&sig);
}

static gboolean sign_bundle(const gchar *bundlename, RaucManifest *manifest, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundlename, FALSE);
	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_nonnull(r_context()->certpath);
	g_assert_nonnull(r_context()->keypath);

	if ((manifest->bundle_format == R_MANIFEST_FORMAT_VERITY) || (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT)) {
		if (!create_verity(bundlename, manifest, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	g_autoptr(GBytes) sig = generate_bundle_signature(bundlename, manifest, &ierror);
	if (!sig) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!append_signature_to_bundle(bundlename, sig, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gchar* get_random_file_name(void)
{
	guint8 rand_bytes[8] = {0};

	if (RAND_bytes((unsigned char *)&rand_bytes, sizeof(rand_bytes)) != 1)
		g_error("Failed to generate random file name");

	return r_hex_encode(rand_bytes, sizeof(rand_bytes));
}

static gboolean encrypt_bundle_payload(const gchar *bundlepath, RaucManifest *manifest, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundlepath, FALSE);
	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_message("Encrypting bundle payload in aes-cbc-plain64 mode");

	g_autofree gchar* dirname = g_path_get_dirname(bundlepath);
	g_autofree gchar* tmpfilename = get_random_file_name();
	g_auto(RTempFile) encpath = g_build_filename(dirname, tmpfilename, NULL); /* remove on early return */

	/* check we have a clean manifest */
	g_assert(manifest->bundle_crypt_key == NULL);

	guint8 key[32] = {0};
	if (RAND_bytes((unsigned char *)&key, sizeof(key)) != 1) {
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_CRYPT,
				"Failed to generate crypt key");
		return FALSE;
	}

	if (!r_crypt_encrypt(bundlepath, encpath, key, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	manifest->bundle_crypt_key = r_hex_encode(key, sizeof(key));

	/* Uncomment for debugging purpose */
	//g_message("encrypted image saved as %s with key %s", encpath, manifest->bundle_crypt_key);

	if (g_rename(encpath, bundlepath) != 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Renaming %s to %s failed, aborting encryption: %s", encpath, bundlepath, g_strerror(err));
		return FALSE;
	}
	g_clear_pointer(&encpath, g_free); /* prevent removal */

	return TRUE;
}

static gboolean decrypt_bundle_payload(RaucBundle *bundle, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autofree gchar *tmpdir = NULL;
	g_autofree guint8 *key = NULL;
	g_autofree gchar* decpath = NULL;
	g_autoptr(GFile) decgfile = NULL;

	g_return_val_if_fail(bundle, FALSE);
	g_return_val_if_fail(bundle->manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", &ierror);
	if (tmpdir == NULL) {
		g_propagate_prefixed_error(error, ierror, "Failed to create tmp dir: ");
		res = FALSE;
		goto out;
	}
	decpath = g_strconcat(tmpdir, "decrypted.raucb", NULL);

	/* check we have a crypt key set in manifest */
	g_assert(bundle->manifest->bundle_crypt_key != NULL);

	/* Uncomment for debugging purpose */
	//g_message("Decrypting with key: %s", manifest->bundle_crypt_key);
	key = r_hex_decode(bundle->manifest->bundle_crypt_key, 32);
	g_assert(key);

	res = r_crypt_decrypt(bundle->path, decpath, key, bundle->size - bundle->manifest->bundle_verity_size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	g_message("decrypted image saved as %s", decpath);

	/* let bundle->stream point to decrypted bundle */
	g_object_unref(bundle->stream);
	decgfile = g_file_new_for_path(decpath);
	bundle->stream = G_INPUT_STREAM(g_file_read(decgfile, NULL, error));

out:
	/* Remove temporary bundle creation directory.
	 * RAUC will still have access to the decrypted bundle via the opened GFile */
	if (tmpdir) {
		g_autoptr(GError) tmperror = NULL;
		if (!rm_tree(tmpdir, &tmperror)) {
			g_warning("Failed to remove bundle decryption tmpdir %s: %s", tmpdir, tmperror->message);
		}
	}

	return res;
}

static gboolean check_workdir_content(const gchar *path, gboolean top_level, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *name = g_path_get_basename(path);

	/* It's not clear what absolute or relative symlinks (with slashes)
	 * in the bundle input should mean, so reject them. If you have a use
	 * case for this, contact us. */
	if (g_file_test(path, G_FILE_TEST_IS_SYMLINK)) {
		g_autofree gchar *link_target = g_file_read_link(path, &ierror);
		if (!link_target) {
			g_propagate_prefixed_error(error, ierror,
					"failed to read symlink in bundle contents (%s): ", name);
			return FALSE;
		}

		if (g_path_is_absolute(link_target)) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
					"absolute symlinks are not supported as bundle contents (%s)", name);
			return FALSE;
		}

		if (strchr(link_target, '/')) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
					"symlinks containing slashes are not supported as bundle contents (%s)", name);
			return FALSE;
		}

		/* Local symlinks in the same directory (containing no slashes) seem
		 * harmless and can be useful in special cases for backwards
		 * compatibility, so allow them. */

		return TRUE;
	}

	if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
		if (top_level && g_str_has_prefix(name, ".")) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
					"hidden directories are not supported as top-level bundle contents (%s)",
					name);
			return FALSE;
		}
		return TRUE;
	}

	if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
				"only regular files are supported as bundle contents (%s)", name);
		return FALSE;
	}

	return TRUE;
}

static gboolean link_contentdir_to_workdir(const gchar *contentdir, const gchar *workdir, gboolean top_dir, GError **error)
{
	GError *ierror = NULL;

	g_autoptr(GDir) dir = g_dir_open(contentdir, 0, &ierror);
	if (!dir) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	const gchar *name;
	while ((name = g_dir_read_name(dir))) {
		if (g_strcmp0(name, ".rauc-workdir") == 0)
			continue;

		g_autofree gchar *oldpath = g_build_filename(contentdir, name, NULL);
		if (!check_workdir_content(oldpath, top_dir, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		g_autofree gchar *newpath = g_build_filename(workdir, name, NULL);

		if (g_file_test(oldpath, G_FILE_TEST_IS_DIR)) {
			struct stat stat_data = {};
			if (g_stat(oldpath, &stat_data) < 0) {
				int err = errno;
				g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
						"failed to get file status for '%s': %s", oldpath, g_strerror(err));
				return FALSE;
			}
			if (g_mkdir(newpath, stat_data.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != 0) {
				int err = errno;
				g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
						"failed to create workdir '%s': %s", newpath, g_strerror(err));
				return FALSE;
			}

			if (!link_contentdir_to_workdir(oldpath, newpath, FALSE, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}

			continue;
		}

		if (link(oldpath, newpath) != 0) {
			int err = errno;
			g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
					"failed to hard-link file '%s' to workdir: %s", name, g_strerror(err));
			return FALSE;
		}
	}

	return TRUE;
}

static gchar *prepare_workdir(const gchar *contentdir, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar* workdir = NULL;

	g_return_val_if_fail(contentdir, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	/* This could be simplified with g_canonicalize_file() after bumping the
	 * glib requirement to 2.58. */
	if (g_path_is_absolute(contentdir)) {
		workdir = g_build_filename(contentdir, ".rauc-workdir", NULL);
	} else {
		g_autofree gchar* cwd = g_get_current_dir();
		workdir = g_build_filename(cwd, contentdir, ".rauc-workdir", NULL);
	}

	if (g_file_test(workdir, G_FILE_TEST_EXISTS)) {
		if (!rm_tree(workdir, &ierror)) {
			g_propagate_prefixed_error(error, ierror, "Failed to remove old workdir: ");
			return NULL;
		}
	}

	if (g_mkdir(workdir, 0700) != 0) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"failed to create the workdir '%s': %s", workdir, g_strerror(err));
		return NULL;
	}

	if (!link_contentdir_to_workdir(contentdir, workdir, TRUE, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return g_steal_pointer(&workdir);
}

static gboolean needs_fakeroot(const RaucManifest *manifest, gboolean *mksquashfs_metadata)
{
	g_return_val_if_fail(manifest != NULL, FALSE);
	g_return_val_if_fail(mksquashfs_metadata != NULL, FALSE);

	*mksquashfs_metadata = FALSE;

	gboolean may_need_fakeroot = FALSE;
	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;

		if (image->convert) {
			if (g_strv_contains((const gchar * const *)image->convert, "tar-extract")) {
				/* This produces files with metadata in the bundle itself. */
				*mksquashfs_metadata = TRUE;
				may_need_fakeroot = TRUE;
			}
			if (g_strv_contains((const gchar * const *)image->convert, "composefs")) {
				/* The metadata is stored in the cfs image. */
				may_need_fakeroot = TRUE;
			}
		}
	}

	if (!may_need_fakeroot)
		return FALSE;

	/* If pseudo is active, we don't need to use fakeroot. */
	if (check_pseudo_active())
		return FALSE;

	/* When running as root, we don't need to use fakeroot. */
	if (geteuid() == 0)
		return FALSE;

	return TRUE;
}

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar* manifestpath = NULL;
	g_autoptr(RaucManifest) manifest = NULL;
	g_autofree gchar *workdir = NULL;
	g_autofree gchar *fakeroot = NULL;
	gboolean mksquashfs_metadata = FALSE;
	gboolean res = FALSE;

	g_return_val_if_fail(bundlename != NULL, FALSE);
	g_return_val_if_fail(contentdir != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_file_test(bundlename, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", bundlename);
		return FALSE;
	}

	g_auto(RTempFile) bundletmp = g_strdup(bundlename); /* remove on early return */

	workdir = prepare_workdir(contentdir, &ierror);
	if (!workdir) {
		g_propagate_error(error, ierror);
		goto out;
	}

	manifestpath = g_build_filename(workdir, "manifest.raucm", NULL);
	res = load_manifest_file(manifestpath, &manifest, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to load manifest: ");
		goto out;
	}

	g_print("Creating '%s' format bundle\n", r_manifest_bundle_format_to_str(manifest->bundle_format));

	res = check_manifest_input(manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* print warnings collected while parsing */
	for (guint i = 0; i < manifest->warnings->len; i++) {
		g_print("%s\n", (gchar *)g_ptr_array_index(manifest->warnings, i));
	}

	res = check_manifest_create(manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = sync_manifest_with_contentdir(manifest, workdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (needs_fakeroot(manifest, &mksquashfs_metadata)) {
		fakeroot = r_fakeroot_init(&ierror);
		if (!fakeroot) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = generate_adaptive_data(manifest, workdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = convert_images(manifest, workdir, fakeroot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = save_manifest_file(manifestpath, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = mksquashfs(bundlename, workdir, mksquashfs_metadata, fakeroot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		res = encrypt_bundle_payload(bundlename, manifest, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = sign_bundle(bundlename, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (workdir && !rm_tree(workdir, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Failed to remove workdir: ");
		goto out;
	}

	g_clear_pointer(&bundletmp, g_free); /* prevent removal */
	res = TRUE;

out:
	/* Remove fakeroot env */
	if (fakeroot) {
		g_autofree GError *cleanup_error = NULL;
		if (!r_fakeroot_cleanup(fakeroot, &cleanup_error)) {
			g_warning("failed to clean up fakeroot environment: %s", cleanup_error->message);
		}
	}
	return res;
}

static gboolean truncate_bundle(const gchar *inpath, const gchar *outpath, goffset size, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(inpath != NULL, FALSE);
	g_return_val_if_fail(outpath != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GFile) infile = g_file_new_for_path(inpath);
	g_autoptr(GFile) outfile = g_file_new_for_path(outpath);

	g_autoptr(GFileInputStream) instream = g_file_read(infile, NULL, &ierror);
	if (instream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for reading: ");
		return FALSE;
	}
	g_autoptr(GFileOutputStream) outstream = g_file_create(outfile, G_FILE_CREATE_NONE, NULL,
			&ierror);
	if (outstream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for writing: ");
		return FALSE;
	}

	gssize ssize = g_output_stream_splice(
			(GOutputStream*)outstream,
			(GInputStream*)instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
			NULL, &ierror);
	if (ssize == -1) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!g_seekable_truncate(G_SEEKABLE(outstream), size, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

gboolean resign_bundle(RaucBundle *bundle, const gchar *outpath, gboolean append, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outpath != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_file_test(outpath, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", outpath);
		return FALSE;
	}

	g_auto(RTempFile) outtmp = g_strdup(outpath); /* remove on early return */

	if (!check_bundle_payload(bundle, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_autoptr(RaucManifest) loaded_manifest = NULL;
	RaucManifest *manifest = NULL; /* alias pointer, not to be freed */
	if (bundle->manifest) {
		manifest = bundle->manifest;
	} else {
		if (!load_manifest_from_bundle(bundle, &loaded_manifest, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		manifest = loaded_manifest;
	}

	g_print("Resigning '%s' format bundle\n", r_manifest_bundle_format_to_str(manifest->bundle_format));

	if (!truncate_bundle(bundle->path, outpath, bundle->size, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_autoptr(GBytes) sig = NULL;
	if (append) {
		sig = append_signature(bundle->sigdata, &ierror);
	} else {
		sig = generate_bundle_signature(outpath, manifest, &ierror);
	}
	if (!sig) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!append_signature_to_bundle(outpath, sig, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_clear_pointer(&outtmp, g_free); /* prevent removal */
	return TRUE;
}

static gboolean convert_to_casync_bundle(RaucBundle *bundle, const gchar *outbundle, const gchar **ignore_images, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *contentdir = NULL;
	g_autofree gchar *mfpath = NULL;
	g_autofree gchar *storepath = NULL;
	g_autoptr(RaucManifest) manifest = NULL;

	g_return_val_if_fail(bundle, FALSE);
	g_return_val_if_fail(outbundle, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_str_has_suffix(outbundle, ".raucb")) {
		g_autofree gchar *basepath = g_strndup(outbundle, strlen(outbundle) - 6);
		storepath = g_strconcat(basepath, ".castr", NULL);
	} else {
		storepath = g_strconcat(outbundle, ".castr", NULL);
	}

	if (g_file_test(storepath, G_FILE_TEST_EXISTS)) {
		g_warning("Store path '%s' already exists, appending new chunks", storepath);
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
		g_propagate_prefixed_error(error, ierror,
				"Failed to load manifest: ");
		goto out;
	}

	g_clear_pointer(&manifest->bundle_verity_salt, g_free);
	g_clear_pointer(&manifest->bundle_verity_hash, g_free);
	manifest->bundle_verity_size = 0;

	/* Iterate over each image and convert */
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;
		g_autofree gchar *imgpath = NULL;
		g_autofree gchar *idxfile = NULL;
		g_autofree gchar *idxpath = NULL;

		imgpath = g_build_filename(contentdir, image->filename, NULL);

		if (!image->filename)
			continue;

		if (ignore_images && g_strv_contains(ignore_images, image->slotclass)) {
			g_message("Skipping conversion of %s as requested", image->filename);
			continue;
		}

		if (image_is_archive(image)) {
			idxfile = g_strconcat(image->filename, ".caidx", NULL);
			idxpath = g_build_filename(contentdir, idxfile, NULL);

			g_message("Converting %s to casync directory tree idx %s", image->filename, idxfile);

			res = casync_make_arch(idxpath, imgpath, storepath, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
		} else {
			idxfile = g_strconcat(image->filename, ".caibx", NULL);
			idxpath = g_build_filename(contentdir, idxfile, NULL);

			g_message("Converting %s to casync blob idx %s", image->filename, idxfile);

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
			g_warning("failed to remove %s", imgpath);
		}
	}

	/* Rewrite manifest to content/ dir */
	res = save_manifest_file(mfpath, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = mksquashfs(outbundle, contentdir, FALSE, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = sign_bundle(outbundle, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	/* Remove temporary bundle creation directory */
	if (tmpdir) {
		g_autoptr(GError) tmperror = NULL;
		if (!rm_tree(tmpdir, &tmperror)) {
			g_warning("Failed to remove conversion tmpdir %s: %s", tmpdir, tmperror->message);
		}
	}
	return res;
}

gboolean create_casync_bundle(RaucBundle *bundle, const gchar *outbundle, const gchar **ignore_images, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outbundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_file_test(outbundle, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", outbundle);
		return FALSE;
	}

	g_auto(RTempFile) outtmp = g_strdup(outbundle); /* remove on early return */

	if (!check_bundle_payload(bundle, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!convert_to_casync_bundle(bundle, outbundle, ignore_images, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_clear_pointer(&outtmp, g_free); /* prevent removal */
	return TRUE;
}

gboolean encrypt_bundle(RaucBundle *bundle, const gchar *outbundle, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outbundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Encrypting the CMS for a 'verity' bundle would technically possible,
	 * but should be avoided as this will be misleading for the user who
	 * receives an encrypted CMS but no encrypted payload (which is what we
	 * actually want to protect).
	 */
	if (!bundle->manifest || bundle->manifest->bundle_format != R_MANIFEST_FORMAT_CRYPT) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE, "Refused to encrypt input bundle that is not in 'crypt' format.");
		return FALSE;
	}

	if (g_file_test(outbundle, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", outbundle);
		return FALSE;
	}

	g_auto(RTempFile) outtmp = g_strdup(outbundle); /* remove on early return */

	if (!truncate_bundle(bundle->path, outbundle, bundle->size, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* encrypt sigdata CMS */
	g_autoptr(GBytes) encdata = cms_encrypt(bundle->sigdata, r_context()->recipients, &ierror);
	if (encdata == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to encrypt bundle: ");
		return FALSE;
	}

	if (!append_signature_to_bundle(outbundle, encdata, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_clear_pointer(&outtmp, g_free); /* prevent removal */
	return TRUE;
}

static gboolean is_remote_scheme(const gchar *scheme)
{
	return (g_strcmp0(scheme, "http") == 0) ||
	       (g_strcmp0(scheme, "https") == 0) ||
	       (g_strcmp0(scheme, "tftp") == 0) ||
	       (g_strcmp0(scheme, "sftp") == 0) ||
	       (g_strcmp0(scheme, "ftp") == 0) ||
	       (g_strcmp0(scheme, "ftps") == 0);
}

static gboolean take_bundle_ownership(int bundle_fd, GError **error)
{
	struct stat stat = {};
	mode_t perm_orig = 0, perm_new = 0;
	uid_t euid;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	euid = geteuid();

	if (fstat(bundle_fd, &stat)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to fstat bundle: %s", g_strerror(err));
		return FALSE;
	}

	/* if it belongs to someone else, try to fchown if we are root */
	if ((stat.st_uid != 0) && (stat.st_uid != euid)) {
		if (euid != 0) {
			g_set_error(error,
					G_FILE_ERROR,
					G_FILE_ERROR_PERM,
					"cannot take file ownership of bundle when running as user (%d)", euid);
			return FALSE;
		}

		if (fchown(bundle_fd, 0, -1)) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"failed to chown bundle to root: %s", g_strerror(err));
			return FALSE;
		}
	}

	/* allow write permission for user only */
	perm_orig = stat.st_mode & 07777;
	perm_new = perm_orig & (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (perm_orig != perm_new) {
		if (fchmod(bundle_fd, perm_new)) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"failed to chmod bundle: %s", g_strerror(err));
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean check_bundle_access(int bundle_fd, GError **error)
{
	struct stat bundle_stat = {};
	struct stat root_stat = {};
	struct statfs bundle_statfs = {};
	mode_t perm = 0;
	GList *mountlist = NULL;
	gboolean mount_checked = FALSE;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* This checks if another user could get or already has write access
	 * the bundle contents.
	 *
	 * Prohibited are:
	 * - ownership or permissions that allow other users to open it for writing
	 * - storage on unsafe filesystems such as FUSE or NFS, where the data
	 *   is supplied by an untrusted source (the rootfs is explicitly
	 *   trusted, though)
	 * - storage on an filesystem mounted from a block device with a non-root owner
	 * - existing open file descriptors (via F_SETLEASE)
	 */

	if (fstat(bundle_fd, &bundle_stat)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to fstat bundle: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}
	perm = bundle_stat.st_mode & 07777;

	if (fstatfs(bundle_fd, &bundle_statfs)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to fstatfs bundle: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	/* unexpected file type */
	if (!S_ISREG(bundle_stat.st_mode)) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "unsafe bundle (not a regular file)");
		res = FALSE;
		goto out;
	}

	/* owned by other user (except root) */
	if ((bundle_stat.st_uid != 0) && (bundle_stat.st_uid != geteuid())) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "unsafe bundle uid %ju", (uintmax_t)bundle_stat.st_uid);
		res = FALSE;
		goto out;
	}

	/* unsafe permissions (not a subset of 0755) */
	if (perm & ~(0755)) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "unsafe bundle permissions 0%jo", (uintmax_t)perm);
		res = FALSE;
		goto out;
	}

	/* the root filesystem is trusted */
	if (stat("/", &root_stat)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to stat rootfs: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}
	if (root_stat.st_dev == bundle_stat.st_dev)
		mount_checked = TRUE;

	/* reject unsafe filesystem types */
	if (!mount_checked) {
		switch (bundle_statfs.f_type) {
			/* fuse doesn't ensure consistency */
			case FUSE_SUPER_MAGIC:
			case NFS_SUPER_MAGIC:
				g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "bundle is stored on an unsafe filesystem");
				res = FALSE;
				goto out;
				break;
			/* local filesystem permissions are enforced by the kernel */
			case AFS_SUPER_MAGIC:
			case BTRFS_SUPER_MAGIC:
			case CRAMFS_MAGIC:
			case EXFAT_SUPER_MAGIC:
			case EXT4_SUPER_MAGIC: /* also covers ext2/3 */
			case F2FS_SUPER_MAGIC:
			case ISOFS_SUPER_MAGIC:
			case JFFS2_SUPER_MAGIC:
			case MSDOS_SUPER_MAGIC:
			case NTFS_SB_MAGIC:
			case NTFS3_SUPER_MAGIC:
			case ROMFS_MAGIC:
			case SQUASHFS_MAGIC:
			case UDF_SUPER_MAGIC:
			case XFS_SUPER_MAGIC:
				break;
			/* these are prepared by root */
			case HOSTFS_SUPER_MAGIC:
			case OVERLAYFS_SUPER_MAGIC:
			case RAMFS_MAGIC:
			case TMPFS_MAGIC:
			case UBIFS_SUPER_MAGIC:
			case ZFS_SUPER_MAGIC:
				mount_checked = TRUE;
				break;
			default:
				g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "bundle is stored on an unknown filesystem (type=%0jx)", (uintmax_t)bundle_statfs.f_type);
				res = FALSE;
				goto out;
				break;
		}
	}

	/* check if the underlying device is acceptable */
	if (!mount_checked) {
		mountlist = g_unix_mounts_get(NULL);
		for (GList *l = mountlist; l != NULL; l = l->next) {
			GUnixMountEntry *m = l->data;
			const gchar *dev_path = g_unix_mount_get_device_path(m);
			struct stat dev_stat = {};
			if (stat(dev_path, &dev_stat))
				continue;
			if (dev_stat.st_rdev != bundle_stat.st_dev)
				continue;
			/* check owner is root */
			if (dev_stat.st_uid != 0) {
				g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "unsafe uid 0%ju for mounted device %s", (uintmax_t)dev_stat.st_uid, dev_path);
				res = FALSE;
				goto out;
			}
			/* As mode 0660 is very widespread for disks,
			 * permission checks would either have many false
			 * positives or be very complex. So we have to trust
			 * that the system integrator has configured the device
			 * group permissions properly.
			 */
			mount_checked = TRUE;
			break;
		}
	}

	if (!mount_checked) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE, "unable to find mounted device for bundle");
		res = FALSE;
		goto out;
	}

	/* check for other open file descriptors via leases (see fcntl(2)) */
	if (fcntl(bundle_fd, F_SETLEASE, F_RDLCK)) {
		const gchar *message = NULL;
		int err = errno;
		if (err == EAGAIN) {
			message = "EAGAIN: existing open file descriptor";
		} else if (err == EACCES) {
			message = "EACCES: missing capability CAP_LEASE?";
		} else {
			message = g_strerror(err);
		}
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_UNSAFE,
				"could not ensure exclusive bundle access (F_SETLEASE): %s", message);
		res = FALSE;
		goto out;
	}
	if (fcntl(bundle_fd, F_GETLEASE) != F_RDLCK) {
		int err = errno;
		g_set_error(error,
				R_BUNDLE_ERROR,
				R_BUNDLE_ERROR_UNSAFE,
				"could not ensure exclusive bundle access (F_GETLEASE): %s", g_strerror(err));
		res = FALSE;
		goto out;
	}
	if (fcntl(bundle_fd, F_SETLEASE, F_UNLCK)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to remove file lease on bundle: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	res = TRUE;

out:
	if (mountlist)
		g_list_free_full(mountlist, (GDestroyNotify)g_unix_mount_free);
	return res;
}

static gboolean enforce_bundle_exclusive(int bundle_fd, GError **error)
{
	GError *ierror_take = NULL, *ierror_check = NULL;
	gboolean res_take = FALSE, res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* first check if the current state is good */
	if (check_bundle_access(bundle_fd, &ierror_check)) {
		/* no need to do anything else */
		res = TRUE;
		goto out;
	}
	g_debug("initial check_bundle_access failed with: %s", ierror_check->message);
	g_clear_error(&ierror_check);

	/* try to take ownership (will fail for normal users and RO filesystems) */
	res_take = take_bundle_ownership(bundle_fd, &ierror_take);

	/* check if it is better now */
	if (!check_bundle_access(bundle_fd, &ierror_check)) {
		if (res_take) {
			/* taking ownership was successful, the relevant error is ierror_check */
			g_propagate_error(error, ierror_check);
		} else {
			/* taking ownership was unsuccessful, the relevant error is ierror_take */
			g_clear_error(&ierror_check);
			g_propagate_prefixed_error(error, ierror_take, "failed to take ownership of bundle: ");
			ierror_take = NULL;
		}
		res = FALSE;
		goto out;
	}

	res = TRUE;

out:
	g_clear_error(&ierror_take);
	return res;
}

static gboolean open_local_bundle(RaucBundle *bundle, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autoptr(GFile) bundlefile = NULL;
	g_autoptr(GFileInfo) bundleinfo = NULL;
	guint64 sigsize;
	goffset offset;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_null(bundle->stream);

	bundlefile = g_file_new_for_path(bundle->path);
	bundle->stream = G_INPUT_STREAM(g_file_read(bundlefile, NULL, &ierror));
	if (bundle->stream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to open bundle for reading: ");
		res = FALSE;
		goto out;
	}

	bundleinfo = g_file_input_stream_query_info(
			G_FILE_INPUT_STREAM(bundle->stream),
			G_FILE_ATTRIBUTE_STANDARD_TYPE,
			NULL, &ierror);
	if (bundleinfo == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to query bundle file info: ");
		res = FALSE;
		goto out;
	}

	if (g_file_info_get_file_type(bundleinfo) != G_FILE_TYPE_REGULAR) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE,
				"Bundle is not a regular file");
		res = FALSE;
		goto out;
	}

	offset = sizeof(sigsize);
	res = g_seekable_seek(G_SEEKABLE(bundle->stream),
			-offset, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to seek to end of bundle: ");
		goto out;
	}
	offset = g_seekable_tell(G_SEEKABLE(bundle->stream));

	res = input_stream_read_uint64_all(bundle->stream,
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
	/* sanity check: signature should not exceed the configured maximum */
	if (sigsize > r_context()->config->max_bundle_signature_size) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size (%"G_GUINT64_FORMAT ") exceeds max-bundle-signature-size (%"G_GUINT64_FORMAT ")",
				sigsize, r_context()->config->max_bundle_signature_size);
		res = FALSE;
		goto out;
	}

	offset -= sigsize;
	if (offset % 4096) {
		g_message(
				"Payload size (%"G_GUINT64_FORMAT ") is not a multiple of 4KiB. "
				"See https://rauc.readthedocs.io/en/latest/faq.html#what-causes-a-payload-size-that-is-not-a-multiple-of-4kib",
				offset);
	}
	bundle->size = offset;

	res = g_seekable_seek(G_SEEKABLE(bundle->stream),
			offset, G_SEEK_SET, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to seek to start of bundle signature: ");
		goto out;
	}

	res = input_stream_read_bytes_all(bundle->stream,
			&bundle->sigdata, sigsize, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read signature from bundle: ");
		goto out;
	}

out:
	return res;
}

#if ENABLE_STREAMING
static gboolean open_remote_bundle(RaucBundle *bundle, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autofree void *buffer = NULL;
	guint64 sigsize;
	guint64 offset;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_null(bundle->stream);
	g_assert_nonnull(bundle->nbd_srv);
	g_assert_null(bundle->nbd_dev);

	/* bundle must at least be large enough for the signature size */
	if (bundle->nbd_srv->data_size < sizeof(sigsize)) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Bundle size (%"G_GUINT64_FORMAT ") is too small", bundle->nbd_srv->data_size);
		res = FALSE;
		goto out;
	}

	offset = bundle->nbd_srv->data_size - sizeof(sigsize);

	res = r_nbd_read(bundle->nbd_srv->sock, (guint8*)&sigsize, sizeof(sigsize), offset, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read signature size from bundle: ");
		goto out;
	}
	sigsize = GUINT64_FROM_BE(sigsize);

	if (sigsize == 0) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size is 0");
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should be smaller than bundle size */
	if (sigsize > offset) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size (%"G_GUINT64_FORMAT ") exceeds bundle size", sigsize);
		res = FALSE;
		goto out;
	}
	/* sanity check: signature should not exceed the configured maximum */
	if (sigsize > r_context()->config->max_bundle_signature_size) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Signature size (%"G_GUINT64_FORMAT ") exceeds max-bundle-signature-size (%"G_GUINT64_FORMAT ")",
				sigsize, r_context()->config->max_bundle_signature_size);
		res = FALSE;
		goto out;
	}

	/* The CMS data starts at filesize - sizeof(sigsize) - sigsize. */
	offset -= sigsize;
	if (offset % 4096) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE,
				"Payload size (%"G_GUINT64_FORMAT ") is not a multiple of 4KiB. "
				"See https://rauc.readthedocs.io/en/latest/faq.html#what-causes-a-payload-size-that-is-not-a-multiple-of-4kib",
				offset);
		res = FALSE;
		goto out;
	}
	bundle->size = offset;

	buffer = g_malloc0(sigsize);
	res = r_nbd_read(bundle->nbd_srv->sock, buffer, sigsize, offset, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read signature from bundle: ");
		goto out;
	}
	bundle->sigdata = g_bytes_new_take(g_steal_pointer(&buffer), sigsize);

out:
	return res;
}
#else
static gboolean open_remote_bundle(RaucBundle *bundle, GError **error)
{
	g_error("configured without -Dstreaming=true");
	return FALSE;
}
#endif

static gboolean check_allowed_bundle_format(RaucManifest *manifest, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!manifest) {
		if (!(r_context()->config->bundle_formats_mask & 1 << R_MANIFEST_FORMAT_PLAIN)) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT,
					"Bundle format 'plain' not allowed");
			return FALSE;
		}

		return TRUE;
	}

	if (manifest->bundle_format == R_MANIFEST_FORMAT_VERITY) {
		if (!(r_context()->config->bundle_formats_mask & 1 << R_MANIFEST_FORMAT_VERITY)) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT,
					"Bundle format 'verity' not allowed");
			return FALSE;
		}
	}

	if (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		if (!(r_context()->config->bundle_formats_mask & 1 << R_MANIFEST_FORMAT_CRYPT)) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT,
					"Bundle format 'crypt' not allowed");
			return FALSE;
		}
	}

	return TRUE;
}

gboolean check_bundle(const gchar *bundlename, RaucBundle **bundle, CheckBundleParams params, RaucBundleAccessArgs *access_args, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	gboolean verify = !(params & CHECK_BUNDLE_NO_VERIFY);
	g_autoptr(RaucBundle) ibundle = g_new0(RaucBundle, 1);
	g_autoptr(GBytes) manifest_bytes = NULL;
	g_autofree gchar *bundlescheme = NULL;
	gboolean detached;

	g_return_val_if_fail(bundlename, FALSE);
	g_return_val_if_fail(bundle != NULL && *bundle == NULL, FALSE);
	g_return_val_if_fail(!(params & TRUE), FALSE); /* protect against passing TRUE as the params enum */
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("check_bundle", "Checking bundle", verify);

	if (verify && !r_context()->config->keyring_path && !r_context()->config->keyring_directory) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_KEYRING, "No keyring file or directory provided");
		res = FALSE;
		goto out;
	}

	ibundle->verification_disabled = !verify;

	/* Download Bundle to temporary location if remote URI is given */
	bundlescheme = g_uri_parse_scheme(bundlename);
	if (is_remote_scheme(bundlescheme)) {
#if ENABLE_STREAMING
		ibundle->path = g_strdup(bundlename);

		g_message("Remote URI detected, streaming bundle...");
		ibundle->nbd_srv = r_nbd_new_server();
		ibundle->nbd_srv->url = g_strdup(bundlename);
		if (access_args) {
			ibundle->nbd_srv->tls_cert = g_strdup(access_args->tls_cert);
			ibundle->nbd_srv->tls_key = g_strdup(access_args->tls_key);
			ibundle->nbd_srv->tls_ca = g_strdup(access_args->tls_ca);
			ibundle->nbd_srv->tls_no_verify = access_args->tls_no_verify;
			ibundle->nbd_srv->headers = g_strdupv(access_args->http_headers);
			if (access_args->http_info_headers)
				ibundle->nbd_srv->info_headers = g_ptr_array_ref(access_args->http_info_headers);
		}
		if (!ibundle->nbd_srv->tls_cert)
			ibundle->nbd_srv->tls_cert = g_strdup(r_context()->config->streaming_tls_cert);
		if (!ibundle->nbd_srv->tls_key)
			ibundle->nbd_srv->tls_key = g_strdup(r_context()->config->streaming_tls_key);
		if (!ibundle->nbd_srv->tls_ca)
			ibundle->nbd_srv->tls_ca = g_strdup(r_context()->config->streaming_tls_ca);
		res = r_nbd_start_server(ibundle->nbd_srv, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Failed to stream bundle %s: ", ibundle->path);
			goto out;
		}
#elif ENABLE_NETWORK
		g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-XXXXXX", &ierror);
		if (tmpdir == NULL) {
			g_propagate_prefixed_error(error, ierror, "Failed to create tmp dir: ");
			res = FALSE;
			goto out;
		}

		ibundle->origpath = g_strdup(bundlename);
		ibundle->path = g_build_filename(tmpdir, "download.raucb", NULL);

		g_message("Remote URI detected, downloading bundle to %s...", ibundle->path);
		res = download_file(ibundle->path, ibundle->origpath, r_context()->config->max_bundle_download_size, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Failed to download bundle %s: ", ibundle->origpath);
			goto out;
		}
		g_debug("Downloaded temp bundle to %s", ibundle->path);
#else
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSUPPORTED,
				"Remote bundle access not supported, recompile with -Dstreaming=true");
		res = FALSE;
		goto out;
#endif
	} else {
		ibundle->path = g_strdup(bundlename);
	}

	/* Determine store path for casync, defaults to bundle */
	if (r_context()->config->store_path) {
		ibundle->storepath = g_strdup(r_context()->config->store_path);
	} else {
		gchar *path = ibundle->origpath ?: ibundle->path;

		if (g_str_has_suffix(path, ".raucb")) {
			g_autofree gchar *strprfx = g_strndup(path, strlen(path) - 6);
			ibundle->storepath = g_strconcat(strprfx, ".castr", NULL);
		} else {
			ibundle->storepath = g_strconcat(path, ".castr", NULL);
		}
	}

	g_message("Reading bundle: %s", ibundle->path);

	if (!ibundle->nbd_srv) { /* local or downloaded */
		res = open_local_bundle(ibundle, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Invalid bundle format: ");
			goto out;
		}
	} else { /* streaming */
		res = open_remote_bundle(ibundle, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Invalid bundle format: ");
			goto out;
		}
	}

	res = cms_is_detached(ibundle->sigdata, &detached, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Invalid bundle format: ");
		goto out;
	}

	g_debug("Found valid CMS data");

	if (detached && ibundle->nbd_srv) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT,
				"Bundle format 'plain' not supported in streaming mode");
		res = FALSE;
		goto out;
	}

	/* For encrypted bundles, the 'signed' CMS is the payload of the
	 * 'enveloped' CMS. Thus we must decrypt it first before forwarding.
	 */
	if (cms_is_envelopeddata(ibundle->sigdata)) {
		GBytes *decrypted_sigdata = NULL;

		g_debug("CMS type is 'enveloped'. Attempting to decrypt..");

		if (r_context()->config->encryption_key == NULL) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_SIGNATURE, "Encrypted bundle detected, but no decryption key given. Use --key=<PEMFILE|PKCS11-URL> to provide one.");
			res = FALSE;
			goto out;
		}

		decrypted_sigdata = cms_decrypt(ibundle->sigdata, r_context()->config->encryption_cert, r_context()->config->encryption_key, &ierror);
		if (decrypted_sigdata == NULL) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to decrypt bundle: ");
			res = FALSE;
			goto out;
		}

		ibundle->enveloped_data = ibundle->sigdata;
		/* replace sigdata by decrypted payload */
		ibundle->sigdata = decrypted_sigdata;
		/* write marker to memorize for later that we originally had an enveloped CMS */
		ibundle->was_encrypted = TRUE;
	}

	if (verify) {
		g_autoptr(CMS_ContentInfo) cms = NULL;
		g_autoptr(X509_STORE) store = setup_x509_store(NULL, NULL, &ierror);
		X509_VERIFY_PARAM *param = NULL;
		gboolean trust_env = (params & CHECK_BUNDLE_TRUST_ENV);
		if (!store) {
			g_propagate_error(error, ierror);
			res = FALSE;
			goto out;
		}
		param = X509_STORE_get0_param(store);

		g_message("Verifying bundle signature... ");

		if (params & CHECK_BUNDLE_NO_CHECK_TIME)
			X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);

		if (detached) {
			int fd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(ibundle->stream));

			if (!trust_env && !enforce_bundle_exclusive(fd, &ierror)) {
				g_propagate_error(error, ierror);
				res = FALSE;
				goto out;
			}
			ibundle->exclusive_verified = TRUE;

			/* the squashfs image size is in ibundle->size */
			res = cms_verify_fd(fd, ibundle->sigdata, ibundle->size, store, &cms, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
			ibundle->signature_verified = TRUE;
			ibundle->payload_verified = TRUE;
		} else {
			/* check if we have exclusive access to local or downloaded bundles */
			if (ibundle->stream) {
				int fd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(ibundle->stream));

				if (!trust_env && !check_bundle_access(fd, &ierror)) {
					ibundle->exclusive_check_error = g_strdup(ierror->message);
					g_clear_error(&ierror);
				} else {
					ibundle->exclusive_verified = TRUE;
				}
			}

			res = cms_verify_sig(ibundle->sigdata, store, &cms, &manifest_bytes, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
			ibundle->signature_verified = TRUE;
			ibundle->payload_verified = FALSE;
		}

		res = cms_get_cert_chain(cms, store, &ibundle->verified_chain, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else {
		if (!detached) {
			res = cms_get_unverified_manifest(ibundle->sigdata, &manifest_bytes, &ierror);
			if (!res) {
				g_propagate_error(error, ierror);
				goto out;
			}
		}
	}

	if (manifest_bytes) {
		res = load_manifest_mem(manifest_bytes, &ibundle->manifest, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to load manifest: ");
			goto out;
		}

		ibundle->manifest->was_encrypted = ibundle->was_encrypted;

		if (ibundle->manifest->bundle_format == R_MANIFEST_FORMAT_PLAIN) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT,
					"Bundle format 'plain' not allowed for external manifest");
			res = FALSE;
			goto out;
		}
	}

	res = check_allowed_bundle_format(ibundle->manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	*bundle = g_steal_pointer(&ibundle);

	res = TRUE;
out:
	r_context_end_step("check_bundle", res);
	return res;
}

gboolean check_bundle_payload(RaucBundle *bundle, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (bundle->verification_disabled || bundle->payload_verified) {
		r_context_begin_step("skip_bundle_payload", "Bundle payload verification not needed", 0);
		r_context_end_step("skip_bundle_payload", TRUE);
		return TRUE;
	}

	g_message("Verifying bundle payload... ");

	if (!bundle->stream) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE,
				"Refused to verify remote bundle. Provide a local bundle instead.");
		return FALSE;
	}

	if (!bundle->exclusive_verified) {
		g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE,
				"cannot check bundle payload without exclusive access: %s", bundle->exclusive_check_error);
		return FALSE;
	}

	if (!bundle->manifest) { /* plain format */
		g_error("plain bundles must be verified during signature check");
		/* g_error always aborts the program */
	} else {
		if (!check_manifest_external(bundle->manifest, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	if (bundle->manifest->bundle_format == R_MANIFEST_FORMAT_PLAIN) {
		g_error("plain bundles must be verified during signature check");
	} else if (bundle->manifest->bundle_format == R_MANIFEST_FORMAT_VERITY || bundle->manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		int bundlefd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(bundle->stream));
		g_autofree guint8 *root_digest = r_hex_decode(bundle->manifest->bundle_verity_hash, 32);
		g_autofree guint8 *salt = r_hex_decode(bundle->manifest->bundle_verity_salt, 32);
		off_t combined_size = bundle->size;
		off_t data_size = bundle->size - bundle->manifest->bundle_verity_size;
		g_assert(root_digest);
		g_assert(salt);
		g_assert(combined_size % 4096 == 0);
		g_assert(data_size % 4096 == 0);

		if (r_verity_hash_verify(bundlefd, data_size/4096, root_digest, salt)) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
					"bundle payload is corrupted");
			return FALSE;
		}
	} else {
		g_error("unsupported bundle format");
		return FALSE;
	}

	bundle->payload_verified = TRUE;

	return TRUE;
}

gboolean replace_signature(RaucBundle *bundle, const gchar *insig, const gchar *outpath, CheckBundleParams params, GError **error)
{
	g_autoptr(RaucManifest) loaded_manifest = NULL;
	RaucManifest *manifest = NULL; /* alias pointer, not to be freed */
	g_autoptr(RaucBundle) outbundle = NULL;
	g_autoptr(GBytes) sig = NULL;
	gchar* keyringpath = NULL;
	gchar* keyringdirectory = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outpath != NULL, FALSE);
	g_return_val_if_fail(insig != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_file_test(outpath, G_FILE_TEST_EXISTS)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "bundle %s already exists", outpath);
		return FALSE;
	}

	g_auto(RTempFile) outtmp = g_strdup(outpath); /* remove on early return */

	if (bundle->manifest) {
		manifest = bundle->manifest;
	} else {
		res = load_manifest_from_bundle(bundle, &loaded_manifest, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to load manifest: ");
			goto out;
		}
		manifest = loaded_manifest;
	}

	g_print("Replacing signature for '%s format bundle\n", r_manifest_bundle_format_to_str(manifest->bundle_format));

	sig = read_file(insig, &ierror);
	if (!sig) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to read signature file: ");
		res = FALSE;
		goto out;
	}

	res = truncate_bundle(bundle->path, outpath, bundle->size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = append_signature_to_bundle(outpath, sig, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/*
	 * If signing_keyringpath is given, replace config->keyring_path, so we can
	 * use check_bundle() as is.
	 */
	if (r_context()->signing_keyringpath) {
		keyringpath = r_context()->config->keyring_path;
		keyringdirectory = r_context()->config->keyring_directory;
		r_context()->config->keyring_path = r_context()->signing_keyringpath;
		r_context()->config->keyring_directory = NULL;
	}

	/* Let the user control verification by optionally providing a keyring. */
	if (r_context()->config->keyring_path || r_context()->config->keyring_directory) {
		g_message("Keyring given, enabling signature verification");
		params &= ~CHECK_BUNDLE_NO_VERIFY;
	} else {
		g_message("No keyring given, disabling signature verification");
		params |= CHECK_BUNDLE_NO_VERIFY;
	}

	res = check_bundle(outpath, &outbundle, params, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to verify the new bundle: ");
		goto out;
	}

	g_clear_pointer(&outtmp, g_free); /* prevent removal */
	res = TRUE;

out:
	/* Restore saved paths if necessary */
	if (keyringpath || keyringdirectory) {
		r_context()->config->keyring_path = keyringpath;
		r_context()->config->keyring_directory = keyringdirectory;
	}

	return res;
}

gboolean extract_signature(RaucBundle *bundle, const gchar *outputsig, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GFile) sigfile = NULL;
	g_autoptr(GOutputStream) sigoutstream = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outputsig != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("extract_signature", "Extracting bundle signature", 0);

	sigfile = g_file_new_for_path(outputsig);
	sigoutstream = (GOutputStream*)g_file_create(sigfile, G_FILE_CREATE_PRIVATE, NULL, &ierror);
	if (sigoutstream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to create file to store signature: ");
		goto out;
	}

	if (!output_stream_write_bytes_all(sigoutstream, bundle->sigdata, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to write signature to file: ");
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("extract_signature", res);
	return res;
}

gboolean extract_bundle(RaucBundle *bundle, const gchar *outputdir, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(outputdir != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("extract_bundle", "Extracting bundle", 2);

	if (g_file_test(outputdir, G_FILE_TEST_EXISTS)) {
		res = FALSE;
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST, "output directory '%s' exists already", outputdir);
		goto out;
	}

	res = check_bundle_payload(bundle, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (bundle->manifest && bundle->manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		res = decrypt_bundle_payload(bundle, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = unsquashfs(g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(bundle->stream)), outputdir, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("extract_bundle", res);
	return res;
}

gboolean load_manifest_from_bundle(RaucBundle *bundle, RaucManifest **manifest, GError **error)
{
	g_autofree gchar* tmpdir = NULL;
	g_autofree gchar* bundledir = NULL;
	g_autofree gchar* manifestpath = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(manifest != NULL && *manifest == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = check_bundle_payload(bundle, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	tmpdir = g_dir_make_tmp("arch-XXXXXX", &ierror);
	if (tmpdir == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to create tmp dir: ");
		res = FALSE;
		goto out;
	}

	bundledir = g_build_filename(tmpdir, "bundle-content", NULL);
	res = unsquashfs(g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(bundle->stream)), bundledir, "manifest.raucm", &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to extract manifest from bundle: ");
		goto out;
	}

	manifestpath = g_build_filename(bundledir, "manifest.raucm", NULL);
	res = load_manifest_file(manifestpath, manifest, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to load manifest: ");
		goto out;
	}

	res = check_manifest_internal(*manifest, &ierror);
	if (!res) {
		g_clear_pointer(manifest, free_manifest);
		g_propagate_prefixed_error(error, ierror,
				"Failed to check manifest: ");
		goto out;
	}
out:
	if (tmpdir) {
		g_autoptr(GError) tmperror = NULL;
		if (!rm_tree(tmpdir, &tmperror)) {
			g_warning("Failed to remove unsquashfs tmpdir %s: %s", tmpdir, tmperror->message);
		}
	}
	return res;
}

static gboolean read_complete_dm_device(gchar *dev, GError **error)
{
	const goffset chunk_size = 65536;
	g_autofree void* buf = NULL;
	ssize_t r;

	g_return_val_if_fail(dev != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_auto(filedesc) fd = g_open(dev, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open %s: %s", dev, g_strerror(err));
		return FALSE;
	}

	buf = g_malloc0(chunk_size);

	for (goffset chunk = 0;; chunk++) {
		r = pread(fd, buf, chunk_size, chunk*chunk_size);
		if (r == 0)
			break;
		else if (r < 0)	{
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Check %s device failed between %"G_GOFFSET_FORMAT " and %"G_GOFFSET_FORMAT " bytes with error: %s", dev, chunk*chunk_size, (chunk+1)*chunk_size, g_strerror(err));
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean cleanup_dangling_mount(const gchar* mount_point, GError **error)
{
	GError *ierror = NULL;

	if (r_is_mount_point(mount_point)) {
		g_message("Unmount dangling moint point: %s", mount_point);
		if (!r_umount_bundle(mount_point, &ierror)) {
			g_warning("Unable to unmount dangling moint point: %s", ierror->message);
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}
/*
 * Sets up dm-verity for reading verity bundles.
 *
 * [ /dev/dm-x ]
 *      🠗
 * [ dm-verity ]
 *      🠗
 * [  bundle   ]
 */
static gboolean prepare_verity(RaucBundle *bundle, gchar *loopname, gchar* mount_point, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autoptr(GError) ierror_dm = NULL;
	g_autoptr(RaucDM) dm_verity = r_dm_new_verity();

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(loopname != NULL, FALSE);
	g_return_val_if_fail(mount_point != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = check_manifest_external(bundle->manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	res = cleanup_dangling_mount(mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	dm_verity->lower_dev = g_strdup(loopname);
	dm_verity->data_size = bundle->size - bundle->manifest->bundle_verity_size;
	dm_verity->root_digest = g_strdup(bundle->manifest->bundle_verity_hash);
	dm_verity->salt = g_strdup(bundle->manifest->bundle_verity_salt);

	res = r_dm_setup(dm_verity, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (r_context()->config->perform_pre_check) {
		res = read_complete_dm_device(dm_verity->upper_dev, &ierror);
		if (!res) {
			/* ensure the already-set-up dm-verity layer is cleaned */
			if (!r_dm_remove(dm_verity, FALSE, &ierror_dm))	{
				g_warning("Failed to remove dm-verity device: %s", ierror_dm->message);
			}
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	res = r_mount_bundle(dm_verity->upper_dev, mount_point, &ierror);

	if (!r_dm_remove(dm_verity, TRUE, &ierror_dm)) {
		g_warning("failed to mark dm verity device for removal: %s", ierror_dm->message);
	}

	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/*
 * Sets up dm-verity and dm-crypt for reading crypt bundles.
 *
 * [ /dev/dm-x ]
 *      🠗
 * [ dm-crypt  ]
 *      🠗
 * [ dm-verity ]
 *      🠗
 * [  bundle   ]
 */
static gboolean prepare_crypt(RaucBundle *bundle, gchar *loopname, gchar* mount_point, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autoptr(GError) ierror_dm = NULL;
	g_autoptr(RaucDM) dm_verity = r_dm_new_verity();
	g_autoptr(RaucDM) dm_crypt = r_dm_new_crypt();

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(loopname != NULL, FALSE);
	g_return_val_if_fail(mount_point != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = check_manifest_external(bundle->manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	res = cleanup_dangling_mount(mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* setup dm-verity */
	dm_verity->lower_dev = g_strdup(loopname);
	dm_verity->data_size = bundle->size - bundle->manifest->bundle_verity_size;
	dm_verity->root_digest = g_strdup(bundle->manifest->bundle_verity_hash);
	dm_verity->salt = g_strdup(bundle->manifest->bundle_verity_salt);

	res = r_dm_setup(dm_verity, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* setup dm-crypt */
	dm_crypt->lower_dev = g_strdup(dm_verity->upper_dev);
	dm_crypt->data_size = bundle->size - bundle->manifest->bundle_verity_size;
	dm_crypt->key = g_strdup(bundle->manifest->bundle_crypt_key);

	res = r_dm_setup(dm_crypt, &ierror);
	if (!res) {
		/* ensure the already-set-up dm-verity layer is cleaned */
		if (!r_dm_remove(dm_verity, FALSE, &ierror_dm)) {
			g_warning("Failed to remove dm-verity device: %s", ierror_dm->message);
		}
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (r_context()->config->perform_pre_check) {
		res = read_complete_dm_device(dm_crypt->upper_dev, &ierror);
		if (!res) {
			/* ensure the already-set-up dm-verity and dm-crypt layers are cleaned */
			if (!r_dm_remove(dm_crypt, TRUE, &ierror_dm)) {
				g_warning("Failed to remove dm-crypt device: %s", ierror_dm->message);
				g_clear_error(&ierror_dm);
			}
			if (!r_dm_remove(dm_verity, TRUE, &ierror_dm)) {
				g_warning("Failed to remove dm-verity device: %s", ierror_dm->message);
			}
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	res = r_mount_bundle(dm_crypt->upper_dev, mount_point, &ierror);

	if (!r_dm_remove(dm_crypt, TRUE, &ierror_dm)) {
		g_warning("Failed to mark dm-crypt device for removal: %s", ierror_dm->message);
		g_clear_error(&ierror_dm);
	}

	if (!r_dm_remove(dm_verity, TRUE, &ierror_dm)) {
		g_warning("Failed to mark dm-verity device for removal: %s", ierror_dm->message);
	}

	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

gboolean mount_bundle(RaucBundle *bundle, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *mount_point = NULL;
	g_autofree gchar *loopname = NULL;
	gint devicefd = -1;
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

	if (!(bundle->signature_verified || bundle->verification_disabled))
		g_error("bundle signature must be verified before mounting");

	g_message("Mounting bundle '%s' to '%s'", bundle->path, mount_point);

	if (bundle->stream) { /* local or downloaded bundle */
		gint bundlefd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(bundle->stream));
		res = r_setup_loop(bundlefd, &devicefd, &loopname, bundle->size, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else if (ENABLE_STREAMING && bundle->nbd_srv) { /* streaming bundle access */
		bundle->nbd_dev = r_nbd_new_device();
		bundle->nbd_dev->data_size = bundle->size;
		bundle->nbd_dev->sock = bundle->nbd_srv->sock;
		bundle->nbd_srv->sock = -1;
		res = r_nbd_setup_device(bundle->nbd_dev, &devicefd, &ierror);
		if (!res) {
			/* The setup failed, so the socket still belongs to the nbd_srv. */
			bundle->nbd_srv->sock = bundle->nbd_dev->sock;
			bundle->nbd_dev->sock = -1;
			g_propagate_error(error, ierror);
			goto out;
		}
		loopname = g_strdup(bundle->nbd_dev->dev);
	} else {
		g_assert_not_reached();
	}

	if (!bundle->manifest) { /* plain format */
		g_autoptr(RaucManifest) manifest = NULL;
		g_autofree gchar* manifestpath = NULL;

		if (!(bundle->payload_verified || bundle->verification_disabled))
			g_error("bundle payload must be verified before mounting for plain bundles");

		res = r_mount_bundle(loopname, mount_point, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}

		manifestpath = g_build_filename(mount_point, "manifest.raucm", NULL);
		res = load_manifest_file(manifestpath, &manifest, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to load manifest from bundle: ");
			ierror = NULL;
			goto umount;
		}
		res = check_manifest_internal(manifest, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			ierror = NULL;
			goto umount;
		}

		if (manifest->bundle_format != R_MANIFEST_FORMAT_PLAIN) {
			g_set_error(error, R_BUNDLE_ERROR, R_BUNDLE_ERROR_PAYLOAD,
					"plain bundles can only contain plain manifests");
			res = FALSE;
			goto umount;
		}

		bundle->manifest = g_steal_pointer(&manifest);
	} else if (bundle->manifest->bundle_format == R_MANIFEST_FORMAT_VERITY) {
		res = prepare_verity(bundle, loopname, mount_point, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else if (bundle->manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		res = prepare_crypt(bundle, loopname, mount_point, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else {
		g_error("unsupported bundle format");
		res = FALSE;
		goto out;
	}

	bundle->mount_point = g_steal_pointer(&mount_point);
	res = TRUE;
	goto out;

umount:
	if (!r_umount_bundle(mount_point, &ierror)) {
		g_warning("ignoring umount error after initial error: %s", ierror->message);
		g_clear_error(&ierror);
	}
out:
	if (mount_point) {
		g_rmdir(mount_point);
	}
	if (devicefd >= 0)
		g_close(devicefd, NULL);
	return res;
}

gboolean umount_bundle(RaucBundle *bundle, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bundle != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_nonnull(bundle->mount_point);

	if (!r_umount_bundle(bundle->mount_point, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_rmdir(bundle->mount_point);
	g_clear_pointer(&bundle->mount_point, g_free);

	if (ENABLE_STREAMING && bundle->nbd_dev) {
		if (!r_nbd_remove_device(bundle->nbd_dev, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	if (ENABLE_STREAMING && bundle->nbd_srv) {
		if (!r_nbd_stop_server(bundle->nbd_srv, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

void free_bundle(RaucBundle *bundle)
{
	if (!bundle)
		return;

	/* In case of a temporary download artifact, remove it. */
	if (bundle->origpath) {
		g_autofree gchar *tmpdir = g_path_get_dirname(bundle->path);
		if (g_remove(bundle->path) != 0) {
			g_warning("failed to remove download artifact %s: %s\n", bundle->path, g_strerror(errno));
		}
		if (g_rmdir(tmpdir) != 0) {
			g_warning("failed to remove download directory %s: %s\n", tmpdir, g_strerror(errno));
		}
	}

	g_free(bundle->path);
	g_free(bundle->origpath);
	g_free(bundle->storepath);

	if (ENABLE_STREAMING && bundle->nbd_dev)
		r_nbd_free_device(bundle->nbd_dev);
	if (ENABLE_STREAMING && bundle->nbd_srv)
		r_nbd_free_server(bundle->nbd_srv);

	if (bundle->stream)
		g_object_unref(bundle->stream);
	g_bytes_unref(bundle->sigdata);
	g_bytes_unref(bundle->enveloped_data);
	g_free(bundle->mount_point);
	if (bundle->manifest)
		free_manifest(bundle->manifest);
	g_free(bundle->exclusive_check_error);
	if (bundle->verified_chain)
		sk_X509_pop_free(bundle->verified_chain, X509_free);
	g_free(bundle);
}

static gchar* get_uptime(void)
{
	g_autofree gchar *contents = NULL;
	g_autoptr(GError) ierror = NULL;
	g_auto(GStrv) uptime = NULL;

	if (!g_file_get_contents("/proc/uptime", &contents, NULL, &ierror)) {
		g_warning("Failed to get uptime: %s", ierror->message);
		return NULL;
	}

	/* file contains two values and a newline, 'chomp' in-place and split then */
	uptime = g_strsplit(g_strchomp(contents), " ", 2);

	return g_strdup(uptime[0]);
}

/* If the input key starts with RAUC_HTTP_, it returns a valid HTTP header
 * string with 'RAUC_HTTP_' replaced by 'RAUC-'.
 * If the input string does not start with RAUC_HTTP_, NULL is returned.
 */
static gchar *system_info_to_header(const gchar *key, const gchar *value)
{
	g_autofree gchar *header_key = NULL;

	g_return_val_if_fail(key, NULL);
	g_return_val_if_fail(value, NULL);

	if (!g_str_has_prefix(key, "RAUC_HTTP_"))
		return NULL;

	header_key = g_strdup(key + strlen("RAUC_HTTP_"));
	for (size_t i = 0; i < strlen(header_key); i++) {
		if (header_key[i] == '_')
			header_key[i] = '-';
	}

	return g_strdup_printf("RAUC-%s: %s", header_key, value);
}

GPtrArray *assemble_info_headers(const gchar *transaction)
{
	g_autoptr(GPtrArray) headers = g_ptr_array_new_with_free_func(g_free);

	if (!r_context()->config->enabled_headers)
		goto no_std_headers;

	for (gchar **header = r_context()->config->enabled_headers; *header; header++) {
		/* Add static system information */
		if (g_strcmp0(*header, "boot-id") == 0 && r_context()->boot_id)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Boot-ID: %s", r_context()->boot_id));
		if (g_strcmp0(*header, "machine-id") == 0 && r_context()->machine_id)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Machine-ID: %s", r_context()->machine_id));
		if (g_strcmp0(*header, "system-version") == 0 && r_context()->system_version)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-System-Version: %s", r_context()->system_version));
		if (g_strcmp0(*header, "serial") == 0 && r_context()->system_serial)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Serial: %s", r_context()->system_serial));
		if (g_strcmp0(*header, "variant") == 0 && r_context()->config->system_variant)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Variant: %s", r_context()->config->system_variant));
		/* Add per-installation information */
		if (g_strcmp0(*header, "transaction-id") == 0 && transaction)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Transaction-ID: %s", transaction));
		/* Add live information */
		if (g_strcmp0(*header, "uptime") == 0) {
			g_autofree gchar *uptime = get_uptime();
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Uptime: %s", uptime));
		}
	}

no_std_headers:

	if (r_context()->system_info) {
		GHashTableIter iter;
		gchar *key = NULL;
		gchar *value = NULL;

		g_hash_table_iter_init(&iter, r_context()->system_info);
		while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
			gchar *header = system_info_to_header(key, value);
			if (header)
				g_ptr_array_add(headers, header);
		}
	}

	return g_steal_pointer(&headers);
}
void clear_bundle_access_args(RaucBundleAccessArgs *access_args)
{
	if (ENABLE_STREAMING) {
		g_free(access_args->tls_cert);
		g_free(access_args->tls_key);
		g_free(access_args->tls_ca);
		g_strfreev(access_args->http_headers);
		g_clear_pointer(&access_args->http_info_headers, g_ptr_array_unref);
	}

	memset(access_args, 0, sizeof(*access_args));
}
