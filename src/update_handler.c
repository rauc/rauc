#include <errno.h>
#include <fcntl.h>
#include <gio/gunixoutputstream.h>
#include <mtd/ubi-user.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "context.h"
#include "mount.h"
#include "signature.h"
#include "update_handler.h"
#include "emmc.h"
#include "utils.h"


#define R_SLOT_HOOK_PRE_INSTALL "slot-pre-install"
#define R_SLOT_HOOK_POST_INSTALL "slot-post-install"
#define R_SLOT_HOOK_INSTALL "slot-install"

#define CLEAR_BLOCK_SIZE 1024

GQuark r_update_error_quark(void)
{
	return g_quark_from_static_string("r_update_error_quark");
}

/* the fd will only live as long as the returned output stream */
static GUnixOutputStream* open_slot_device(RaucSlot *slot, int *fd, GError **error)
{
	GUnixOutputStream *outstream = NULL;
	GFile *destslotfile = NULL;
	GError *ierror = NULL;
	int fd_out;

	destslotfile = g_file_new_for_path(slot->device);

	fd_out = open(g_file_get_path(destslotfile), O_WRONLY | O_EXCL);

	if (fd_out == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"opening output device failed: %s", strerror(errno));
		goto out;
	}

	outstream = (GUnixOutputStream *) g_unix_output_stream_new(fd_out, TRUE);
	if (outstream == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"failed to open file for writing: ");
		goto out;
	}

	if (fd != NULL)
		*fd = fd_out;

out:
	return outstream;
}

#if ENABLE_EMMC_BOOT_SUPPORT == 1
static gboolean clear_slot(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	static gchar zerobuf[CLEAR_BLOCK_SIZE] = {};
	g_autoptr(GOutputStream) outstream = NULL;
	int out_fd;
	gint write_count = 0;

	outstream = (GOutputStream *) open_slot_device(slot, &out_fd, &ierror);
	if (outstream == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	while (write_count != -1) {
		write_count = g_output_stream_write(outstream, zerobuf, CLEAR_BLOCK_SIZE, NULL,
				&ierror);
		/*
		 * G_IO_ERROR_NO_SPACE is expected here, because the block
		 * device is cleared completely
		 */
		if (write_count == -1 &&
		    !g_error_matches(ierror, G_IO_ERROR, G_IO_ERROR_NO_SPACE)) {
			g_propagate_prefixed_error(error, ierror,
					"failed clearing block device: ");
			goto out;
		}
	}

	res = g_output_stream_close(outstream, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;

out:
	return res;
}
#endif

static gboolean ubifs_ioctl(RaucImage *image, int fd, GError **error)
{
	int ret;
	gint64 size = image->checksum.size;

	/* set up ubi volume for image copy */
	ret = ioctl(fd, UBI_IOCVOLUP, &size);
	if (ret == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"ubi volume update failed: %s", strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean copy_raw_image(RaucImage *image, GUnixOutputStream *outstream, GError **error)
{
	GError *ierror = NULL;
	gssize size;
	g_autoptr(GFile) srcimagefile = g_file_new_for_path(image->filename);
	int out_fd = g_unix_output_stream_get_fd(outstream);

	g_autoptr(GInputStream) instream = (GInputStream*)g_file_read(srcimagefile, NULL, &ierror);
	if (instream == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to open file for reading: ");
		return FALSE;
	}

	/* Do not close fd automatically to give us the chance to call fsync() on it before closing */
	g_unix_output_stream_set_close_fd(outstream, FALSE);

	size = g_output_stream_splice((GOutputStream *) outstream, instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
			NULL,
			&ierror);
	if (size == -1) {
		g_propagate_prefixed_error(error, ierror,
				"Failed splicing data: ");
		return FALSE;
	} else if (size != (gssize)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Written size (%"G_GSIZE_FORMAT ") != image size (%"G_GSIZE_FORMAT ")", size, (gssize)image->checksum.size);
		return FALSE;
	}

	/* flush to block device before closing to assure content is written to disk */
	if (fsync(out_fd) == -1) {
		close(out_fd); /* Silent attempt to close as we failed, anyway */
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Syncing content to disk failed: %s", strerror(errno));
		return FALSE;
	}

	if (close(out_fd) == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Closing output device failed: %s", strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean casync_extract(RaucImage *image, gchar *dest, const gchar *seed, const gchar *store, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("casync"));
	g_ptr_array_add(args, g_strdup("extract"));
	if (seed) {
		g_ptr_array_add(args, g_strdup("--seed"));
		g_ptr_array_add(args, g_strdup(seed));
	}
	if (store) {
		g_ptr_array_add(args, g_strdup("--store"));
		g_ptr_array_add(args, g_strdup(store));
	}
	g_ptr_array_add(args, g_strdup("--seed-output=no"));
	g_ptr_array_add(args, g_strdup(image->filename));
	g_ptr_array_add(args, g_strdup(dest));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start casync extract: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run casync extract: ");
		goto out;
	}

out:
	return res;
}

static RaucSlot *get_active_slot_class_member(gchar *slotclass)
{
	RaucSlot *iterslot;
	GHashTableIter iter;

	g_return_val_if_fail(slotclass, NULL);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&iterslot)) {
		if (iterslot->state == ST_INACTIVE)
			continue;

		if (g_strcmp0(iterslot->sclass, slotclass) == 0) {
			return iterslot;
		}
	}

	return NULL;
}

static gboolean casync_extract_image(RaucImage *image, gchar *dest, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	RaucSlot *seedslot = NULL;
	g_autofree gchar *seed = NULL;
	gchar *store = NULL;
	gboolean seed_mounted = FALSE;

	/* Prepare Seed */
	seedslot = get_active_slot_class_member(image->slotclass);
	if (!seedslot) {
		g_warning("No seed slot available for %s", image->slotclass);
		goto extract;
	}

	if (g_str_has_suffix(image->filename, ".caidx" )) {
		/* We need to have the seed slot (bind) mounted to a distinct
		 * path to allow seeding. E.g. using mount path '/' for the
		 * rootfs slot seed is inaproppriate as it contains virtual
		 * file systems, additional mounts, etc. */
		if (!seedslot->mount_point) {
			g_debug("Mounting %s to use as seed", seedslot->device);
			res = r_mount_slot(seedslot, &ierror);
			if (!res) {
				g_warning("Failed mounting for seeding: %s", ierror->message);
				g_clear_error(&ierror);
				goto extract;
			}
			seed_mounted = TRUE;
		}

		g_debug("Adding as casync directory tree seed: %s", seedslot->mount_point);
		seed = g_strdup(seedslot->mount_point);
	} else {
		g_debug("Adding as casync blob seed: %s", seedslot->device);
		seed = g_strdup(seedslot->device);
	}

extract:
	/* Set store */
	store = r_context()->install_info->mounted_bundle->storepath;
	g_debug("Using store path: '%s'", store);

	/* Call casync to extract */
	res = casync_extract(image, dest, seed, store, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* Cleanup seed */
	if (seed_mounted) {
		res = r_umount_slot(seedslot, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Failed unmounting seed slot: ");
			goto out;
		}
	}

	res = TRUE;
out:
	return res;
}

static gboolean copy_raw_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	g_autoptr(GUnixOutputStream) outstream = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* open */
	g_message("opening slot device %s", slot->device);
	outstream = open_slot_device(slot, NULL, &ierror);
	if (outstream == NULL) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* copy */
	g_message("writing data to device %s", slot->device);
	res = copy_raw_image(image, outstream, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

static gboolean write_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* Handle casync index file */
	if (g_str_has_suffix(image->filename, ".caibx")) {
		g_message("Extracting %s to %s", image->filename, slot->device);

		/* Extract caibx to device */
		res = casync_extract_image(image, slot->device, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}

	} else {
		res = copy_raw_image_to_dev(image, slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

static gboolean ubifs_format_slot(RaucSlot *dest_slot, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(3, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ubifs"));
	g_ptr_array_add(args, g_strdup("-y"));
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start mkfs.ubifs: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run mkfs.ubifs: ");
		goto out;
	}

out:
	return res;
}

static gboolean ext4_resize_slot(RaucSlot *dest_slot, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(3, g_free);

	g_ptr_array_add(args, g_strdup("resize2fs"));
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start resize2fs: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run resize2fs: ");
		goto out;
	}

out:
	return res;
}

static gboolean ext4_format_slot(RaucSlot *dest_slot, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ext4"));
	g_ptr_array_add(args, g_strdup("-F"));
	if (strlen(dest_slot->name) <= 16) {
		g_ptr_array_add(args, g_strdup("-L"));
		g_ptr_array_add(args, g_strdup(dest_slot->name));
	}
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start mkfs.ext4: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run mkfs.ext4: ");
		goto out;
	}

out:
	return res;
}

static gboolean vfat_format_slot(RaucSlot *dest_slot, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.vfat"));
	if (strlen(dest_slot->name) <= 16) {
		g_ptr_array_add(args, g_strdup("-n"));
		g_ptr_array_add(args, g_strdup(dest_slot->name));
	}
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start mkfs.vfat: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run mkfs.vfat: ");
		goto out;
	}

out:
	return res;
}

static gboolean nand_format_slot(const gchar *device, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("flash_erase"));
	g_ptr_array_add(args, g_strdup("--quiet"));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start flash_erase: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run flash_erase: ");
		goto out;
	}

out:
	return res;
}

static gboolean nand_write_slot(const gchar *image, const gchar *device, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("nandwrite"));
	g_ptr_array_add(args, g_strdup("--pad"));
	g_ptr_array_add(args, g_strdup("--quiet"));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, g_strdup(image));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start nandwrite: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run nandwrite: ");
		goto out;
	}

out:
	return res;
}

static gboolean untar_image(RaucImage *image, gchar *dest, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("xf"));
	g_ptr_array_add(args, g_strdup(image->filename));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(dest));
	g_ptr_array_add(args, g_strdup("--numeric-owner"));
	g_ptr_array_add(args, NULL);

	r_debug_subprocess(args);
	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start tar extract: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run tar extract: ");
		goto out;
	}

out:
	return res;
}

static gboolean unpack_archive(RaucImage *image, gchar *dest, GError **error)
{
	if (g_str_has_suffix(image->filename, ".caidx" ))
		return casync_extract_image(image, dest, error);
	else if (g_str_has_suffix(image->filename, ".catar" ))
		return casync_extract_image(image, dest, error);
	else
		return untar_image(image, dest, error);
}

/**
 * Executes the per-slot hook script.
 *
 * @param hook_name file name of the hook script
 * @param hook_cmd first argument to the hook script
 * @param image image to be installed (optional)
 * @param slot target slot
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
static gboolean run_slot_hook(const gchar *hook_name, const gchar *hook_cmd, RaucImage *image, RaucSlot *slot, GError **error)
{
	g_autoptr(GSubprocessLauncher) launcher = NULL;
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_assert_nonnull(slot);
	g_assert_nonnull(slot->name);
	g_assert_nonnull(slot->sclass);

	g_message("Running slot hook %s for %s", hook_cmd, slot->name);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_COMPATIBLE", r_context()->config->system_compatible ?: "", TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_VARIANT", r_context()->config->system_variant ?: "", TRUE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_NAME", slot->name, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_STATE", slotstate_to_str(slot->state), TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_CLASS", slot->sclass, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_TYPE", slot->type, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_DEVICE", slot->device, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_BOOTNAME", slot->bootname ?: "", TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_PARENT", slot->parent ? slot->parent->name : "", TRUE);
	if (slot->mount_point) {
		g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_MOUNT_POINT", slot->mount_point, TRUE);
	}
	if (image) {
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_NAME", image->filename, TRUE);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_DIGEST", image->checksum.digest, TRUE);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_CLASS", image->slotclass, TRUE);
	}
	g_subprocess_launcher_setenv(launcher, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	if (r_context()->install_info->mounted_bundle) {
		gchar **hashes = NULL;
		gchar *string = NULL;

		hashes = get_pubkey_hashes(r_context()->install_info->mounted_bundle->verified_chain);
		string = g_strjoinv(" ", hashes);
		g_strfreev(hashes);

		g_subprocess_launcher_setenv(launcher, "RAUC_BUNDLE_SPKI_HASHES", string, FALSE);
		g_free(string);
	}

	sproc = g_subprocess_launcher_spawn(
			launcher, &ierror,
			hook_name,
			hook_cmd,
			NULL);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start slot hook: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run slot hook: ");
		goto out;
	}

out:
	return res;
}

static gboolean mount_and_run_slot_hook(const gchar *hook_name, const gchar *hook_cmd, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_assert_nonnull(hook_name);
	g_assert_nonnull(hook_cmd);

	/* mount slot */
	g_message("Mounting slot %s", slot->device);
	res = r_mount_slot(slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot install hook */
	g_message("Running slot '%s' hook for %s", hook_cmd, slot->name);
	res = run_slot_hook(hook_name, hook_cmd, NULL, slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
	}

	/* finally umount slot */
	g_message("Unmounting slot %s", slot->device);
	if (!r_umount_slot(slot, &ierror)) {
		res = FALSE;
		if (error && *error) {
			/* the slot hook error is more relevant here */
			g_warning("Ignoring umount error after slot hook error: %s", ierror->message);
			g_clear_error(&ierror);
		} else {
			g_propagate_error(error, ierror);
		}
	}

out:
	return res;
}

static gboolean img_to_ubivol_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	g_autoptr(GUnixOutputStream) outstream = NULL;
	GError *ierror = NULL;
	int out_fd;
	gboolean res = FALSE;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* open */
	g_message("opening slot device %s", dest_slot->device);
	outstream = open_slot_device(dest_slot, &out_fd, &ierror);
	if (outstream == NULL) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* ubifs ioctl */
	res = ubifs_ioctl(image, out_fd, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* copy */
	res = copy_raw_image(image, outstream, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

static gboolean img_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	g_autoptr(GUnixOutputStream) outstream = NULL;
	GError *ierror = NULL;
	int out_fd;
	gboolean res = FALSE;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* open */
	g_message("opening slot device %s", dest_slot->device);
	outstream = open_slot_device(dest_slot, &out_fd, &ierror);
	if (outstream == NULL) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* ubifs ioctl */
	res = ubifs_ioctl(image, out_fd, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* copy */
	res = copy_raw_image(image, outstream, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

static gboolean archive_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* format ubi volume */
	g_message("Formatting ubifs slot %s", dest_slot->device);
	res = ubifs_format_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* mount ubi volume */
	g_message("Mounting ubifs slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* extract tar into mounted ubi volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = unpack_archive(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount ubi volume */
	g_message("Unmounting ubifs slot %s", dest_slot->device);
	if (!r_umount_slot(dest_slot, &ierror)) {
		res = FALSE;
		if (error && *error) {
			/* the previous error is more relevant here */
			g_warning("Ignoring umount error after previous error: %s", ierror->message);
			g_clear_error(&ierror);
		} else {
			g_propagate_error(error, ierror);
		}
	}

out:
	return res;
}

static gboolean archive_to_ext4_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* format ext4 volume */
	g_message("Formatting ext4 slot %s", dest_slot->device);
	res = ext4_format_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* mount ext4 volume */
	g_message("Mounting ext4 slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* extract tar into mounted ext4 volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = unpack_archive(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount ext4 volume */
	g_message("Unmounting ext4 slot %s", dest_slot->device);
	if (!r_umount_slot(dest_slot, &ierror)) {
		res = FALSE;
		if (error && *error) {
			/* the previous error is more relevant here */
			g_warning("Ignoring umount error after previous error: %s", ierror->message);
			g_clear_error(&ierror);
		} else {
			g_propagate_error(error, ierror);
		}
	}

out:
	return res;
}

static gboolean archive_to_vfat_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* format vfat volume */
	g_message("Formatting vfat slot %s", dest_slot->device);
	res = vfat_format_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* mount vfat volume */
	g_message("Mounting vfat slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* extract tar into mounted vfat volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = unpack_archive(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount vfat volume */
	g_message("Unmounting vfat slot %s", dest_slot->device);
	if (!r_umount_slot(dest_slot, &ierror)) {
		res = FALSE;
		if (error && *error) {
			/* the previous error is more relevant here */
			g_warning("Ignoring umount error after previous error: %s", ierror->message);
			g_clear_error(&ierror);
		} else {
			g_propagate_error(error, ierror);
		}
	}

out:
	return res;
}

static gboolean img_to_nand_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* erase */
	g_message("erasing slot device %s", dest_slot->device);
	res = nand_format_slot(dest_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* write */
	g_message("writing slot device %s", dest_slot->device);
	res = nand_write_slot(image->filename, dest_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

static gboolean img_to_fs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* copy */
	res = write_image_to_dev(image, dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (dest_slot->resize && g_strcmp0(dest_slot->type, "ext4") == 0) {
		g_message("Resizing %s", dest_slot->device);
		res = ext4_resize_slot(dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install)  {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

#if ENABLE_EMMC_BOOT_SUPPORT == 1
static gboolean img_to_boot_emmc_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{

	gboolean res = FALSE;
	int out_fd;
	gint part_active;
	g_autofree gchar *part_active_str = NULL;
	gint part_active_after;
	g_autoptr(GUnixOutputStream) outstream = NULL;
	GError *ierror = NULL;
	g_autoptr(RaucSlot) part_slot = NULL;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(
				hook_name,
				R_SLOT_HOOK_PRE_INSTALL,
				NULL,
				dest_slot,
				&ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* read active boot partition from ext_csd */
	res = r_emmc_read_bootpart(dest_slot->device, &part_active, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}
	switch (part_active) {
		case -1:
			part_active_str = g_strdup("<none>");
			break;
		case 6:
			part_active_str = g_strdup(dest_slot->device);
			break;
		default:
			part_active_str = g_strdup_printf("%sboot%d", dest_slot->device,
					part_active);
	}
	g_message("Found active eMMC boot partition %s", part_active_str);

	/* create a temporary RaucSlot with the actual (currently inactive) boot
	 * partition as device; for simplicity reasons: in case the user partition
	 * is active use mmcblkXboot1, in case no partition is active use mmcblkXboot0
	 */
	part_slot = g_new0(RaucSlot, 1);
	part_slot->device = g_strdup_printf(
			"%sboot%d",
			dest_slot->device,
			INACTIVE_BOOT_PARTITION(part_active));

	/* disable read-only on determined eMMC boot partition */
	g_debug("Disabling read-only mode of slot device partition %s",
			part_slot->device);
	res = r_emmc_force_part_rw(part_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* clear block device partition */
	g_message("Clearing slot device %s", part_slot->device);
	res = clear_slot(part_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* open */
	g_message("Opening slot device partition %s", part_slot->device);
	outstream = open_slot_device(part_slot, &out_fd, &ierror);
	if (outstream == NULL) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto out;
	}

	/* copy */
	g_message("Copying image to slot device partition %s",
			part_slot->device);
	res = copy_raw_image(image, outstream, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* reenable read-only on determined eMMC boot partition */
	g_debug("Reenabling read-only mode of slot device partition %s",
			part_slot->device);
	res = r_emmc_force_part_ro(part_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* toggle active boot partition in ext_csd register; do this explicitly on
	 * determined boot partition to force the kernel to switch to the partition;
	 * for simplicity reasons: in case the user partition is active use
	 * mmcblkXboot1, in case no partition is active use mmcblkXboot0
	 */
	g_debug("Toggling active eMMC boot partition %s -> %s", part_active_str,
			part_slot->device);
	res = r_emmc_write_bootpart(
			part_slot->device,
			INACTIVE_BOOT_PARTITION(part_active),
			&ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* sanity check: read active boot partition from ext_csd
	 *
	 * Read explicitly from root device (this forces another kernel
	 * partition switch and should trigger the ext_csd bug more reliably).
	 */
	res = r_emmc_read_bootpart(dest_slot->device, &part_active_after, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (part_active == part_active_after) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Toggling the boot partition failed! Your kernel is most-likely affected by the ioctl ext_csd bug: see http://rauc.readthedocs.io/en/latest/advanced.html#update-emmc-boot-partitions");
		res = FALSE;
		goto out;
	}

	g_message("Boot partition %s is now active", part_slot->device);

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(
				hook_name,
				R_SLOT_HOOK_POST_INSTALL,
				NULL,
				dest_slot,
				&ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	/* ensure that the eMMC boot partition is read-only afterwards */
	if (!res && part_slot)
		r_emmc_force_part_ro(part_slot->device, NULL);

	return res;
}
#endif

static gboolean img_to_raw_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* copy */
	res = write_image_to_dev(image, dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, NULL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	return res;
}

static gboolean hook_install_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* run slot install hook */
	g_message("Running custom slot install hook for %s", dest_slot->name);
	res = run_slot_hook(hook_name, R_SLOT_HOOK_INSTALL, image, dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

typedef struct {
	const gchar *src;
	const gchar *dest;
	img_to_slot_handler handler;
} RaucUpdatePair;

RaucUpdatePair updatepairs[] = {
	{"*.ext4.caibx", "ext4", img_to_fs_handler},
	{"*.ext4.caibx", "raw", img_to_raw_handler},
	{"*.vfat.caibx", "raw", img_to_raw_handler},
	//{"*.ubifs.caibx", "ubivol", img_to_ubivol_handler}, /* unsupported */
	//{"*.ubifs.caibx", "ubifs", img_to_ubifs_handler}, /* unsupported */
	//{"*.img.caibx", "nand", img_to_nand_handler}, /* unsupported */
	//{"*.img.caibx", "ubivol", img_to_ubivol_handler}, /* unsupported */
	//{"*.squashfs.caibx", "ubivol", img_to_ubivol_handler}, /* unsupported */
	{"*.img.caibx", "*", img_to_raw_handler}, /* fallback */
	{"*.caidx", "ext4", archive_to_ext4_handler},
	{"*.caidx", "ubifs", archive_to_ubifs_handler},
	{"*.caidx", "vfat", archive_to_vfat_handler},
	{"*.ext4", "ext4", img_to_fs_handler},
	{"*.ext4", "raw", img_to_raw_handler},
	{"*.vfat", "raw", img_to_raw_handler},
	{"*.squashfs", "raw", img_to_raw_handler},
	{"*.vfat", "vfat", img_to_fs_handler},
	{"*.tar*", "ext4", archive_to_ext4_handler},
	{"*.catar", "ext4", archive_to_ext4_handler},
	{"*.tar*", "ubifs", archive_to_ubifs_handler},
	{"*.tar*", "vfat", archive_to_vfat_handler},
	{"*.ubifs", "ubivol", img_to_ubivol_handler},
	{"*.ubifs", "ubifs", img_to_ubifs_handler},
	{"*.img", "ext4", img_to_fs_handler},
	{"*.img", "nand", img_to_nand_handler},
	{"*.img", "ubifs", img_to_ubifs_handler},
	{"*.img", "ubivol", img_to_ubivol_handler},
	{"*.img", "vfat", img_to_fs_handler},
	{"*.squashfs", "ubivol", img_to_ubivol_handler},
#if ENABLE_EMMC_BOOT_SUPPORT == 1
	{"*.img", "boot-emmc", img_to_boot_emmc_handler},
#endif
	{"*.img", "*", img_to_raw_handler}, /* fallback */
	{0}
};

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot *dest_slot, GError **error)
{
	const gchar *src = mfimage->filename;
	const gchar *dest = dest_slot->type;
	img_to_slot_handler handler = NULL;

	/* If we have a custom install handler, use this instead of selecting an existing one */
	if (mfimage->hooks.install) {
		return hook_install_handler;
	}

	g_message("Checking image type for slot type: %s", dest);

	for (RaucUpdatePair *updatepair = updatepairs; updatepair->handler != NULL; updatepair++) {
		if (g_pattern_match_simple(updatepair->src, src) &&
		    g_pattern_match_simple(updatepair->dest, dest)) {
			g_message("Image detected as type: %s", updatepair->src);
			handler = updatepair->handler;
			break;
		}
	}

	if (handler == NULL)  {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_NO_HANDLER, "Unsupported image %s for slot type %s",
				mfimage->filename, dest);
		goto out;
	}

out:
	return handler;
}
