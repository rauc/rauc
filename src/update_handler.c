#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gunixinputstream.h>
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
#include "update_utils.h"
#include "emmc.h"
#include "mbr.h"
#include "gpt.h"
#include "utils.h"
#include "hash_index.h"

#define R_SLOT_HOOK_PRE_INSTALL "slot-pre-install"
#define R_SLOT_HOOK_POST_INSTALL "slot-post-install"
#define R_SLOT_HOOK_INSTALL "slot-install"

#define CLEAR_BLOCK_SIZE 1024

GQuark r_update_error_quark(void)
{
	return g_quark_from_static_string("r_update_error_quark");
}

/**
 * Checks if given image fits into the (block) device.
 *
 * Checks if the image size fits into the block device referred to by the
 * provided file descriptor.
 * If the size cannot be determined, the image is assumed to fit.
 *
 * Additionally, if a slot is given and the slot has a 'size-limit' set, the
 * image is checked against this limit first.
 *
 * @param fd file descriptor of device to check
 * @param slot slot (e.g. for optional size-limit check)
 * @param image image to check
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if image fits into device (or size-limit) or if no size can be determined. FALSE otherwise.
 */
static gboolean check_image_size(int fd, const RaucSlot *slot, const RaucImage *image, GError **error)
{
	GError *ierror = NULL;
	goffset dev_size;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (slot->size_limit > 0 && (guint64)image->checksum.size > slot->size_limit) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Image size (%"G_GOFFSET_FORMAT " bytes) is larger than size-limit (%"G_GUINT64_FORMAT " bytes).",
				image->checksum.size, slot->size_limit);
		return FALSE;
	}

	dev_size = get_device_size(fd, &ierror);
	if (g_error_matches(ierror, R_UTILS_ERROR, R_UTILS_ERROR_INAPPROPRIATE_IOCTL)) {
		g_clear_error(&ierror);
		g_info("Slot is not a block device, skipping size check");
		return TRUE;
	}

	/* Sanity check for size limit being < device size.
	 * Should be moved to a proper location for configuration vs. target checks (maybe context setup) and become an error later. */
	if (slot->size_limit > 0 && slot->size_limit > (guint64)dev_size) {
		g_warning("The size-limit (%"G_GUINT64_FORMAT " bytes) exceeds actual device size (%"G_GOFFSET_FORMAT " bytes).",
				slot->size_limit, dev_size);
	}

	if (dev_size < image->checksum.size) {
		if (ierror) {
			g_propagate_error(error, ierror);
		} else {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
					"Slot (%"G_GOFFSET_FORMAT " bytes) is too small for image (%"G_GOFFSET_FORMAT " bytes).",
					dev_size, image->checksum.size);
		}
		return FALSE;
	}

	return TRUE;
}

#if ENABLE_EMMC_BOOT_SUPPORT == 1
static gboolean clear_slot(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	static gchar zerobuf[CLEAR_BLOCK_SIZE] = {};
	g_autoptr(GOutputStream) outstream = NULL;
	gint write_count = 0;
	guint64 total_written = 0;

	outstream = G_OUTPUT_STREAM(r_unix_output_stream_open_device(slot->device, NULL, &ierror));
	if (outstream == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	while (write_count != -1) {
		/* cap writes to slot->size_limit if set */
		gsize write_size = CLEAR_BLOCK_SIZE;
		if (slot->size_limit > 0 &&
		    total_written + write_size > slot->size_limit)
			write_size = slot->size_limit - total_written;

		write_count = g_output_stream_write(outstream, zerobuf, write_size, NULL,
				&ierror);
		/*
		 * G_IO_ERROR_NO_SPACE is expected here, because the block
		 * device is cleared completely
		 */
		if (write_count == -1) {
			if (g_error_matches(ierror, G_IO_ERROR, G_IO_ERROR_NO_SPACE)) {
				g_clear_error(&ierror);
				break;
			} else {
				g_propagate_prefixed_error(error, ierror,
						"failed clearing block device: ");
				return FALSE;
			}
		}

		total_written += write_count;
		if (slot->size_limit > 0 && total_written >= slot->size_limit)
			break;
	}

	if (slot->size_limit > 0)
		g_message("Cleared first %"G_GOFFSET_FORMAT " bytes on %s", total_written, slot->device);
	else
		g_debug("Cleared %"G_GOFFSET_FORMAT " bytes on %s", total_written, slot->device);

	if (!g_output_stream_close(outstream, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
#endif

/**
 * Clear the the memory area defined in dest_partition.
 *
 * @param device dev path (/dev/mmcblkX)
 * @param dest_partition partition to be cleared (start & size) *
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
static gboolean clear_boot_switch_partition(const gchar *device,
		const struct boot_switch_partition *dest_partition,
		GError **error)
{
	gboolean res = FALSE;
	static gchar zerobuf[512] = {};
	gint clear_size = sizeof(zerobuf);
	guint clear_count = 0;
	gint tmp_count = 0;
	gint fd;

	g_return_val_if_fail(device, FALSE);
	g_return_val_if_fail(dest_partition, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	fd = g_open(device, O_RDWR);
	if (fd == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Opening device failed: %s",
				g_strerror(errno));
		goto out;
	}

	if (lseek(fd, dest_partition->start, SEEK_SET) !=
	    (off_t)dest_partition->start) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to set file to position %"G_GUINT64_FORMAT ": %s",
				dest_partition->start, g_strerror(errno));
		goto out;
	}

	while (clear_count < dest_partition->size) {
		if ((dest_partition->size - clear_count) < sizeof(zerobuf))
			clear_size = dest_partition->size - clear_count;

		tmp_count = write(fd, zerobuf, clear_size);

		if (tmp_count < 0)
			break;

		clear_count += tmp_count;
	}

	if (clear_count != dest_partition->size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to clear partition: %s",
				g_strerror(errno));
		goto out;
	}
	res = TRUE;
out:
	if (fd >= 0)
		g_close(fd, NULL);

	return res;
}

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

static gboolean splice_with_progress(GUnixInputStream *image_stream,
		GUnixOutputStream *out_stream, GError **error)
{
	int in_fd = g_unix_input_stream_get_fd(image_stream);
	int out_fd = g_unix_output_stream_get_fd(out_stream);
	struct stat stat = {};
	ssize_t out_size = 0;
	goffset sum_size = 0;

	if (fstat(in_fd, &stat)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to fstat input: %s", g_strerror(err));
		return FALSE;
	}

	do {
		/* Splice in 1M blocks */
		out_size = splice(in_fd, NULL, out_fd, NULL, 1UL*1024*1024, 0);
		if (out_size == -1) {
			int err = errno;
			g_set_error(error, G_IO_ERROR, g_io_error_from_errno(err),
					"%s", g_strerror(err));
			return FALSE;
		}

		sum_size += out_size;

		/* emit progress info (but only when in progress context) */
		if (r_context()->progress)
			r_context_set_step_percentage("copy_image", sum_size * 100 / stat.st_size);
	} while (out_size);

	return TRUE;
}

static gboolean splice_file_to_outstream(const gchar *filename,
		GUnixOutputStream *out_stream, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GUnixInputStream) image_stream = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(out_stream, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	image_stream = r_open_unix_input_stream(filename, NULL, &ierror);
	if (image_stream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to open input file for splicing: ");
		return FALSE;
	}

	if (!splice_with_progress(image_stream, out_stream, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_output_stream_close(G_OUTPUT_STREAM(out_stream), NULL, &ierror) != TRUE) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed closing output pipe: ");
		return FALSE;
	}

	if (g_input_stream_close(G_INPUT_STREAM(image_stream), NULL, &ierror) != TRUE) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed closing input file: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean splice_file_to_process_stdin(const gchar *filename, GSubprocess *sproc,
		GError **error)
{
	GUnixOutputStream *out_stream = G_UNIX_OUTPUT_STREAM(g_subprocess_get_stdin_pipe(sproc));
	g_assert_nonnull(out_stream);

	return splice_file_to_outstream(filename, out_stream, error);
}

static gboolean copy_raw_image(RaucImage *image, GUnixOutputStream *outstream, gsize len_header_last, GError **error)
{
	GError *ierror = NULL;
	goffset seeksize;
	g_autoptr(GFile) srcimagefile = NULL;
	int out_fd = -1;
	g_autofree void *header = NULL;
	g_autoptr(GInputStream) instream = NULL;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(image->checksum.size >= 0, FALSE);
	g_return_val_if_fail(outstream, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	srcimagefile = g_file_new_for_path(image->filename);
	out_fd = g_unix_output_stream_get_fd(outstream);

	instream = G_INPUT_STREAM(g_file_read(srcimagefile, NULL, &ierror));
	if (instream == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to open file for reading: ");
		return FALSE;
	}

	if (len_header_last) {
		gsize sector_size = (gsize) get_sectorsize(out_fd);

		if (len_header_last != sector_size) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
					"Specified header length (%"G_GSIZE_FORMAT ") does not match sector size (%"G_GSIZE_FORMAT ")", len_header_last, sector_size);
			return FALSE;
		}

		header = g_malloc(len_header_last);

		if (!g_input_stream_read_all(instream, header, len_header_last, &len_header_last, NULL, &ierror)) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to read header: ");
			return FALSE;
		}

		if (lseek(out_fd, len_header_last, SEEK_CUR) == -1) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Failed to skip header: %s", strerror(errno));
			return FALSE;
		}
	}

	if (!r_copy_stream_with_progress(instream, G_OUTPUT_STREAM(outstream), image->checksum.size, &ierror)) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to copy data: ");
		return FALSE;
	}

	seeksize = g_seekable_tell(G_SEEKABLE(instream));

	if (seeksize != (goffset)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Written size (%"G_GOFFSET_FORMAT ") != image size (%"G_GOFFSET_FORMAT ")", seeksize, image->checksum.size);
		return FALSE;
	}

	if (len_header_last) {
		gsize bytes;

		if (fsync(out_fd) == -1) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Syncing content to disk failed: %s", strerror(errno));
			return FALSE;
		}

		if (lseek(out_fd, -seeksize, SEEK_CUR) == -1) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Failed to rewind output stream: %s", strerror(errno));
			return FALSE;
		}

		if (!g_output_stream_write_all(G_OUTPUT_STREAM(outstream), header, len_header_last, &bytes, NULL, &ierror)) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to write header: ");
			return FALSE;
		}
	}

	if (!g_input_stream_close(instream, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* flush to block device before closing to assure content is written to disk */
	if (fsync(out_fd) == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Syncing content to disk failed: %s", strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean write_boot_switch_partition(RaucImage *image, const gchar *device,
		const struct boot_switch_partition *dest_partition,
		gsize len_header_last,
		GError **error)
{
	GError *ierror = NULL;
	g_auto(filedesc) out_fd = -1;
	g_autoptr(GUnixOutputStream) outstream = NULL;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(device, FALSE);
	g_return_val_if_fail(dest_partition, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	out_fd = open(device, O_WRONLY);
	if (out_fd == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Opening output device failed: %s",
				strerror(errno));
		return FALSE;
	}

	if (lseek(out_fd, dest_partition->start, SEEK_SET) !=
	    (off_t)dest_partition->start) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to set file to position %"G_GUINT64_FORMAT,
				dest_partition->start);
		return FALSE;
	}

	outstream = G_UNIX_OUTPUT_STREAM(g_unix_output_stream_new(out_fd, FALSE));
	if (outstream == NULL) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to create output stream");
		return FALSE;
	}

	if (!copy_raw_image(image, outstream, len_header_last, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!g_output_stream_close(G_OUTPUT_STREAM(outstream), NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean casync_extract(RaucImage *image, gchar *dest, int out_fd, const gchar *seed, const gchar *store, const gchar *tmpdir, GError **error)
{
	g_autoptr(GSubprocessLauncher) launcher = NULL;
	g_autoptr(GSubprocess) sproc = NULL;
	g_auto(GStrv) casync_argvp = NULL;
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	if (r_context()->config->use_desync)
		g_ptr_array_add(args, g_strdup("desync"));
	else
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
	/* Desync doesn't have the --seed-output option */
	if (!r_context()->config->use_desync)
		g_ptr_array_add(args, g_strdup("--seed-output=no"));

	if (r_context()->config->casync_install_args != NULL) {
		if (!g_shell_parse_argv(r_context()->config->casync_install_args, NULL, &casync_argvp, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to parse casync extra args: ");
			return FALSE;
		}
		r_ptr_array_addv(args, casync_argvp, TRUE);
	}
	g_ptr_array_add(args, g_strdup(image->filename));
	g_ptr_array_add(args, g_strdup(out_fd >= 0 ? "-" : dest));
	g_ptr_array_add(args, NULL);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);

	if (out_fd >= 0) {
		/* Must be a copy: glib automatically closes stdout_fd, but we close out_fd as well */
		int out_fd_copy = dup(out_fd);
		if (out_fd_copy == -1) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
					"Failed to dup() output file descriptor: %s",
					strerror(errno));
			return FALSE;
		}
		g_subprocess_launcher_take_stdout_fd(launcher, out_fd_copy);
	}

	if (tmpdir)
		g_subprocess_launcher_setenv(launcher, "TMPDIR", tmpdir, TRUE);

	/* Enable Desync parsable progress updates */
	if (r_context()->config->use_desync)
		g_subprocess_launcher_setenv(launcher, "DESYNC_ENABLE_PARSABLE_PROGRESS", "1", TRUE);

	sproc = r_subprocess_launcher_spawnv(launcher, args, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start casync extract: ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sproc, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run casync extract: ");
		return FALSE;
	}

	return TRUE;
}

static RaucSlot *get_active_slot_class_member(gchar *slotclass)
{
	RaucSlot *iterslot;
	GHashTableIter iter;

	g_return_val_if_fail(slotclass, NULL);

	if (!r_context()->config->slots) {
		/* when no slots are configured, there can be not active slot */
		return NULL;
	}

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

static gboolean casync_extract_image(RaucImage *image, gchar *dest, int out_fd, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	RaucSlot *seedslot = NULL;
	g_autofree gchar *seed = NULL;
	gchar *store = NULL;
	gchar *tmpdir = NULL;
	gboolean seed_mounted = FALSE;

	g_assert_nonnull(r_context()->install_info);
	g_assert_nonnull(r_context()->install_info->mounted_bundle);
	g_assert_nonnull(r_context()->install_info->mounted_bundle->storepath);

	if (r_context()->config->use_desync) {
		/* TODO: do something clever to locate and/or generate the seed index file */
		goto extract;
	}

	/* Prepare Seed */
	seedslot = get_active_slot_class_member(image->slotclass);
	if (!seedslot) {
		g_message("No casync seed slot available for %s", image->slotclass);
		goto extract;
	}

	if (g_str_has_suffix(image->filename, ".caidx")) {
		/* We need to have the seed slot (bind) mounted to a distinct
		 * path to allow seeding. E.g. using mount path '/' for the
		 * rootfs slot seed is inaproppriate as it contains virtual
		 * file systems, additional mounts, etc. */
		if (!seedslot->mount_point) {
			g_debug("Mounting %s to use as casync seed", seedslot->device);
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
		GStatBuf seedstat;

		/* For the moment do not utilize UBI volumes as seed because they are
		 * character devices - additional logic is needed to (temporarily) map
		 * them to UBIBLOCK devices which are suitable for that purpose */
		if (g_stat(seedslot->device, &seedstat) < 0 || S_ISCHR(seedstat.st_mode)) {
			g_message("Cannot use %s as seed device (non-existing or char device)", seedslot->device);
			goto extract;
		}

		g_debug("Adding as casync blob seed: %s", seedslot->device);
		seed = g_strdup(seedslot->device);
	}

extract:
	/* Set store */
	store = r_context()->install_info->mounted_bundle->storepath;
	g_debug("Using casync store path: '%s'", store);

	/* Set temporary directory */
	tmpdir = r_context()->config->tmp_path;
	if (tmpdir)
		g_debug("Using casync tmp path: '%s'", tmpdir);

	/* Call casync to extract */
	res = casync_extract(image, dest, out_fd, seed, store, tmpdir, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

	res = TRUE;

unmount_out:
	/* Cleanup seed */
	if (seed_mounted) {
		g_message("Unmounting seed slot %s", seedslot->device);
		ierror = NULL; /* any previous error was propagated already */
		if (!r_umount_slot(seedslot, &ierror)) {
			res = FALSE;
			if (error && *error) {
				/* the previous error is more relevant here */
				g_warning("Ignoring umount error after previous error: %s", ierror->message);
				g_clear_error(&ierror);
			} else {
				g_propagate_error(error, ierror);
			}
		}
	}

	return res;
}

/**
 * Writes given RaucImage to the device referred to by the given RaucSlot.
 *
 * Checks if the provided RaucImage fits into the target device before the copy
 * process starts.
 *
 * Copying is done using simple dd-like raw data copying.
 *
 * @param image RaucImage to write
 * @param slot RaucSlot to copy to
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success. FALSE on error.
 */
static gboolean copy_raw_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	g_autoptr(GUnixOutputStream) outstream = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* open */
	g_message("opening slot device %s", slot->device);
	outstream = r_unix_output_stream_open_device(slot->device, NULL, &ierror);
	if (outstream == NULL) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* check size */
	if (!check_image_size(g_unix_output_stream_get_fd(outstream), slot, image, &ierror)) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* copy */
	g_message("writing data to device %s", slot->device);
	res = copy_raw_image(image, outstream, 0, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = g_output_stream_close(G_OUTPUT_STREAM(outstream), NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

static gboolean copy_block_hash_index_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(RaucHashIndex) tmp = NULL;
	g_autoptr(GPtrArray) sources = NULL;
	const RaucSlot *seedslot = NULL;
	const guint8(*chunk_hashes)[32];
	guint32 chunk_count;
	g_autofree RaucHashIndexChunk *chunk = NULL;
	off_t offset = 0;
	int target_fd = -1;
	g_autoptr(RaucStats) zero_stats = NULL;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	zero_stats = r_stats_new("zero chunk");

	sources = g_ptr_array_new_with_free_func((GDestroyNotify)r_hash_index_free);

	/* If we have an index for the target slot, use it, otherwise generate and append for upper range. */
	/* Compared to open_slot_device, we need O_RDWR and seeking. */
	tmp = r_hash_index_open_slot("target_slot", slot, O_RDWR | O_EXCL, &ierror);
	if (!tmp) {
		g_propagate_prefixed_error(error, ierror, "failed to open target slot hash index for %s: ", slot->name);
		res = FALSE;
		goto out;
	}
	if (!check_image_size(tmp->data_fd, slot, image, &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto out;
	}

	/* emit progress info (when in progress context) since a new
	 * target_slot hash index might have been generated and that could
	 * have taken some time. */
	if (r_context()->progress)
		r_context_set_step_percentage("copy_image", R_HASH_INDEX_GEN_PROGRESS_SPAN);

	g_ptr_array_add(sources, g_steal_pointer(&tmp));

	/* Open and append seed slot. */
	seedslot = get_active_slot_class_member(image->slotclass);
	if (seedslot) {
		tmp = r_hash_index_open_slot("active_slot", seedslot, O_RDONLY, &ierror);
		if (!tmp) {
			g_propagate_prefixed_error(error, ierror, "failed to open active slot hash index for %s: ", seedslot->name);
			res = FALSE;
			goto out;
		}
		g_ptr_array_add(sources, g_steal_pointer(&tmp));
	} else {
		g_message("No active slot available to use as seed for %s", image->slotclass);
	}

	/* emit progress info (when in progress context) since a new
	 * active_slot hash index might have been generated and that could
	 * have taken some time. */
	if (r_context()->progress)
		r_context_set_step_percentage("copy_image", R_HASH_INDEX_GEN_PROGRESS_SPAN * 2);

	/* Open and append source image. */
	tmp = r_hash_index_open_image("source_image", image, &ierror);
	if (!tmp) {
		g_propagate_prefixed_error(error, ierror, "failed to open source image hash index for %s: ", image->filename);
		res = FALSE;
		goto out;
	}
	/* The bundle data is read-only and authenticated. */
	tmp->skip_hash_check = TRUE;
	g_ptr_array_add(sources, g_steal_pointer(&tmp));

	/* Open source index and target fd for lower range (reuse written chunks). */
	tmp = r_hash_index_reuse("target_slot_written",
			g_ptr_array_index(sources, sources->len - 1),
			dup(((RaucHashIndex*)g_ptr_array_index(sources, 0))->data_fd),
			&ierror);
	if (!tmp) {
		g_propagate_prefixed_error(error, ierror, "failed to reuse source hash index for target slot: ");
		res = FALSE;
		goto out;
	}
	/* Nothing is valid yet. */
	tmp->invalid_from = 0;
	/* This is the data we've just written. */
	tmp->skip_hash_check = TRUE;
	/* Insert the growing region in the target slot first. */
	g_ptr_array_insert(sources, 0, g_steal_pointer(&tmp));

	/* Now we have a GPtrArray of RaucHashIndices:
	 *
	 * 0: target slot with source index (for reuse of written chunks)
	 * 1: target slot with corresponding old index
	 * 2: active slot with corresponding index (optional)
	 * len-1: source image with corresponding index
	 */
	g_assert(sources->len <= 4);

	{
		const RaucHashIndex *target = g_ptr_array_index(sources, 0);
		const RaucHashIndex *source = g_ptr_array_index(sources, sources->len-1);
		target_fd = target->data_fd;
		chunk_hashes = g_bytes_get_data(source->hashes, NULL);
		chunk_count = source->count;
	}

	/* Ensure we start writing from the beginning */
	offset = 0;
	if (lseek(target_fd, offset, SEEK_SET) != offset) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Failed to seek to start of target slot: %s", g_strerror(errno));
		res = FALSE;
		goto out;
	}

	/* Temporary data storage */
	chunk = g_new0(RaucHashIndexChunk, 1);

	/* Iterate over chunks in source image */
	for (guint32 c = 0; c < chunk_count; c++) {
		gboolean found = FALSE;

		if (memcmp(chunk_hashes[c], R_HASH_INDEX_ZERO_CHUNK, 32) == 0) {
			/* Generate zero chunk */
			memset(chunk->data, 0, sizeof(chunk->data));
			found = TRUE;
			r_stats_add(zero_stats, 1);
		} else {
			/* Iterate over indices and call get chunk */
			for (guint s = 0; s < sources->len; s++) {
				const RaucHashIndex *source = g_ptr_array_index(sources, s);
				if (r_hash_index_get_chunk(source, chunk_hashes[c], chunk, &ierror)) {
					//g_autofree gchar *hash = r_hex_encode(chunk_hashes[c], sizeof(chunk_hashes[c]));
					//g_debug("found chunk %"G_GUINT32_FORMAT" [%s] in index %u [%s]", c, hash, s, source->label);
					found = TRUE;
					break;
				} else {
					//g_autofree gchar *hash = r_hex_encode(chunk_hashes[c], sizeof(chunk_hashes[c]));
					//g_debug("no chunk %"G_GUINT32_FORMAT" [%s] in index %u [%s]: %s", c, hash, s, source->label, ierror->message);
					g_clear_error(&ierror);
				}
			}
		}

		if (!found) {
			g_autofree gchar *hash = r_hex_encode(chunk_hashes[c], sizeof(chunk_hashes[c]));
			g_set_error(error,
					R_HASH_INDEX_ERROR,
					R_HASH_INDEX_ERROR_NOT_FOUND,
					"no chunk with required hash [%s] found", hash);
			res = FALSE;
			goto out;
		}

		/* Write chunk to target
		 *
		 * We could potentially avoid a chunk write if  r_hash_index_get_chunk
		 * would report where the chunk was found. If it was found on the target
		 * in the correct location, we could skip the write.
		 */
		offset = (off_t)c * sizeof(chunk->data);
		if (!r_pwrite_lazy(target_fd, chunk->data, sizeof(chunk->data), offset, &ierror)) {
			g_propagate_error(error, ierror);
			res = FALSE;
			goto out;
		}

		/* Update limits */
		{
			RaucHashIndex *target_written = g_ptr_array_index(sources, 0);
			RaucHashIndex *target_old = g_ptr_array_index(sources, 1);
			target_written->invalid_from = c+1;
			target_old->invalid_below = c;
		}

		/* emit progress info (but only when in progress context).
		 * Since the first 10 percent are reserved for the hash index
		 * generation, we just set the last 90 percent here. */
		if (r_context()->progress)
			r_context_set_step_percentage("copy_image", (R_HASH_INDEX_GEN_PROGRESS_SPAN * 2) + (c + 1) * (100 - (R_HASH_INDEX_GEN_PROGRESS_SPAN * 2)) / chunk_count);
	}

	/* Seek after the written data so this behaves similar to the simpler write helpers */
	offset = (off_t)chunk_count * sizeof(chunk->data);
	if (lseek(target_fd, offset, SEEK_SET) != offset) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Failed to seek to end of image: %s", g_strerror(errno));
		res = FALSE;
		goto out;
	}

	/* Flush to block device before closing to assure content is written to disk */
	if (fsync(target_fd) == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED, "Syncing content to slot failed: %s", strerror(errno));
		res = FALSE;
		goto out;
	}

	/* Write new index to slot data dir. */
	{
		const RaucHashIndex *source = g_ptr_array_index(sources, sources->len-1);
		if (!r_hash_index_export_slot(source, slot, &image->checksum, &ierror)) {
			g_warning("Continuing after failure to write new hash index: %s", ierror->message);
		}
	}

	r_stats_show(zero_stats, "access stats for");
	for (guint s = 0; s < sources->len; s++) {
		const RaucHashIndex *source = g_ptr_array_index(sources, s);
		r_stats_show(source->match_stats, "access stats for");
	}

	res = TRUE;

out:
	/* We let the hash index close the file and use dup for the target slot, to simplify cleanup */
	return res;
}

static gboolean copy_adaptive_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar* temp_string = NULL;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_strv_contains((const gchar * const*)image->adaptive, "block-hash-index")) {
		g_info("Selected adaptive update method 'block-hash-index'");

		if (!copy_block_hash_index_image_to_dev(image, slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		return TRUE;
	}

	temp_string = g_strjoinv(" ", (gchar**) image->adaptive);
	g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_UNSUPPORTED_ADAPTIVE_MODE,
			"No compatible adaptive method found in '%s'", temp_string);
	return FALSE;
}

/**
 * Writes given RaucImage to the device referred to by the given RaucSlot.
 *
 * Handles both casync .caibx images and adaptive methods, if present.
 * Otherwise (or on adaptive errors), it performs a raw copy.
 *
 * @param image RaucImage to write
 * @param slot RaucSlot to copy to
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success. FALSE on error.
 */
static gboolean write_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	/* Handle casync index file */
	if (g_str_has_suffix(image->filename, ".caibx")) {
		g_message("Extracting %s to %s", image->filename, slot->device);

		/* Extract caibx to device */
		if (!casync_extract_image(image, slot->device, -1, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		return TRUE;
	}

	/* Try adaptive mode */
	if (image->adaptive) {
		if (!slot->data_directory) {
			g_message("Ignoring adaptive method since 'data-directory' is not configured");
			goto raw_copy;
		}

		if (!copy_adaptive_image_to_dev(image, slot, &ierror)) {
			if (g_error_matches(ierror, R_UPDATE_ERROR, R_UPDATE_ERROR_UNSUPPORTED_ADAPTIVE_MODE)) {
				g_info("%s", ierror->message);
			} else {
				g_warning("Continuing after adaptive mode error: %s", ierror->message);
				/* Note that step progress can already be at a certain percentage at this point
				 * and will be reset to 0 when normal copying runs instead.
				 * This isn't propagated but high level progress may stall until step progress
				 * exceeds the current value again. */
			}
			g_clear_error(&ierror);
			/* Continue with full copy */
		} else {
			return TRUE;
		}
	}

raw_copy:
	/* Finally, try a raw copy */
	if (!copy_raw_image_to_dev(image, slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean ubifs_format_slot(RaucSlot *dest_slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(3, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ubifs"));
	g_ptr_array_add(args, g_strdup("-y"));
	r_ptr_array_addv(args, dest_slot->extra_mkfs_opts, TRUE);
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(3, g_free);

	g_ptr_array_add(args, g_strdup("resize2fs"));
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(6, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ext4"));
	g_ptr_array_add(args, g_strdup("-F"));
	if (strlen(dest_slot->name) <= 16) {
		g_ptr_array_add(args, g_strdup("-L"));
		g_ptr_array_add(args, g_strdup(dest_slot->name));
	}
	g_ptr_array_add(args, g_strdup("-I256"));
	r_ptr_array_addv(args, dest_slot->extra_mkfs_opts, TRUE);
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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

/**
 * Create valid / safe vfat label names.
 *
 * mkfs.vfat label requirements:
 *
 * | mkfs.fat: Warning: lowercase labels might not work properly on some systems
 * | mkfs.vfat: Labels with characters *?.,;:/\|+=<>[]" are not allowed
 * | mkfs.vfat: Label can be no longer than 11 characters
 *
 * This cuts input at 11 characters, makes all characters uppercase and
 * replaces all invalid characters by '_' (underscore)
 *
 * @param name input name to create vfat label from
 * @return newly-allocated string to be used as "-n" argument for mkfs.vfat
 */
static gchar* vfat_label_generator(const gchar *name)
{
	gchar *label_name;
	const gchar *invalid_chars = "*?.,;:/\\|+=<>[]\"";

	g_return_val_if_fail(name, NULL);

	/* limit label length to 11 characters */
	if (strlen(name) > 11)
		label_name = g_strndup(name, 11);
	else
		label_name = g_strdup(name);

	for (gchar *c = label_name; *c != '\0'; c++) {
		/* make chars uppercase */
		if (g_ascii_islower(*c))
			*c = g_ascii_toupper(*c);
		/* replace invalid chars */
		for (size_t i = 0; i < strlen(invalid_chars); i++) {
			if (*c == invalid_chars[i]) {
				*c = '_';
				break;
			}
		}
	}

	return label_name;
}

static gboolean vfat_format_slot(RaucSlot *dest_slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.vfat"));
	g_ptr_array_add(args, g_strdup("-n"));
	g_ptr_array_add(args, vfat_label_generator(dest_slot->name));
	r_ptr_array_addv(args, dest_slot->extra_mkfs_opts, TRUE);
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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

static gboolean nor_write_slot(const gchar *image, const gchar *device, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("flashcp"));
	g_ptr_array_add(args, g_strdup(image));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run flashcp: ");
		goto out;
	}

out:
	return res;
}

static gboolean flash_format_slot(const gchar *device, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("flash_erase"));
	g_ptr_array_add(args, g_strdup("--quiet"));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, NULL);

	res = r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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
	g_ptr_array_add(args, g_strdup("-"));
	g_ptr_array_add(args, NULL);

	sproc = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_STDIN_PIPE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start nandwrite: ");
		goto out;
	}

	res = splice_file_to_process_stdin(image, sproc, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to splice data to nandwrite: ");
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

struct suffix_tar_flag {
	const char *suffix;
	const char *tar_flag;
};

static struct suffix_tar_flag suffixes[] = {
	{".tar",	NULL},
	{".gz",		"-z"},
	{".tgz",	"-z"},
	{".taz",	"-z"},
	{".Z",		"-Z"},
	{".taZ",	"-Z"},
	{".bz2",	"-j"},
	{".tbz",	"-j"},
	{".tbz2",	"-j"},
	{".tz2",	"-j"},
	{".lz",		"--lzip"},
	{".lzma",	"--lzma"},
	{".tlz",	"--lzma"},
	{".lzo",	"--lzop"},
	{".xz",		"-J"},
	{".txz",	"-J"},
	{".zst",	"--zstd"},
	{".tzst",	"--zstd"},
	{NULL,		NULL}
};

static const gchar *suffix_to_tar_flag(const gchar *filename)
{
	g_return_val_if_fail(filename, NULL);

	for (int i = 0; suffixes[i].suffix != NULL; i++) {
		if (g_str_has_suffix(filename, suffixes[i].suffix))
			return suffixes[i].tar_flag;
	}

	return NULL;
}

static gboolean untar_image(RaucImage *image, gchar *dest, GError **error)
{
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("xf"));
	g_ptr_array_add(args, g_strdup("-"));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(dest));
	g_ptr_array_add(args, g_strdup("--numeric-owner"));
	g_ptr_array_add(args, g_strdup(suffix_to_tar_flag(image->filename)));
	g_ptr_array_add(args, NULL);

	sproc = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_STDIN_PIPE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start tar extract: ");
		goto out;
	}

	res = splice_file_to_process_stdin(image->filename, sproc, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to splice data to tar: ");
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
	if (g_str_has_suffix(image->filename, ".caidx"))
		return casync_extract_image(image, dest, -1, error);
	else if (g_str_has_suffix(image->filename, ".catar"))
		return casync_extract_image(image, dest, -1, error);
	else
		return untar_image(image, dest, error);
}

/**
 * Executes the per-slot hook script with extra environment variables.
 *
 * @param hook_name file name of the hook script
 * @param hook_cmd first argument to the hook script
 * @param image image to be installed (optional)
 * @param slot target slot
 * @param variables extra environment variables, or NULL
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
static gboolean run_slot_hook_extra_env(const gchar *hook_name, const gchar *hook_cmd, RaucImage *image, RaucSlot *slot, GHashTable *variables, GError **error)
{
	g_autoptr(GSubprocessLauncher) launcher = NULL;
	g_autoptr(GSubprocess) sproc = NULL;
	g_autofree gchar* image_size = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	RaucBundle *bundle;

	g_return_val_if_fail(hook_name, FALSE);
	g_return_val_if_fail(hook_cmd, FALSE);
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(slot->name, FALSE);
	g_return_val_if_fail(slot->sclass, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_message("Running slot hook '%s' for %s", hook_cmd, slot->name);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_COMPATIBLE", r_context()->config->system_compatible ?: "", TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_VARIANT", r_context()->config->system_variant ?: "", TRUE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_NAME", slot->name, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_STATE", r_slot_slotstate_to_str(slot->state), TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_CLASS", slot->sclass, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_TYPE", slot->type, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_DEVICE", slot->device, TRUE);
	if (slot->parent) {
		g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_BOOTNAME", slot->parent->bootname ?: "", TRUE);
	} else {
		g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_BOOTNAME", slot->bootname ?: "", TRUE);
	}
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_PARENT", slot->parent ? slot->parent->name : "", TRUE);
	if (slot->mount_point) {
		g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_MOUNT_POINT", slot->mount_point, TRUE);
	} else if (slot->ext_mount_point) {
		g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_MOUNT_POINT", slot->ext_mount_point, TRUE);
	}
	if (image) {
		image_size = g_strdup_printf("%" G_GOFFSET_FORMAT, image->checksum.size);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_NAME", image->filename ? image->filename : "", TRUE);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_SIZE", image_size, TRUE);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_DIGEST", image->checksum.digest ? image->checksum.digest : "", TRUE);
		g_subprocess_launcher_setenv(launcher, "RAUC_IMAGE_CLASS", image->slotclass, TRUE);
	}
	g_subprocess_launcher_setenv(launcher, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	bundle = r_context()->install_info->mounted_bundle;
	if (bundle) {
		g_auto(GStrv) hashes = get_pubkey_hashes(bundle->verified_chain);
		g_autofree gchar *string = g_strjoinv(" ", hashes);

		g_subprocess_launcher_setenv(launcher, "RAUC_BUNDLE_SPKI_HASHES", string, TRUE);

		g_subprocess_launcher_setenv(launcher, "RAUC_BUNDLE_MOUNT_POINT", bundle->mount_point, TRUE);
	}

	if (variables) {
		GHashTableIter iter;
		gchar *key = NULL;
		gchar *value = NULL;

		/* copy the variables from the hashtable and add them to the
		   subprocess environment */
		g_hash_table_iter_init(&iter, variables);
		while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
			g_subprocess_launcher_setenv(launcher, g_strdup(key), g_strdup(value), TRUE);
		}
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

/**
 * Executes the per-slot hook script without setting extra environment variables.
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
	return run_slot_hook_extra_env(hook_name, hook_cmd, image, slot, NULL, error);
}

static gboolean mount_and_run_slot_hook(const gchar *hook_name, const gchar *hook_cmd, RaucImage *image, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(hook_name, FALSE);
	g_return_val_if_fail(hook_cmd, FALSE);
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* mount slot */
	g_message("Mounting slot %s", slot->device);
	res = r_mount_slot(slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot install hook */
	g_message("Running slot '%s' hook for %s", hook_cmd, slot->name);
	res = run_slot_hook(hook_name, hook_cmd, image, slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
	}

	/* finally umount slot */
	g_message("Unmounting slot %s", slot->device);
	ierror = NULL; /* any previous error was propagated already */
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
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* open */
	g_message("opening slot device %s", dest_slot->device);
	outstream = r_unix_output_stream_open_device(dest_slot->device, &out_fd, &ierror);
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

	/* Handle casync index file */
	if (g_str_has_suffix(image->filename, ".caibx")) {
		g_message("Extracting %s to %s", image->filename, dest_slot->device);

		res = casync_extract_image(image, NULL, out_fd, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else {
		/* copy */
		res = copy_raw_image(image, outstream, 0, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = g_output_stream_close(G_OUTPUT_STREAM(outstream), NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
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
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* open */
	g_message("opening slot device %s", dest_slot->device);
	outstream = r_unix_output_stream_open_device(dest_slot->device, &out_fd, &ierror);
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

	/* Handle casync index file */
	if (g_str_has_suffix(image->filename, ".caibx")) {
		g_message("Extracting %s to %s", image->filename, dest_slot->device);

		res = casync_extract_image(image, NULL, out_fd, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	} else {
		/* copy */
		res = copy_raw_image(image, outstream, 0, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	res = g_output_stream_close(G_OUTPUT_STREAM(outstream), NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
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
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
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
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount ubi volume */
	g_message("Unmounting ubifs slot %s", dest_slot->device);
	ierror = NULL; /* any previous error was propagated already */
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

static gboolean archive_to_jffs2_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* erase */
	g_message("Erasing slot mtd device %s", dest_slot->device);
	res = flash_format_slot(dest_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* jffs2 needs no formatting - mount directly */
	g_message("Mounting jffs2 slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* extract tar into mounted jffs2 volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = unpack_archive(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount jffs2 volume */
	g_message("Unmounting jffs2 slot %s", dest_slot->device);
	ierror = NULL; /* any previous error was propagated already */
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
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
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

	/* 'emptyfs' image type does not have an archive included. So skip extraction. */
	if (g_strcmp0(image->type, "emptyfs") != 0) {
		/* extract tar into mounted ext4 volume */
		g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
		res = unpack_archive(image, dest_slot->mount_point, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount ext4 volume */
	g_message("Unmounting ext4 slot %s", dest_slot->device);
	ierror = NULL; /* any previous error was propagated already */
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
		res = run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror);
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
		res = run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto unmount_out;
		}
	}

unmount_out:
	/* finally umount vfat volume */
	g_message("Unmounting vfat slot %s", dest_slot->device);
	ierror = NULL; /* any previous error was propagated already */
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

static gboolean img_to_nor_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* erase */
	g_message("erasing slot device %s", dest_slot->device);
	if (!flash_format_slot(dest_slot->device, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* write */
	g_message("writing slot device %s", dest_slot->device);
	if (!nor_write_slot(image->filename, dest_slot->device, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean img_to_nand_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* erase */
	g_message("erasing slot device %s", dest_slot->device);
	if (!flash_format_slot(dest_slot->device, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* write */
	g_message("writing slot device %s", dest_slot->device);
	if (!nand_write_slot(image->filename, dest_slot->device, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean img_to_fs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		if (!mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* copy */
	if (!write_image_to_dev(image, dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (dest_slot->resize && g_strcmp0(dest_slot->type, "ext4") == 0) {
		g_message("Resizing %s", dest_slot->device);
		if (!ext4_resize_slot(dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		if (!mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean img_to_boot_mbr_switch_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	gboolean res = FALSE;
	int inactive_half;
	GError *ierror = NULL;
	struct boot_switch_partition dest_partition;
	g_autoptr(GHashTable) vars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	res = r_mbr_switch_get_inactive_partition(dest_slot->device,
			&dest_partition, dest_slot->region_start,
			dest_slot->region_size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (dest_partition.start == dest_slot->region_start)
		inactive_half = 0;
	else
		inactive_half = 1;

	g_message("Found inactive (%s) half of boot partition region (pos. %"G_GUINT64_FORMAT "B, size %"G_GUINT64_FORMAT "B)",
			inactive_half == 0 ? "first" : "second", dest_partition.start, dest_partition.size);

	if (dest_partition.size < (guint64)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Size of image (%"G_GOFFSET_FORMAT ") does not fit to slot size %"G_GUINT64_FORMAT,
				image->checksum.size, dest_partition.size);
		res = FALSE;
		goto out;
	}

	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_ACTIVATING"),
			g_strdup_printf("%d", inactive_half));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_START"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_partition.start));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_SIZE"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_partition.size));

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_PRE_INSTALL, image,
				dest_slot, vars, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	g_message("Clearing inactive (%s) half of boot partition region on %s", inactive_half == 0 ? "first" : "second",
			dest_slot->device);

	res = clear_boot_switch_partition(dest_slot->device, &dest_partition, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to clear inactive region: ");
		goto out;
	}

	g_message("Write image to inactive (%s) half of boot partition region on %s", inactive_half == 0 ? "first" : "second", dest_slot->device);

	res = write_boot_switch_partition(image, dest_slot->device, &dest_partition, 0, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to write inactive region: ");
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_POST_INSTALL, image,
				dest_slot, vars, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	g_message("Setting %s half of boot partition region active in MBR", inactive_half == 0 ? "first" : "second");

	res = r_mbr_switch_set_boot_partition(dest_slot->device, &dest_partition, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:

	return res;
}

#if ENABLE_GPT == 1
G_GNUC_UNUSED
static gboolean img_to_boot_gpt_switch_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	gboolean res = FALSE;
	int inactive_half;
	GError *ierror = NULL;
	struct boot_switch_partition dest_partition;
	g_autoptr(GHashTable) vars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	res = r_gpt_switch_get_inactive_partition(dest_slot->device,
			&dest_partition, dest_slot->region_start,
			dest_slot->region_size, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (dest_partition.start == dest_slot->region_start)
		inactive_half = 0;
	else
		inactive_half = 1;

	g_message("Found inactive (%s) half of boot partition region (pos. %"G_GUINT64_FORMAT "B, size %"G_GUINT64_FORMAT "B)",
			inactive_half == 0 ? "first" : "second", dest_partition.start, dest_partition.size);

	if (dest_partition.size < (guint64)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Size of image (%"G_GOFFSET_FORMAT ") does not fit to slot size %"G_GUINT64_FORMAT,
				image->checksum.size, dest_partition.size);
		res = FALSE;
		goto out;
	}

	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_ACTIVATING"),
			g_strdup_printf("%d", inactive_half));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_START"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_partition.start));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_SIZE"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_partition.size));

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_PRE_INSTALL, image,
				dest_slot, vars, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	g_message("Clearing inactive (%s) half of boot partition region on %s", inactive_half == 0 ? "first" : "second",
			dest_slot->device);

	res = clear_boot_switch_partition(dest_slot->device, &dest_partition, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to clear inactive partition: ");
		goto out;
	}

	g_message("Write image to inactive (%s) half of boot partition region on %s", inactive_half == 0 ? "first" : "second", dest_slot->device);

	res = write_boot_switch_partition(image, dest_slot->device, &dest_partition, 0, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to write inactive region: ");
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_POST_INSTALL, image,
				dest_slot, vars, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	g_message("Setting %s half of boot partition region active in GPT", inactive_half == 0 ? "first" : "second");

	res = r_gpt_switch_set_boot_partition(dest_slot->device, &dest_partition, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}
out:
	return res;
}
#endif

#if ENABLE_EMMC_BOOT_SUPPORT == 1
/**
 * Copies given image to eMMC boot partition.
 *
 * @param image Image to copy
 * @param slot Slot to copy to
 * @param hook_name name of the hook, or NULL
 * @param vars additional env vars to pass, or NULL
 * @param error return location for a GError, or NULL
 */
static gboolean copy_img_to_emmc_bootpart(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GHashTable *vars, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	/* disable read-only on determined eMMC boot partition */
	g_debug("Disabling read-only mode of slot device partition %s",
			dest_slot->device);
	res = r_emmc_force_part_rw(dest_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		res = run_slot_hook_extra_env(
				hook_name,
				R_SLOT_HOOK_PRE_INSTALL,
				image,
				dest_slot,
				vars,
				&ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* clear block device partition */
	g_message("Clearing slot device %s", dest_slot->device);
	res = clear_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (!copy_raw_image_to_dev(image, dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto out;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		res = run_slot_hook_extra_env(
				hook_name,
				R_SLOT_HOOK_POST_INSTALL,
				image,
				dest_slot,
				vars,
				&ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

	/* re-enable read-only on determined eMMC boot partition */
	g_debug("Reenabling read-only mode of slot device partition %s",
			dest_slot->device);
	res = r_emmc_force_part_ro(dest_slot->device, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	if (!res)
		r_emmc_force_part_ro(dest_slot->device, NULL);

	return res;
}

static gboolean img_to_boot_emmc_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	gboolean res = FALSE;
	gint part_active;
	g_autofree gchar *realdev = NULL;
	GError *ierror = NULL;
	g_autoptr(RaucSlot) part_slot = NULL;
	g_autoptr(GHashTable) vars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	realdev = r_realpath(dest_slot->device);
	if (!realdev) {
		g_set_error(error,
				R_UPDATE_ERROR,
				R_UPDATE_ERROR_FAILED,
				"Can't resolve eMMC device %s", dest_slot->device);
		return FALSE;
	}

	/* read active boot partition from ext_csd */
	res = r_emmc_read_bootpart(realdev, &part_active, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (part_active == -1) {
		g_warning("eMMC device was not enabled for booting, yet. Ignoring.");
		/* For simplicity: Consider boot1 to be active */
		part_active = 1;
	} else {
		g_message("Found active eMMC boot partition %sboot%d", realdev, part_active);
	}

	/* create a temporary RaucSlot with the actual (currently inactive) boot
	 * partition as device.
	 */
	part_slot = g_new0(RaucSlot, 1);
	part_slot->device = g_strdup_printf(
			"%sboot%d",
			realdev,
			INACTIVE_BOOT_PARTITION(part_active));
	part_slot->size_limit = dest_slot->size_limit;

	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_PARTITION_ACTIVATING"),
			g_strdup_printf("%d", INACTIVE_BOOT_PARTITION(part_active)));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_SIZE_LIMIT"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_slot->size_limit));

	/* To keep RAUC_SLOT_DEVICE consistent, override with the eMMC base
	 * device here. */
	g_hash_table_insert(vars, g_strdup("RAUC_SLOT_DEVICE"), g_strdup(realdev));

	res = copy_img_to_emmc_bootpart(image, part_slot, hook_name, vars, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!r_emmc_toggle_active_bootpart(realdev, part_active, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
static gboolean emmc_boot_linked_migration_helper(RaucImage *image, RaucSlot *dest_slot, GError **error)
{
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autofree gchar *real_dest = r_realpath(dest_slot->device);
	if (!real_dest) {
		g_set_error(error,
				R_UPDATE_ERROR,
				R_UPDATE_ERROR_FAILED,
				"Can't resolve eMMC device %s", dest_slot->device);
		return FALSE;
	}

	/* Get the base device for out destination partition so we can check which boot partition
	 * is actually activated */
	GError *ierror = NULL;
	g_autofree gchar *base_device = NULL;
	if (!r_emmc_extract_base_dev(real_dest, &base_device, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* read active boot partition from ext_csd. */
	gint active_partition = -1;
	if (!r_emmc_read_bootpart(base_device, &active_partition, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Device is not boot enabled at all, so there is nothing to switch */
	if (active_partition == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_EMMC_MIGRATION,
				"Device '%s' is not boot enabled", base_device);
		return FALSE;
	}

	/* Check if the target slot is the currently active eMMC boot partition */
	g_message("Active eMMC boot partition for %s: boot%d", real_dest, active_partition);
	g_autofree gchar *boot_suffix = g_strdup_printf("boot%d", active_partition);
	if (!g_str_has_suffix(dest_slot->device, boot_suffix)) {
		return TRUE;
	}

	/* If the target slot corresponds to the currently active eMMC boot partition,
	 * we assume it contains the running bootloader.
	 *
	 * To avoid bricking the device in case of an update failure,
	 * first copy the contents of the active boot partition to the inactive one.
	 * Then switch the active boot partition to the new one.
	 *
	 * This migration step ensures that a fallback bootloader is preserved,
	 * providing a recovery path in case something goes wrong.
	 */

	/* Create a temporary RaucSlot for the inactive boot partition */
	g_autoptr(RaucSlot) inactive_slot = g_new0(RaucSlot, 1);
	inactive_slot->device = g_strdup_printf("%sboot%d", base_device, INACTIVE_BOOT_PARTITION(active_partition));
	/* Create a temporary RaucImage using the active boot partition device as filename */
	g_autoptr(RaucImage) source_image = g_new0(RaucImage, 1);
	source_image->filename = g_strdup_printf("%sboot%d", base_device, active_partition);
	source_image->checksum.size = get_device_size_from_dev(source_image->filename, &ierror);
	if (ierror != NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_message("Preserving boot partition content by copying from %s to %s", source_image->filename, inactive_slot->device);
	if (!copy_img_to_emmc_bootpart(source_image, inactive_slot, NULL, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!r_emmc_toggle_active_bootpart(base_device, active_partition, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_message("The eMMC boot partition for %s has been successfully migrated", real_dest);
	return TRUE;
}

static gboolean img_to_emmc_boot_linked_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	GError *ierror = NULL;
	/* When migrating from a setup not supporting emmc-boot-linked, yet,
	 * the boot partitions might not yet be aligned as expected from the
	 * new linked config. So we have to check how they are aligned and
	 * ensure the target boot partition is not the currently activated one. */
	if (!emmc_boot_linked_migration_helper(image, dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* We've made sure that the boot partitions are properly set up during migration,
	 * so the image can now be written to the planned destination slot */
	if (!copy_img_to_emmc_bootpart(image, dest_slot, hook_name, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
#endif

static gboolean check_if_area_is_clear(const gchar *device, guint64 start, gsize size, gboolean *clear, GError **error)
{
	gboolean res = FALSE;
	g_autofree guchar *read_buf = NULL;
	gint read_size = 512;
	gint fd;

	g_return_val_if_fail(device, FALSE);
	g_return_val_if_fail(clear, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	read_buf = g_malloc0(read_size);

	fd = g_open(device, O_RDONLY);
	if (fd == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Opening device failed: %s",
				g_strerror(errno));
		goto out;
	}

	if (lseek(fd, start, SEEK_SET) != (off_t) start) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to set file to position %"G_GUINT64_FORMAT ": %s",
				start, g_strerror(errno));
		goto out;
	}

	*clear = TRUE;

	while (size && *clear) {
		gint read_count = 0;

		if (size < (gsize) read_size)
			read_size = size;

		read_count = read(fd, read_buf, read_size);
		if (read_count < 0)
			goto out;

		for (gint i = 0; i < read_count; i++) {
			if ((read_buf[i] != 0x00) && (read_buf[i] != 0xFF)) {
				*clear = FALSE;
				break;
			}
		}

		size -= read_count;
	}

	res = TRUE;

out:
	if (fd >= 0)
		g_close(fd, NULL);

	return res;
}

static gboolean img_to_boot_raw_fallback_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;
	guint64 half_size;
	gboolean primary_clear;
	struct part_desc {
		const char *name;
		struct boot_switch_partition partition;
	} part_desc[2];
	int first_part_desc_index = 0;
	g_autoptr(GHashTable) vars = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	const gsize header_size = 512;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(dest_slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	half_size = dest_slot->region_size / 2;

	/* Since down in copy_raw_image() the header size must match the sector size, checking the
	 * alignment to the header size also implicitly ensures sector alignment.
	 */
	if ((dest_slot->region_start % header_size) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region start %"G_GUINT64_FORMAT " is not aligned to the header size %"G_GSIZE_FORMAT,
				dest_slot->region_start, header_size);
		return FALSE;
	}

	if ((half_size % header_size) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Half region size %"G_GUINT64_FORMAT " is not aligned to the header size %"G_GSIZE_FORMAT,
				half_size, header_size);
		return FALSE;
	}

	if (half_size < (guint64)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Size of image (%"G_GOFFSET_FORMAT ") does not fit to slot size %"G_GUINT64_FORMAT,
				image->checksum.size, half_size);
		return FALSE;
	}

	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_REGION_START"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_slot->region_start));
	g_hash_table_insert(vars, g_strdup("RAUC_BOOT_REGION_SIZE"),
			g_strdup_printf("%"G_GUINT64_FORMAT, dest_slot->region_size));

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		if (!run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_PRE_INSTALL, image,
				dest_slot, vars, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	part_desc[0].name = "fallback";
	part_desc[0].partition.start = dest_slot->region_start + half_size;
	part_desc[0].partition.size = half_size;

	part_desc[1].name = "primary";
	part_desc[1].partition.start = dest_slot->region_start;
	part_desc[1].partition.size = half_size;

	/* If the primary partition is not fully programmed, it most likely means that the fallback
	 * partition was used to boot and is therefore valid. To avoid ending up with two broken partitions,
	 * upgrade the primary partition first.
	 */
	if (!check_if_area_is_clear(dest_slot->device, dest_slot->region_start, header_size, &primary_clear, &ierror)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to check area at %"G_GUINT64_FORMAT " on %s",
				dest_slot->region_start, dest_slot->device);
		return FALSE;
	}

	if (primary_clear)
		first_part_desc_index++;

	for (gint i = 0; i < 2; i++) {
		struct part_desc *pd = &part_desc[(first_part_desc_index + i) % 2];

		g_message("Updating %s partition at %"G_GUINT64_FORMAT " on %s", pd->name, pd->partition.start, dest_slot->device);

		if (!clear_boot_switch_partition(dest_slot->device, &pd->partition, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		if (!write_boot_switch_partition(image, dest_slot->device, &pd->partition, header_size, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		if (!run_slot_hook_extra_env(hook_name, R_SLOT_HOOK_POST_INSTALL, image,
				dest_slot, vars, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean img_to_raw_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;

	/* run slot pre install hook if enabled */
	if (hook_name && image->hooks.pre_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_PRE_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* copy */
	if (!write_image_to_dev(image, dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install) {
		if (!run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, image, dest_slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean hook_install_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GError *ierror = NULL;

	/* run slot install hook */
	if (!run_slot_hook(hook_name, R_SLOT_HOOK_INSTALL, image, dest_slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
typedef struct {
	const gchar *type;
	const gchar *slottype;
	img_to_slot_handler handler;
} RaucImageTypeMap;

/* Image type to handler mapping */
static RaucImageTypeMap image_type_map[] = {
	/* casync - caibx */
	{"ext4-caibx", "ext4", img_to_fs_handler},
	{"raw-caibx", "ext4", img_to_raw_handler},

	{"ext4-caibx", "raw", img_to_raw_handler},
	{"vfat-caibx", "raw", img_to_raw_handler},
	{"raw-caibx", "raw", img_to_raw_handler},
	{"raw-caibx", "vfat", img_to_raw_handler},
	{"raw-caibx", "jffs2", img_to_raw_handler},
	{"raw-caibx", "nor", img_to_raw_handler},
	{"raw-caibx", "nand", img_to_raw_handler},
	{"squashfs-caibx", "raw", img_to_raw_handler},

	{"squashfs-caibx", "ubivol", img_to_ubivol_handler},
	{"ubifs-caibx", "ubivol", img_to_ubivol_handler},
	{"raw-caibx", "ubivol", img_to_ubivol_handler},
	{"ubifs-caibx", "ubifs", img_to_ubifs_handler},
	{"raw-caibx", "ubifs", img_to_ubifs_handler},
	/* casync - caidx */
	{"caidx", "ext4", archive_to_ext4_handler},
	{"caidx", "ubifs", archive_to_ubifs_handler},
	{"caidx", "vfat", archive_to_vfat_handler},
	/* casync - catar */
	{"catar", "ext4", archive_to_ext4_handler},
	/* file system */
	{"ext4", "ext4", img_to_fs_handler},
	{"ext4", "raw", img_to_raw_handler},
	{"vfat", "vfat", img_to_fs_handler},
	{"vfat", "raw", img_to_raw_handler},
	{"squashfs", "ubivol", img_to_ubivol_handler},
	{"squashfs", "raw", img_to_raw_handler},
	{"ubifs", "ubivol", img_to_ubivol_handler},
	{"ubifs", "ubifs", img_to_ubifs_handler},
	/* raw */
	{"raw", "ext4", img_to_fs_handler},
	{"raw", "nor", img_to_nor_handler},
	{"raw", "nand", img_to_nand_handler},
	{"raw", "ubifs", img_to_ubifs_handler},
	{"raw", "ubivol", img_to_ubivol_handler},
	{"raw", "vfat", img_to_fs_handler},
	{"raw", "raw", img_to_raw_handler},
	{"raw", "jffs2", img_to_raw_handler},
	/* archive */
	{"tar", "ext4", archive_to_ext4_handler},
	{"tar", "ubifs", archive_to_ubifs_handler},
	{"tar", "vfat", archive_to_vfat_handler},
	{"tar", "jffs2", archive_to_jffs2_handler},
	/* boot-* slot types */
#if ENABLE_EMMC_BOOT_SUPPORT == 1
	{"raw", "boot-emmc", img_to_boot_emmc_handler},
	{"raw", "emmc-boot-linked", img_to_emmc_boot_linked_handler},
#endif
	{"vfat", "boot-mbr-switch", img_to_boot_mbr_switch_handler},
	{"raw", "boot-mbr-switch", img_to_boot_mbr_switch_handler},
#if ENABLE_GPT == 1
	{"vfat", "boot-gpt-switch", img_to_boot_gpt_switch_handler},
	{"ext4", "boot-gpt-switch", img_to_boot_gpt_switch_handler},
	{"raw", "boot-gpt-switch", img_to_boot_gpt_switch_handler},
#endif
	{"raw", "boot-raw-fallback", img_to_boot_raw_fallback_handler},
	{"emptyfs", "ext4", archive_to_ext4_handler},
	{NULL, NULL, NULL}
};

typedef struct {
	const gchar *fileext;
	const gchar *type;
} RaucFileExtTypeMap;

/* For compatibility reasons, this mapping is needed to map the former file
 * extension-based approach to the image types.
 * It must be ordered with more specific patterns first (e.g.
 * '*.squashfs-*.caibx' before '*.squashfs-*') to avoid selecting the wrong
 * image type. */
static RaucFileExtTypeMap ext_type_map[] = {
	{"*.ext4.caibx", "ext4-caibx"},
	{"*.vfat.caibx", "vfat-caibx"},
	{"*.ubifs.caibx", "ubifs-caibx"},
	{"*.img.caibx", "raw-caibx"},
	{"*.squashfs.caibx", "squashfs-caibx"},
	{"*.squashfs-*.caibx", "squashfs-caibx"},
	{"*.catar", "catar"},
	{"*.caidx", "caidx"},
	{"*.tar*", "tar"},
	{"*.tgz", "tar"},
	{"*.ext4", "ext4"},
	{"*.vfat", "vfat"},
	{"*.img", "raw"},
	{"*.squashfs-*", "squashfs"},
	{"*.squashfs", "squashfs"},
	{"*.ubifs", "ubifs"},
};

const gchar* derive_image_type_from_filename_pattern(const gchar *filename)
{
	g_return_val_if_fail(filename, NULL);

	for (unsigned long i = 0; i < G_N_ELEMENTS(ext_type_map); i++) {
		if (g_pattern_match_simple(ext_type_map[i].fileext, filename)) {
			return ext_type_map[i].type;
		}
	}

	return NULL;
}

static img_to_slot_handler get_handler_from_type(const gchar *image_type, const gchar *slot_type)
{
	g_return_val_if_fail(image_type, NULL);
	g_return_val_if_fail(slot_type, NULL);

	for (RaucImageTypeMap *map = image_type_map; map->type != NULL; map++) {
		if (g_strcmp0(map->type, image_type) == 0 &&
		    g_strcmp0(map->slottype, slot_type) == 0) {
			return map->handler;
		}
	}

	return NULL;
}

gboolean is_image_type_supported(const gchar *type)
{
	g_return_val_if_fail(type, FALSE);

	for (RaucImageTypeMap *map = image_type_map; map->type != NULL; map++) {
		if (g_strcmp0(map->type, type) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot *dest_slot, GError **error)
{
	const gchar *dest = dest_slot->type;
	img_to_slot_handler handler = NULL;

	/* If we have a custom install handler, use this instead of selecting an existing one */
	if (mfimage->hooks.install) {
		return hook_install_handler;
	}

	g_message("Checking image type for slot type: %s", dest);

	handler = get_handler_from_type(mfimage->type, dest);
	if (!handler) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_NO_HANDLER,
				"Unsupported image type '%s' for slot type '%s'", mfimage->type, dest);
		return NULL;
	}

	g_message("Found handler for image type '%s' and slot type '%s'", mfimage->type, dest);
	return handler;
}
