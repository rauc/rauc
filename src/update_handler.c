#include <config.h>

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


#define R_SLOT_HOOK_PRE_INSTALL "slot-pre-install"
#define R_SLOT_HOOK_POST_INSTALL "slot-post-install"
#define R_SLOT_HOOK_INSTALL "slot-install"

GQuark r_update_error_quark(void)
{
	return g_quark_from_static_string("r_update_error_quark");
}

/* the fd will only live as long as the returned output stream */
static GOutputStream* open_slot_device(RaucSlot *slot, int *fd, GError **error)
{
	GOutputStream *outstream = NULL;
	GFile *destslotfile = NULL;
	GError *ierror = NULL;
	int fd_out;

	destslotfile = g_file_new_for_path(slot->device);

	fd_out = open(g_file_get_path(destslotfile), O_WRONLY);

	if (fd_out == -1) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"opening output device failed: %s", strerror(errno));
		goto out;
	}

	outstream = g_unix_output_stream_new(fd_out, TRUE);
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

static gboolean copy_raw_image(RaucImage *image, GOutputStream *outstream, GError **error)
{
	GError *ierror = NULL;
	gssize size;
	GFile *srcimagefile = g_file_new_for_path(image->filename);
	gboolean res = FALSE;

	GInputStream *instream = (GInputStream*)g_file_read(srcimagefile, NULL, &ierror);
	if (instream == NULL) {
		g_propagate_prefixed_error(error, ierror,
				"failed to open file for reading: ");
		goto out;
	}

	size = g_output_stream_splice(outstream, instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
			NULL,
			&ierror);
	if (size == -1) {
		g_propagate_prefixed_error(error, ierror,
				"failed splicing data: ");
		goto out;
	} else if (size != (gssize)image->checksum.size) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"written size (%"G_GSIZE_FORMAT") != image size (%"G_GSIZE_FORMAT")", size, (gssize)image->checksum.size);
		goto out;
	}

	res = TRUE;

out:
	g_clear_object(&instream);
	g_clear_object(&srcimagefile);
	return res;
}

static gboolean casync_extract(RaucImage *image, gchar *dest, const gchar *seed, const gchar *store, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static RaucSlot *get_active_slot_class_member(gchar *slotclass) {
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
	gchar *seed = NULL;
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

	store = r_context()->install_info->mounted_bundle->storepath;
	g_debug("Using store path: '%s'", store);

extract:
	/* Call casync to extract */
	res = casync_extract(image, dest, seed, store, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* Cleanup seed */
	if (seed_mounted) {
		r_umount_slot(seedslot, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Failed unmounting seed slot: ");
			goto out;
		}
	}

	res = TRUE;
out:
	return res;
}

static gboolean copy_raw_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error) {
	GOutputStream *outstream = NULL;
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
	g_clear_object(&outstream);
	return res;
}

static gboolean write_image_to_dev(RaucImage *image, RaucSlot *slot, GError **error) {
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
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(3, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ubifs"));
	g_ptr_array_add(args, g_strdup("-y"));
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean ext4_format_slot(RaucSlot *dest_slot, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ext4"));
	g_ptr_array_add(args, g_strdup("-F"));
	if (strlen(dest_slot->name) <= 16) {
		g_ptr_array_add(args, g_strdup("-L"));
		g_ptr_array_add(args, g_strdup(dest_slot->name));
	}
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean vfat_format_slot(RaucSlot *dest_slot, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.vfat"));
	if (strlen(dest_slot->name) <= 16) {
		g_ptr_array_add(args, g_strdup("-n"));
		g_ptr_array_add(args, g_strdup(dest_slot->name));
	}
	g_ptr_array_add(args, g_strdup(dest_slot->device));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean nand_format_slot(const gchar *device, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("flash_erase"));
	g_ptr_array_add(args, g_strdup("--quiet"));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, g_strdup("0"));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean nand_write_slot(const gchar *image, const gchar *device, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("nandwrite"));
	g_ptr_array_add(args, g_strdup("--pad"));
	g_ptr_array_add(args, g_strdup("--quiet"));
	g_ptr_array_add(args, g_strdup(device));
	g_ptr_array_add(args, g_strdup(image));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean untar_image(RaucImage *image, gchar *dest, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("xf"));
	g_ptr_array_add(args, g_strdup(image->filename));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(dest));
	g_ptr_array_add(args, NULL);

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
	g_ptr_array_unref(args);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean unpack_archive(RaucImage *image, gchar *dest, GError **error)
{
	if (g_str_has_suffix(image->filename, ".caidx" ))
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
static gboolean run_slot_hook(const gchar *hook_name, const gchar *hook_cmd, RaucImage *image, RaucSlot *slot, GError **error) {
	GSubprocessLauncher *launcher = NULL;
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_assert_nonnull(slot);
	g_assert_nonnull(slot->name);
	g_assert_nonnull(slot->sclass);

	g_message("Running slot hook %s for %s", hook_cmd, slot->name);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_NAME", slot->name, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SLOT_CLASS", slot->sclass, TRUE);
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
	g_clear_pointer(&launcher, g_object_unref);
	g_clear_pointer(&sproc, g_object_unref);
	return res;
}

static gboolean mount_and_run_slot_hook(const gchar *hook_name, const gchar *hook_cmd, RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

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
		if (error) {
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
	GOutputStream *outstream = NULL;
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
	g_clear_object(&outstream);
	return res;
}

static gboolean img_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
{
	GOutputStream *outstream = NULL;
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
	g_clear_object(&outstream);
	return res;
}

static gboolean archive_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
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
		if (error) {
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

static gboolean archive_to_ext4_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error) {
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
		if (error) {
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
		if (error) {
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

static gboolean img_to_nand_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error) {
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

static gboolean img_to_fs_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error) {
	GOutputStream *outstream = NULL;
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

	/* run slot post install hook if enabled */
	if (hook_name && image->hooks.post_install)  {
		res = mount_and_run_slot_hook(hook_name, R_SLOT_HOOK_POST_INSTALL, dest_slot, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
	}

out:
	g_clear_object(&outstream);
	return res;
}

static gboolean img_to_raw_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error) {
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

static gboolean hook_install_handler(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error) {
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
	{"*.tar*", "ext4", archive_to_ext4_handler},
	{"*.tar*", "ubifs", archive_to_ubifs_handler},
	{"*.tar*", "vfat", archive_to_vfat_handler},
	{"*.ubifs", "ubivol", img_to_ubivol_handler},
	{"*.ubifs", "ubifs", img_to_ubifs_handler},
	{"*.img", "nand", img_to_nand_handler},
	{"*.img", "ubivol", img_to_ubivol_handler},
	{"*.squashfs", "ubivol", img_to_ubivol_handler},
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
