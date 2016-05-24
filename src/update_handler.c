#include "update_handler.h"
#include "mount.h"

#include <gio/gunixoutputstream.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <mtd/ubi-user.h>

#define R_UPDATE_ERROR r_update_error_quark()

static GQuark r_update_error_quark(void)
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
		g_set_error(error, R_UPDATE_ERROR, 0,
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
		g_set_error(error, R_UPDATE_ERROR, 0,
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
		g_set_error_literal(error, R_UPDATE_ERROR, 0,
				"image size and written size differ!");
		goto out;
	}

out:
	g_clear_object(&instream);
	g_clear_object(&srcimagefile);
	return TRUE;
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
	return res;
}

static gboolean ext4_format_slot(RaucSlot *dest_slot, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(4, g_free);

	g_ptr_array_add(args, g_strdup("mkfs.ext4"));
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
	return res;
}

static gboolean ubifs_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, GError **error)
{
	GOutputStream *outstream = NULL;
	GError *ierror = NULL;
	int out_fd;
	gboolean res = FALSE;

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

out:
	g_clear_object(&outstream);
	return res;
}

static gboolean tar_to_ubifs_handler(RaucImage *image, RaucSlot *dest_slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

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
		g_message("Mounting failed: %s", ierror->message);
		g_clear_error(&ierror);
		goto unmount_out;
	}

	/* extract tar into mounted ubi volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = untar_image(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

unmount_out:
	/* finally umount ubi volume */
	g_message("Unmounting ubifs slot %s", dest_slot->device);
	if (!r_umount_slot(dest_slot, &ierror)) {
		res = FALSE;
		g_warning("Unmounting failed: %s", ierror->message);
		g_clear_error(&ierror);
	}

out:
	return res;
}

static gboolean tar_to_ext4_handler(RaucImage *image, RaucSlot *dest_slot, GError **error) {
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* format ext4 volume */
	g_message("Formatting ext4 slot %s", dest_slot->device);
	res = ext4_format_slot(dest_slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* mount ubi volume */
	g_message("Mounting ext4 slot %s", dest_slot->device);
	res = r_mount_slot(dest_slot, &ierror);
	if (!res) {
		g_message("Mounting failed: %s", ierror->message);
		g_clear_error(&ierror);
		goto unmount_out;
	}

	/* extract tar into mounted ubi volume */
	g_message("Extracting %s to %s", image->filename, dest_slot->mount_point);
	res = untar_image(image, dest_slot->mount_point, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto unmount_out;
	}

unmount_out:
	/* finally umount ubi volume */
	g_message("Unmounting ext4 slot %s", dest_slot->device);
	if (!r_umount_slot(dest_slot, &ierror)) {
		res = FALSE;
		g_warning("Unmounting failed: %s", ierror->message);
		g_clear_error(&ierror);
	}

out:
	return res;
}

static gboolean img_to_nand_handler(RaucImage *image, RaucSlot *dest_slot, GError **error) {
	GError *ierror = NULL;
	gboolean res = FALSE;

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

out:
	return res;
}

static gboolean img_to_raw_handler(RaucImage *image, RaucSlot *dest_slot, GError **error) {
	GOutputStream *outstream = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* open */
	g_message("opening slot device %s", dest_slot->device);
	outstream = open_slot_device(dest_slot, NULL, &ierror);
	if (outstream == NULL) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	/* copy */
	res = copy_raw_image(image, outstream, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_clear_object(&outstream);
	return res;
}

typedef struct {
	const gchar *src;
	const gchar *dest;
	img_to_fs_handler handler;
} RaucUpdatePair;

RaucUpdatePair updatepairs[] = {
	{"*.ext4", "ext4", img_to_raw_handler},
	{"*.ext4", "raw", img_to_raw_handler},
	{"*.vfat", "raw", img_to_raw_handler},
	{"*.tar.*", "ext4", tar_to_ext4_handler},
	{"*.tar.*", "ubifs", tar_to_ubifs_handler},
	{"*.ubifs", "ubifs", ubifs_to_ubifs_handler},
	{"*.img", "nand", img_to_nand_handler},
	{"*.img", "*", img_to_raw_handler}, /* fallback */
	{0}
};

img_to_fs_handler get_update_handler(RaucImage *mfimage, RaucSlot *dest_slot, GError **error)
{
	const gchar *src = mfimage->filename;
	const gchar *dest = dest_slot->type;
	img_to_fs_handler handler = NULL;

	g_message("Checking image type for slot type: %s", dest);

	for (RaucUpdatePair *updatepair = updatepairs; updatepair->handler != NULL; updatepair++) {
		//g_message("Checking for pattern: %s", (gchar*)l->data);
		if (g_pattern_match_simple(updatepair->src, src) &&
		    g_pattern_match_simple(updatepair->dest, dest)) {
			g_message("Image detected as type: %s\n", updatepair->src);
			handler = updatepair->handler;
			break;
		}
	}

	if (handler == NULL)  {
		g_set_error(error, R_UPDATE_ERROR, 1, "Unsupported image %s for slot type %s",
			    mfimage->filename, dest);
		goto out;
	}

out:
	return handler;
}
