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
	{"*.ubifs", "ubifs", ubifs_to_ubifs_handler},
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
