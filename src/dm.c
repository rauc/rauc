#include <gio/gio.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "dm.h"

static void dm_set_header(struct dm_ioctl *header, size_t size, guint32 flags, const gchar *uuid)
{
	memset(header, 0, sizeof(*header));
	header->version[0] = DM_VERSION_MAJOR;
	header->version[1] = 0; // DM_VERSION_MINOR
	header->version[2] = 0; // DM_VERSION_PATCHLEVEL
	header->data_size = size;
	header->data_start = sizeof(*header);
	header->flags = flags;
	g_strlcpy(header->uuid, uuid, sizeof(header->uuid));
}

RaucDM *r_dm_new_verity(void)
{
	RaucDM *dm_verity = g_malloc0(sizeof(RaucDM));

	dm_verity->type = RAUC_DM_VERITY;
	dm_verity->uuid = g_uuid_string_random();

	return dm_verity;
}

RaucDM *r_dm_new_crypt(void)
{
	RaucDM *dm_crypt = g_malloc0(sizeof(RaucDM));

	dm_crypt->type = RAUC_DM_CRYPT;
	dm_crypt->uuid = g_uuid_string_random();

	return dm_crypt;
}

void r_dm_free(RaucDM *dm)
{
	if (!dm)
		return;

	g_free(dm->uuid);
	g_free(dm->lower_dev);
	g_free(dm->upper_dev);
	g_free(dm->root_digest);
	g_free(dm->salt);
	g_free(dm->key);
	g_free(dm);
}

static const gchar* dmtype_to_str(RaucDMType dmtype)
{
	switch (dmtype) {
		case RAUC_DM_VERITY:
			return "verity";
		case RAUC_DM_CRYPT:
			return "crypt";
		default:
			return "unknown";
	}
}

static const gchar* dmstatus_by_dmtype(RaucDMType dmtype)
{
	switch (dmtype) {
		case RAUC_DM_VERITY:
			return "V";
		case RAUC_DM_CRYPT:
			return "\0";
		default:
			return "unknown";
	}
}

gboolean r_dm_setup(RaucDM *dm, GError **error)
{
	gboolean res = FALSE;
	int dmfd = -1;
	int checkfd = -1;
	char checkbuf[1];
	struct {
		struct dm_ioctl header;
		struct dm_target_spec target_spec;
		char params[1024];
	} setup = {0};
	gint ret;

	G_STATIC_ASSERT(sizeof(setup) == (sizeof(setup.header)+sizeof(setup.target_spec)+sizeof(setup.params)));

	g_return_val_if_fail(dm != NULL, FALSE);
	g_return_val_if_fail(dm->uuid != NULL, FALSE);
	g_return_val_if_fail(dm->lower_dev != NULL, FALSE);
	g_return_val_if_fail(dm->upper_dev == NULL, FALSE);
	g_return_val_if_fail(dm->data_size > 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (dm->data_size % 4096 != 0) {
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Payload size (%"G_GUINT64_FORMAT ") is not a multiple of 4KiB. "
				"See https://rauc.readthedocs.io/en/latest/faq.html#what-causes-a-payload-size-that-is-not-a-multiple-of-4kib",
				dm->data_size);
		res = FALSE;
		goto out;
	}

	dmfd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
	if (dmfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open /dev/mapper/control: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	/* create our dm device */

	dm_set_header(&setup.header, sizeof(setup), DM_READONLY_FLAG, dm->uuid);
	if (dm->type == RAUC_DM_VERITY)
		g_strlcpy(setup.header.name, "rauc-verity-bundle", sizeof(setup.header.name));
	else if (dm->type == RAUC_DM_CRYPT)
		g_strlcpy(setup.header.name, "rauc-crypt-bundle", sizeof(setup.header.name));
	else
		g_error("unknown dm type");

	if (ioctl(dmfd, DM_DEV_CREATE, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to create dm device: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	/* configure dm */

	dm_set_header(&setup.header, sizeof(setup), DM_READONLY_FLAG, dm->uuid);
	setup.header.target_count = 1;

	setup.target_spec.status = 0;
	setup.target_spec.sector_start = 0;
	setup.target_spec.length = dm->data_size / 512;
	g_strlcpy(setup.target_spec.target_type, dmtype_to_str(dm->type), sizeof(setup.target_spec.target_type));

	switch (dm->type) {
		case RAUC_DM_VERITY: {
			ret = g_snprintf(setup.params, sizeof(setup.params),
					"1 %s %s 4096 4096 %"G_GUINT64_FORMAT " %"G_GUINT64_FORMAT " sha256 %s %s", // version 1 with sha256 hashes
					dm->lower_dev, dm->lower_dev, // data and hash in the same device
					dm->data_size / 4096,
					dm->data_size / 4096, // hash offset is data size
					dm->root_digest,
					dm->salt) >= (gint)sizeof(setup.params);
			break;
		};
		case RAUC_DM_CRYPT:
			/* <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset> <dev_path> <start> */
			ret = g_snprintf(setup.params, sizeof(setup.params),
					"aes-cbc-plain64 %s 0 %s 0 1 sector_size:4096",
					dm->key,
					dm->lower_dev) >= (gint)sizeof(setup.params);
			break;
		default:
			g_error("unknown dm type");
			break;
	}
	if (ret) {
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to generate dm parameter string");
		res = FALSE;
		goto out_remove_dm;
	}

	if (ioctl(dmfd, DM_TABLE_LOAD, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to load dm table: %s, "
				"check DM_VERITY, DM_CRYPT or CRYPTO_AES kernel options.", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	/* activate the configuration */

	dm_set_header(&setup.header, sizeof(setup), 0, dm->uuid);

	if (ioctl(dmfd, DM_DEV_SUSPEND, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to resume dm device: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	dm->upper_dev = g_strdup_printf("/dev/dm-%u", minor(setup.header.dev));

	/* quick check the at least the first block verifies ok */

	checkfd = g_open(dm->upper_dev, O_RDONLY|O_CLOEXEC, 0);
	if (checkfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open %s: %s", dm->upper_dev, g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	if (read(checkfd, checkbuf, sizeof(checkbuf)) != sizeof(checkbuf)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Check read from dm-%s device failed: %s", dmtype_to_str(dm->type), g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	dm_set_header(&setup.header, sizeof(setup), 0, dm->uuid);

	if (ioctl(dmfd, DM_TABLE_STATUS, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to query dm device status: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}
	if (g_strcmp0(setup.params, dmstatus_by_dmtype(dm->type)) != 0) {
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Unexpected dm-%s status '%s' (instead of '\\0')", dmtype_to_str(dm->type), setup.params);
		res = FALSE;
		goto out_remove_dm;
	}

	g_message("Configured dm-%s device '%s'", dmtype_to_str(dm->type), dm->upper_dev);

	res = TRUE;
	goto out;

out_remove_dm:
	/* clean up after a failed setup */
	if (checkfd >= 0) {
		g_close(checkfd, NULL);
		checkfd = -1;
	}

	dm_set_header(&setup.header, sizeof(setup), 0, dm->uuid);

	if (ioctl(dmfd, DM_DEV_REMOVE, &setup)) {
		int err = errno;
		g_message("Failed to remove bad dm-%s device on error: %s", dmtype_to_str(dm->type), g_strerror(err));
	}
out:
	if (checkfd >= 0)
		g_close(checkfd, NULL);
	if (dmfd >= 0)
		g_close(dmfd, NULL);

	return res;
}

gboolean r_dm_remove(RaucDM *dm, gboolean deferred, GError **error)
{
	gboolean res = FALSE;
	int dmfd = -1;
	struct {
		struct dm_ioctl header;
	} setup = {0};

	g_return_val_if_fail(dm != NULL, FALSE);
	g_return_val_if_fail(dm->uuid != NULL, FALSE);
	g_return_val_if_fail(dm->lower_dev != NULL, FALSE);
	g_return_val_if_fail(dm->upper_dev != NULL, FALSE);
	g_return_val_if_fail(dm->data_size > 0 && dm->data_size % 4096 == 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	if (dm->type == RAUC_DM_VERITY) {
		g_return_val_if_fail(dm->root_digest != NULL, FALSE);
		g_return_val_if_fail(dm->salt != NULL, FALSE);
	} else if (dm->type == RAUC_DM_CRYPT) {
		g_return_val_if_fail(dm->key != NULL, FALSE);
	}

	dmfd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
	if (dmfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open /dev/mapper/control: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	dm_set_header(&setup.header, sizeof(setup),
			deferred ? DM_DEFERRED_REMOVE : 0,
			dm->uuid);

	if (ioctl(dmfd, DM_DEV_REMOVE, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to remove dm device: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	g_clear_pointer(&dm->upper_dev, g_free);

	res = TRUE;
out:
	if (dmfd >= 0)
		g_close(dmfd, NULL);

	return res;
}
