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

#ifndef GLIB_VERSION_2_52
/**
 * g_uuid_string_random:
 *
 * Generates a random UUID (RFC 4122 version 4) as a string.
 *
 * Returns: (transfer full): A string that should be freed with g_free().
 */
static gchar *
g_uuid_string_random(void)
{
	int i;
	guint8 bytes[16];
	guint32 *ints;

	ints = (guint32 *) bytes;
	for (i = 0; i < 4; i++)
		ints[i] = g_random_int();

	/*
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the 4-bit version number from
	 * Section 4.1.3.
	 */
	bytes[6] &= 0x0f;
	bytes[6] |= 4 << 4;
	/*
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	bytes[8] &= 0x3f;
	bytes[8] |= 0x80;

	return g_strdup_printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
			"-%02x%02x%02x%02x%02x%02x",
			bytes[0], bytes[1], bytes[2], bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7],
			bytes[8], bytes[9], bytes[10], bytes[11],
			bytes[12], bytes[13], bytes[14], bytes[15]);
}
#endif

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

RaucDMVerity *new_dm_verity(void)
{
	RaucDMVerity *dm_verity = g_malloc0(sizeof(RaucDMVerity));

	dm_verity->uuid = g_uuid_string_random();

	return dm_verity;
}

void free_dm_verity(RaucDMVerity *dm_verity)
{
	g_return_if_fail(dm_verity);

	g_free(dm_verity->uuid);
	g_free(dm_verity->lower_dev);
	g_free(dm_verity->upper_dev);
	g_free(dm_verity->root_digest);
	g_free(dm_verity->salt);
	g_free(dm_verity);
}

gboolean setup_dm_verity(RaucDMVerity *dm_verity, GError **error)
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

	G_STATIC_ASSERT(sizeof(setup) == (sizeof(setup.header)+sizeof(setup.target_spec)+sizeof(setup.params)));

	g_return_val_if_fail(dm_verity != NULL, FALSE);
	g_return_val_if_fail(dm_verity->uuid != NULL, FALSE);
	g_return_val_if_fail(dm_verity->lower_dev != NULL, FALSE);
	g_return_val_if_fail(dm_verity->upper_dev == NULL, FALSE);
	g_return_val_if_fail(dm_verity->data_size > 0 && dm_verity->data_size % 4096 == 0, FALSE);
	g_return_val_if_fail(dm_verity->root_digest != NULL, FALSE);
	g_return_val_if_fail(dm_verity->salt != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	dmfd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
	if (dmfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to open /dev/mapper/control: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	/* create our dm-verity device */

	dm_set_header(&setup.header, sizeof(setup), DM_READONLY_FLAG, dm_verity->uuid);
	g_strlcpy(setup.header.name, "rauc-verity-bundle", sizeof(setup.header.name));

	if (ioctl(dmfd, DM_DEV_CREATE, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to create dm device: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	/* configure dm-verity */

	dm_set_header(&setup.header, sizeof(setup), DM_READONLY_FLAG, dm_verity->uuid);
	setup.header.target_count = 1;

	setup.target_spec.status = 0;
	setup.target_spec.sector_start = 0;
	setup.target_spec.length = dm_verity->data_size / 512;
	g_strlcpy(setup.target_spec.target_type, "verity", sizeof(setup.target_spec.target_type));

	if (g_snprintf(setup.params, sizeof(setup.params),
			"1 %s %s 4096 4096 %"G_GUINT64_FORMAT " %"G_GUINT64_FORMAT " sha256 %s %s", // version 1 with sha256 hashes
			dm_verity->lower_dev, dm_verity->lower_dev, // data and hash in the same device
			dm_verity->data_size / 4096,
			dm_verity->data_size / 4096, // hash offset is data size
			dm_verity->root_digest,
			dm_verity->salt) >= (gint)sizeof(setup.params)) {
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
				G_FILE_ERROR_FAILED,
				"Failed to load dm table: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	/* activate the configuration */

	dm_set_header(&setup.header, sizeof(setup), 0, dm_verity->uuid);

	if (ioctl(dmfd, DM_DEV_SUSPEND, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to resume dm device: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	dm_verity->upper_dev = g_strdup_printf("/dev/dm-%u", minor(setup.header.dev));

	/* quick check the at least the first block verifies ok */

	checkfd = g_open(dm_verity->upper_dev, O_RDONLY|O_CLOEXEC, 0);
	if (checkfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to open %s: %s", dm_verity->upper_dev, g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	if (read(checkfd, checkbuf, sizeof(checkbuf)) != sizeof(checkbuf)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Check read from dm-verity device failed: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}

	dm_set_header(&setup.header, sizeof(setup), 0, dm_verity->uuid);

	if (ioctl(dmfd, DM_TABLE_STATUS, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to query dm device status: %s", g_strerror(err));
		res = FALSE;
		goto out_remove_dm;
	}
	if (g_strcmp0(setup.params, "V") != 0) {
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Unexpected dm-verity status '%s' (instead of 'V')", setup.params);
		res = FALSE;
		goto out_remove_dm;
	}

	g_message("Configured dm-verity device '%s'", dm_verity->upper_dev);

	res = TRUE;
	goto out;

out_remove_dm:
	/* clean up after a failed setup */
	if (checkfd >= 0) {
		g_close(checkfd, NULL);
		checkfd = -1;
	}

	dm_set_header(&setup.header, sizeof(setup), 0, dm_verity->uuid);

	if (ioctl(dmfd, DM_DEV_REMOVE, &setup)) {
		int err = errno;
		g_message("Failed to remove bad dm-verity device on error: %s", g_strerror(err));
	}
out:
	if (checkfd >= 0)
		g_close(checkfd, NULL);
	if (dmfd >= 0)
		g_close(dmfd, NULL);

	return res;
}

gboolean remove_dm_verity(RaucDMVerity *dm_verity, gboolean deferred, GError **error)
{
	gboolean res = FALSE;
	int dmfd = -1;
	struct {
		struct dm_ioctl header;
	} setup = {0};

	g_return_val_if_fail(dm_verity != NULL, FALSE);
	g_return_val_if_fail(dm_verity->uuid != NULL, FALSE);
	g_return_val_if_fail(dm_verity->lower_dev != NULL, FALSE);
	g_return_val_if_fail(dm_verity->upper_dev != NULL, FALSE);
	g_return_val_if_fail(dm_verity->data_size > 0 && dm_verity->data_size % 4096 == 0, FALSE);
	g_return_val_if_fail(dm_verity->root_digest != NULL, FALSE);
	g_return_val_if_fail(dm_verity->salt != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	dmfd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
	if (dmfd < 0) {
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to open /dev/mapper/control");
		res = FALSE;
		goto out;
	}

	dm_set_header(&setup.header, sizeof(setup),
			deferred ? DM_DEFERRED_REMOVE : 0,
			dm_verity->uuid);

	if (ioctl(dmfd, DM_DEV_REMOVE, &setup)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				G_FILE_ERROR_FAILED,
				"Failed to remove dm device: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	g_clear_pointer(&dm_verity->upper_dev, g_free);

	res = TRUE;
out:
	if (dmfd >= 0)
		g_close(dmfd, NULL);

	return res;
}
