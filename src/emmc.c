#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <linux/major.h>
#include <linux/types.h> /* kernel < 3.4 forgot that in mmc/ioctl.h */
#include <linux/mmc/ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "emmc.h"
#include "update_handler.h"
#include "utils.h"

GQuark r_emmc_error_quark(void)
{
	return g_quark_from_static_string("r_emmc_error_quark");
}

static int r_emmc_read_extcsd(int fd, guint8 extcsd[512])
{
	struct mmc_ioc_cmd cmd = {};

	cmd.write_flag = 0;
	cmd.opcode = MMC_SEND_EXT_CSD;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	cmd.blksz = 512;
	cmd.blocks = 1;
	mmc_ioc_cmd_set_data(cmd, extcsd);

	return ioctl(fd, MMC_IOC_CMD, &cmd);
}

gboolean r_emmc_read_bootpart(const gchar *device, gint *bootpart_active, GError **error)
{
	guint8 extcsd[512];
	g_auto(filedesc) fd = -1;
	/* count from 1 */
	gint active_partition = -1;

	fd = g_open(device, O_RDONLY);
	if (fd == -1) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"opening eMMC device failed: %s", g_strerror(err));
		return FALSE;
	}

	if (r_emmc_read_extcsd(fd, extcsd)) {
		g_set_error(error, R_EMMC_ERROR, R_EMMC_ERROR_IOCTL,
				"Could not read from extcsd register %d in %s",
				EXT_CSD_PART_CONFIG, device);
		return FALSE;
	}

	/* retrieve active partition from BOOT_PART register */
	active_partition = (extcsd[EXT_CSD_PART_CONFIG] & 0x38) >> 3;

	switch (active_partition) {
		case 0x0: /* not boot enabled */
			*bootpart_active = -1;
			return TRUE;
		case 0x1: /* boot0 / boot 1 */
		/* fallthgrough */
		case 0x2:
			/* return the partitions counted from 0 */
			*bootpart_active = active_partition - 1;
			return TRUE;
		case 0x7: /* user data area */
			g_set_error(error,
					R_EMMC_ERROR,
					R_EMMC_ERROR_BOOTPART_UDA,
					"Active eMMC partition is UDA when boot0/boot1 was expected.");
			return FALSE;
		default:
			g_set_error(error,
					R_EMMC_ERROR,
					R_EMMC_ERROR_BOOTPART_INVALID,
					"Invalid (Reserved) eMMC boot part number.");
			return FALSE;
	}

	g_return_val_if_reached(FALSE);
}

static gint r_emmc_write_extcsd(int fd, guint8 index, guint8 value)
{
	struct mmc_ioc_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));

	cmd.write_flag = 1;
	cmd.opcode = MMC_SWITCH;
	cmd.arg = (MMC_SWITCH_MODE_WRITE_BYTE << 24) | (index << 16) |
	          (value << 8) | EXT_CSD_CMD_SET_NORMAL;
	cmd.flags = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;

	return ioctl(fd, MMC_IOC_CMD, &cmd);
}

gboolean r_emmc_write_bootpart(const gchar *device, gint bootpart_active, GError **error)
{
	g_auto(filedesc) fd = -1;
	guint8 extcsd[512];
	guint8 value = 0;

	g_return_val_if_fail(bootpart_active == 0 || bootpart_active == 1, FALSE);

	fd = g_open(device, O_RDWR | O_EXCL);
	if (fd == -1) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"opening eMMC device failed: %s", g_strerror(err));
		return FALSE;
	}

	if (r_emmc_read_extcsd(fd, extcsd)) {
		g_set_error(error, R_EMMC_ERROR, R_EMMC_ERROR_IOCTL,
				"Could not read from extcsd register %d in %s",
				EXT_CSD_PART_CONFIG, device);
		return FALSE;
	}

	/* Keep BOOT_ACK value as it is. Resetting this bit might prevent
	 * proper boot process on some platforms since in some SoCs, ROM boot
	 * loaders need this flag to be set.
	 * The PARTITION_ACCESS value is handled inside the kernel so we do not
	 * need to take care of it here. */
	value = extcsd[EXT_CSD_PART_CONFIG] & (1 << 6);

	/* write [5:3] : BOOT_PARTITION_ENABLE of PARTITION_CONFIG */
	if (bootpart_active == 0)
		value |= 0x08;
	else if (bootpart_active == 1)
		value |= 0x10;

	if (r_emmc_write_extcsd(fd, EXT_CSD_PART_CONFIG, value)) {
		g_set_error(error, R_EMMC_ERROR, R_EMMC_ERROR_IOCTL,
				"Could not write 0x%02x to extcsd register %d in %s",
				value, EXT_CSD_PART_CONFIG, device);
		return FALSE;
	}

	return TRUE;
}

static gboolean r_emmc_force_part_write(const gchar *device, gchar value, GError **error)
{
	gboolean ret = FALSE;
	g_autofree gchar *device_basename = g_path_get_basename(device);
	g_autofree gchar *sysfs_path = NULL;
	FILE *f = NULL;

	g_return_val_if_fail(value == '0' || value == '1', FALSE);

	sysfs_path = g_strdup_printf("/sys/block/%s/force_ro", device_basename);
	f = g_fopen(sysfs_path, "w");
	if (!f) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"Could not open device attribute %s: %s",
				sysfs_path, g_strerror(err));
		goto out;
	}

	if (fwrite(&value, 1, 1, f) != 1) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
				"Could not write to %s", sysfs_path);
		goto out;
	}

	ret = TRUE;

out:
	if (f)
		fclose(f);

	return ret;
}

gboolean r_emmc_force_part_ro(const gchar *device, GError **error)
{
	gboolean ret = FALSE;
	GError *ierror = NULL;

	ret = r_emmc_force_part_write(device, '1', &ierror);
	if (!ret)
		g_propagate_prefixed_error(error, ierror,
				"failed forcing ro: ");

	return ret;
}

gboolean r_emmc_force_part_rw(const gchar *device, GError **error)
{
	gboolean ret = FALSE;
	GError *ierror = NULL;

	ret = r_emmc_force_part_write(device, '0', &ierror);
	if (!ret)
		g_propagate_prefixed_error(error, ierror,
				"failed forcing rw: ");

	return ret;
}

gboolean r_emmc_extract_base_dev(const gchar *device_path, gchar **base_device, GError **error)
{
	g_return_val_if_fail(device_path != NULL, FALSE);
	g_return_val_if_fail(base_device != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Pattern to find valid MMC/eMMC base device */
	*base_device = r_regex_match_simple("(/dev/mmcblk[0-9]+)", device_path);

	if (*base_device == NULL) {
		g_set_error(error, R_EMMC_ERROR, R_EMMC_ERROR_FAILED,
				"Device path '%s' does not contain valid MMC device pattern", device_path);
		return FALSE;
	}

	return TRUE;
}
