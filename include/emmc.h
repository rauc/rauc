#pragma once

#include <glib.h>
#include <linux/types.h>

#define EMMC_BOOT_PARTITIONS			2
#define INACTIVE_BOOT_PARTITION(part_active)	((part_active + 1) % EMMC_BOOT_PARTITIONS)

#define EXT_CSD_PART_CONFIG			179
#define EXT_CSD_CMD_SET_NORMAL			(1 << 0)
#define EXT_CSD_BOOT_CFG_ACC			(0x07)

/* From kernel linux/mmc/mmc.h */
#define MMC_SWITCH				6               /* ac	[31:0] See below	R1b */
#define MMC_SEND_EXT_CSD			8               /* adtc				R1  */
#define MMC_SWITCH_MODE_WRITE_BYTE		0x03            /* Set target to value */

/* From kernel linux/mmc/core.h */
#define MMC_RSP_PRESENT				(1 << 0)
#define MMC_RSP_CRC				(1 << 2)        /* expect valid crc */
#define MMC_RSP_BUSY				(1 << 3)        /* card may send busy */
#define MMC_RSP_OPCODE				(1 << 4)        /* response contains opcode */

#define MMC_CMD_AC				(0 << 5)
#define MMC_CMD_ADTC				(1 << 5)

#define MMC_RSP_SPI_S1				(1 << 7)        /* one status byte */
#define MMC_RSP_SPI_BUSY			(1 << 10)       /* card may send busy */

#define MMC_RSP_SPI_R1				(MMC_RSP_SPI_S1)
#define MMC_RSP_SPI_R1B				(MMC_RSP_SPI_S1|MMC_RSP_SPI_BUSY)

#define MMC_RSP_R1				(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1B				(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE|MMC_RSP_BUSY)


/**
 * Reads the active eMMC boot partition index of given eMMC device into the
 * given variable.
 *
 * @param device eMMC /dev path (/dev/mmcblkX)
 * @param bootpart_active will contain the active boot partition
 * (0 for mmcblkXboot0, 1 for mmcblkXboot1, 6 for mmcblkX user partition and
 * -1 for no active boot partition)
 * for user partition)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_emmc_read_bootpart(const gchar *device, gint *bootpart_active, GError **error);

/**
 * Set the given boot partition (by index) active.
 *
 * @param device eMMC /dev path (/dev/mmcblkX)
 * @param bootpart_active boot partition to set active (0 or 1)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_emmc_write_bootpart(const gchar *device, gint bootpart_active, GError **error);

/**
 * Set eMMC boot partition to read-only.
 *
 * @param device eMMC boot partition /dev path (/dev/mmcblkXbootY)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_emmc_force_part_ro(const gchar *device, GError **error);

/**
 * Set eMMC boot partition to read-write.
 *
 * @param device eMMC boot partition /dev path (/dev/mmcblkXbootY)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_emmc_force_part_rw(const gchar *device, GError **error);
