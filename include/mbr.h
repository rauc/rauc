#pragma once

#include <glib.h>

struct mbr_switch_partition {
	guint64 start;          /* address in bytes */
	guint64 size;           /* size in bytes */
};

/**
 * Get the address and size of the inactive boot partition
 * if a partition exists in the defined region.
 *
 * @param device dev path (/dev/mmcblkX)
 * @param partition will contain the inactive boot partition (start & size)
 * @param region_start start address of the region, where bootpartitions are
 * are inside
 * @param region_size size of the region, where bootpartitions are are inside
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mbr_switch_get_inactive_partition(const gchar *device,
		struct mbr_switch_partition *partition,
		guint64 region_start, guint64 region_size,
		GError **error);

/**
 * Clear the the memory area defined in dest_partition.
 *
 * @param device dev path (/dev/mmcblkX)
 * @param dest_partition partition to be cleared (start & size) *
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mbr_switch_clear_partition(const gchar *device,
		const struct mbr_switch_partition *dest_partition,
		GError **error);

/**
 * Set the boot partition in master boot record to point to the
 * partion at address and size in partition.
 *
 * @param device dev path (/dev/mmcblkX)
 * @param partition updated boot partition (start & size)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mbr_switch_set_boot_partition(const gchar *device,
		const struct mbr_switch_partition *partition,
		GError **error);
