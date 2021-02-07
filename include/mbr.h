#pragma once

#include <glib.h>

#include "update_handler.h"

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
		struct boot_switch_partition *partition,
		guint64 region_start, guint64 region_size,
		GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Set the boot partition in master boot record to point to the
 * partition at address and size in partition.
 *
 * @param device dev path (/dev/mmcblkX)
 * @param partition updated boot partition (start & size)
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mbr_switch_set_boot_partition(const gchar *device,
		const struct boot_switch_partition *partition,
		GError **error)
G_GNUC_WARN_UNUSED_RESULT;
