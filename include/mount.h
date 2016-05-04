#pragma once

#include <glib.h>

#include "config_file.h"

gboolean r_mount_full(const gchar *source, const gchar *mountpoint, const gchar* type, gsize size, GError **error);

/**
 * Loopback mount a file.
 *
 * @param filename name of file to mount
 * @param mountpoint destination mount point
 * @param size Limit accessable size of file, If 0, entire file is used
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_loop(const gchar *filename, const gchar *mountpoint, gsize size, GError **error);

/**
 * Unmount a slot or a file.
 *
 * @param dirdev directory or device to unmount
 */
gboolean r_umount(const gchar *dirdev, GError **error);

/**
 * Create a mount dir under mount prefix path.
 *
 * @param name
 * @param error
 */
gchar* r_create_mount_point(const gchar *name, GError **error);

/**
 * Mount a slot.
 *
 * The mountpoint will be available as slot->mount_point.
 *
 * @param slot Slot to mount
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_slot(RaucSlot *slot, GError **error);

/**
 * Unmount a slot.
 *
 * This only works for Slots that were mounted by rauc.
 *
 * @param slot Slot to unmount
 *
 * @return True if succeeded, False if failed
 */
gboolean r_umount_slot(RaucSlot *slot, GError **error);
