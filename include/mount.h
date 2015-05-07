#pragma once

#include <glib.h>

#include "config_file.h"

/**
 * Loopback mount a file.
 *
 * @param filename name of file to mount
 * @param mountpoint destination mount point
 * @param size Limit accessable size of file, If 0, entire file is used
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_loop(const gchar *filename, const gchar *mountpoint, gsize size);

/**
 * Mount a slot.
 *
 * @param slot Slot to mount
 * @param mountpoint destination mount point
 */
gboolean r_mount_slot(RaucSlot *slot, const gchar *mountpoint);

/**
 * Unmount a slot or a file.
 *
 * @param dirdev directory or device to unmount
 */
gboolean r_umount(const gchar *dirdev);
