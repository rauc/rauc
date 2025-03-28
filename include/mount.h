#pragma once

#include <glib.h>

#include "config_file.h"

/**
 * Wrapper for the mount() system call with a configuration intended for use
 * with bundles.
 *
 * Using the external 'mount' command is not needed in this case, as all options
 * are fixed.
 *
 * @param source source path for mount
 * @param mountpoint destination path for mount
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_bundle(const gchar *source, const gchar *mountpoint, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Wrapper for the umount() system call with a configuration intended for use
 * with bundles.
 *
 * Using the external 'umount' command is not needed in this case, as all
 * options are fixed.
 *
 * @param mountpoint destination path for mount
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_umount_bundle(const gchar *mountpoint, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Wrapper for calling systems 'mount' command.
 *
 * @param source source path for mount
 * @param mountpoint destination path for mount
 * @param type type of image to mount (results in -t option)
 * @param extra_options additional mount options that will be passed to mount
 *        via `-o` argument
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_full(const gchar *source, const gchar *mountpoint, const gchar* type, const gchar *extra_options, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Setup a loopback device for a file.
 *
 * The size must be > 0, as we always know the exact size of the payload.
 *
 * @param fd file descriptor of file to mount
 * @param loopfd_out file descriptor of the open loop device
 * @param loopname_out device name of loop device
 * @param size limit accessible size of file
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_setup_loop(gint fd, gint *loopfd_out, gchar **loopname_out, goffset size, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Unmount a slot or a file.
 *
 * @param dirdev directory or device to unmount
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_umount(const gchar *dirdev, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Create a mount directory.
 *
 * The directory will be created relative to the configured mount prefix path.
 *
 * @param name mount directory name to create
 * @param error return location for a GError, or NULL
 *
 * @return A newly allocated string containing the created mount path
 */
gchar* r_create_mount_point(const gchar *name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mount a slot.
 *
 * The mountpoint will be available as slot->mount_point.
 *
 * @param slot slot to mount
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_mount_slot(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Unmount a slot.
 *
 * This only works for slots that were mounted by rauc.
 *
 * @param slot slot to unmount
 * @param error return location for a GError, or NULL
 *
 * @return True if succeeded, False if failed
 */
gboolean r_umount_slot(RaucSlot *slot, GError **error);

/**
 * Check if a path is mount point.
 *
 * @param mountpoint path for mount check
 *
 * @return True if path is a mount point, False if not
 */
gboolean r_is_mount_point(const gchar *mountpoint);
