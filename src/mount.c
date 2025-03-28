#include <gio/gio.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "context.h"
#include "mount.h"
#include "utils.h"

#ifndef LOOP_SET_BLOCK_SIZE
#define LOOP_SET_BLOCK_SIZE 0x4C09
#endif

gboolean r_mount_bundle(const gchar *source, const gchar *mountpoint, GError **error)
{
	const unsigned long flags = MS_NODEV | MS_NOSUID | MS_RDONLY;

	g_return_val_if_fail(source != NULL, FALSE);
	g_return_val_if_fail(mountpoint != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (mount(source, mountpoint, "squashfs", flags, NULL)) {
		const gchar *errmsg;
		int err = errno;
		if (err == ENODEV) {
			errmsg = "squashfs support not enabled in kernel";
		} else {
			errmsg = g_strerror(err);
		}
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"%s", errmsg);
		return FALSE;
	}

	return TRUE;
}

gboolean r_umount_bundle(const gchar *mountpoint, GError **error)
{
	const int flags = UMOUNT_NOFOLLOW;

	g_return_val_if_fail(mountpoint != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (umount2(mountpoint, flags)) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to umount bundle: %s", g_strerror(err));
		return FALSE;
	}

	return TRUE;
}

gboolean r_mount_full(const gchar *source, const gchar *mountpoint, const gchar* type, const gchar* extra_options, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);

	g_return_val_if_fail(source != NULL, FALSE);
	g_return_val_if_fail(mountpoint != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(args, g_strdup("mount"));
	if (type != NULL) {
		g_ptr_array_add(args, g_strdup("-t"));
		g_ptr_array_add(args, g_strdup(type));
	}
	if (extra_options) {
		g_ptr_array_add(args, g_strdup("-o"));
		g_ptr_array_add(args, g_strdup(extra_options));
	}

	/*
	 * jffs2 mount must be called without /dev/ path. As we have already
	 * checked for the device name having a (/dev/-)path we can go with
	 * get_basename here.
	 */
	if ((type != NULL) && g_str_equal(type, "jffs2")) {
		g_ptr_array_add(args, g_path_get_basename(source));
	} else {
		g_ptr_array_add(args, g_strdup(source));
	}
	g_ptr_array_add(args, g_strdup(mountpoint));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run mount: ");
		return FALSE;
	}

	return TRUE;
}

gboolean r_setup_loop(gint fd, gint *loopfd_out, gchar **loopname_out, goffset size, GError **error)
{
	gboolean res = FALSE;
	gint controlfd = -1;
	g_autofree gchar *loopname = NULL;
	gint loopfd = -1, looprc;
	guint tries;
	struct loop_info64 loopinfo = {0};

	g_return_val_if_fail(fd >= 0, FALSE);
	g_return_val_if_fail(loopfd_out != NULL, FALSE);
	g_return_val_if_fail(loopname_out != NULL && *loopname_out == NULL, FALSE);
	g_return_val_if_fail(size > 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	controlfd = open("/dev/loop-control", O_RDWR|O_CLOEXEC);
	if (controlfd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open /dev/loop-control: %s", g_strerror(err));
		res = FALSE;
		goto out;
	}

	for (tries = 10; tries > 0; tries--) {
		gint loopidx;

		g_clear_pointer(&loopname, g_free);
		if (loopfd >= 0) {
			g_close(loopfd, NULL);
			loopfd = -1;
		}

		loopidx = ioctl(controlfd, LOOP_CTL_GET_FREE);
		if (loopidx < 0) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to get free loop device: %s", g_strerror(err));
			res = FALSE;
			goto out;
		}

		loopname = g_strdup_printf("/dev/loop%d", loopidx);

		loopfd = open(loopname, O_RDONLY|O_CLOEXEC);
		if (loopfd < 0) {
			int err = errno;
			/* is this loop dev gone already? */
			if ((err == ENOENT) || (err == ENXIO))
				continue; /* retry */
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to open %s: %s", loopname, g_strerror(err));
			res = FALSE;
			goto out;
		}

		looprc = ioctl(loopfd, LOOP_SET_FD, fd);
		if (looprc < 0) {
			int err = errno;
			/* is this loop dev is already in use by someone else? */
			if (err == EBUSY)
				continue; /* retry */
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to set loop device file descriptor: %s", g_strerror(err));
			res = FALSE;
			goto out;
		} else {
			break; /* claimed a loop dev */
		}
	}

	if (!tries) {
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(EBUSY),
				"Failed to find free loop device");
		res = FALSE;
		goto out;
	}

	loopinfo.lo_sizelimit = size;
	loopinfo.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;

	do {
		looprc = ioctl(loopfd, LOOP_SET_STATUS64, &loopinfo);
	} while (looprc && errno == EAGAIN);
	if (looprc < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to set loop device configuration: %s", g_strerror(err));
		ioctl(loopfd, LOOP_CLR_FD, 0);
		res = FALSE;
		goto out;
	}

	do {
		looprc = ioctl(loopfd, LOOP_SET_BLOCK_SIZE, 4096);
	} while (looprc < 0 && errno == EAGAIN);
	if (looprc < 0) {
		g_warning("Failed to set loop device block size to 4096: %s, continuing",
				g_strerror(errno));
	}

	g_message("Configured loop device '%s' for %" G_GOFFSET_FORMAT " bytes", loopname, size);

	*loopfd_out = loopfd;
	loopfd = -1;
	*loopname_out = g_steal_pointer(&loopname);
	res = TRUE;

out:
	if (loopfd >= 0)
		g_close(loopfd, NULL);
	if (controlfd >= 0)
		g_close(controlfd, NULL);
	return res;
}

gboolean r_umount(const gchar *filename, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(args, g_strdup("umount"));
	g_ptr_array_add(args, g_strdup(filename));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run umount: ");
		return FALSE;
	}

	return TRUE;
}

/* Creates a mount subdir in mount path prefix */
gchar* r_create_mount_point(const gchar *name, GError **error)
{
	gchar* prefix;
	gchar* mountpoint = NULL;

	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	prefix = r_context()->config->mount_prefix;
	mountpoint = g_build_filename(prefix, name, NULL);

	if (!g_file_test(mountpoint, G_FILE_TEST_IS_DIR)) {
		gint ret;
		ret = g_mkdir_with_parents(mountpoint, 0700);

		if (ret != 0) {
			int err = errno;
			g_set_error(
					error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed creating mount path '%s': %s",
					mountpoint,
					g_strerror(err));
			g_free(mountpoint);
			mountpoint = NULL;
			goto out;
		}
	}

out:
	return mountpoint;
}

gboolean r_mount_slot(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *mount_point = NULL;

	g_return_val_if_fail(slot != NULL, FALSE);
	g_return_val_if_fail(slot->mount_point == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_file_test(slot->device, G_FILE_TEST_EXISTS)) {
		g_set_error(
				error,
				G_FILE_ERROR,
				G_FILE_ERROR_NOENT,
				"Slot device '%s' not found",
				slot->device);
		goto out;
	}

	mount_point = r_create_mount_point(slot->name, &ierror);
	if (!mount_point) {
		res = FALSE;
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to create mount point: ");
		goto out;
	}

	res = r_mount_full(slot->device, mount_point, slot->type, slot->extra_mount_opts, &ierror);
	if (!res) {
		res = FALSE;
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to mount slot: ");
		g_rmdir(mount_point);
		g_free(mount_point);
		goto out;
	}

	slot->mount_point = mount_point;

out:
	return res;
}

gboolean r_umount_slot(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot != NULL, FALSE);
	g_return_val_if_fail(slot->mount_point != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!r_umount(slot->mount_point, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to unmount slot: ");
		return FALSE;
	}

	g_rmdir(slot->mount_point);
	g_clear_pointer(&slot->mount_point, g_free);

	return TRUE;
}

gboolean r_is_mount_point(const gchar *mountpoint)
{
	struct stat mnt, parent;
	g_autofree gchar *parentname = NULL;

	g_return_val_if_fail(mountpoint != NULL, FALSE);

	parentname = g_strdup_printf("%s/../", mountpoint);

	if (stat(mountpoint, &mnt) || stat(parentname, &parent)) {
		return FALSE;
	}

	/* When mnt is a mount point, it has a different device number than its parent directory.*/
	if (mnt.st_dev != parent.st_dev) {
		return TRUE;
	}

	return FALSE;
}