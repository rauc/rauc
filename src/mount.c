#include <unistd.h>

#include <gio/gio.h>

#include <config.h>
#include "mount.h"
#include "utils.h"
#include "context.h"

static gboolean mount_full(const gchar *source, const gchar *mountpoint, const gchar* type, gsize size) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);
	
	if (getuid() != 0) {
		g_ptr_array_add(args, g_strdup("sudo"));
		g_ptr_array_add(args, g_strdup("--non-interactive"));
	}
	g_ptr_array_add(args, g_strdup("mount"));
	if (type != NULL) {
		g_ptr_array_add(args, g_strdup("-t"));
		g_ptr_array_add(args, g_strdup(type));
	}
	if (size != 0) {
		g_ptr_array_add(args, g_strdup("-o"));
		g_ptr_array_add(args, g_strdup_printf("loop,sizelimit=%"G_GSIZE_FORMAT, size));
	}
	g_ptr_array_add(args, g_strdup(source));
	g_ptr_array_add(args, g_strdup(mountpoint));
	g_ptr_array_add(args, NULL);

	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
				  G_SUBPROCESS_FLAGS_NONE, &error);
	if (sproc == NULL) {
		g_warning("failed to start mount: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &error);
	if (!res) {
		g_warning("failed to run mount: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(args);
	return res;
}


gboolean r_mount_loop(const gchar *filename, const gchar *mountpoint, gsize size) {
	return mount_full(filename, mountpoint, "squashfs", size);
}

gboolean r_mount_slot(RaucSlot *slot, const gchar *mountpoint) {
	g_assert_nonnull(slot);

	if (!g_file_test(slot->device, G_FILE_TEST_EXISTS)) {
		g_warning("Destination device '%s' not found", slot->device);
		return FALSE;
	}

	return mount_full(slot->device, mountpoint, NULL, 0);
}

gboolean r_umount(const gchar *filename) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);
	
	if (getuid() != 0) {
		g_ptr_array_add(args, g_strdup("sudo"));
		g_ptr_array_add(args, g_strdup("--non-interactive"));
	}
	g_ptr_array_add(args, g_strdup("umount"));
	g_ptr_array_add(args, g_strdup(filename));
	g_ptr_array_add(args, NULL);

	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
				  G_SUBPROCESS_FLAGS_NONE, &error);
	if (sproc == NULL) {
		g_warning("failed to start umount: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &error);
	if (!res) {
		g_warning("failed to run umount: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(args);
	return res;
}
