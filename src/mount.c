#include <unistd.h>

#include <gio/gio.h>

#include <config.h>
#include "mount.h"

gboolean mount_loop(const gchar *filename, const gchar *mountpoint, gsize size) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);
	
	if (getuid() != 0) {
		g_ptr_array_add(args, g_strdup("sudo"));
		g_ptr_array_add(args, g_strdup("--non-interactive"));
	}
	g_ptr_array_add(args, g_strdup("mount"));
	g_ptr_array_add(args, g_strdup("-t"));
	g_ptr_array_add(args, g_strdup("squashfs"));
	g_ptr_array_add(args, g_strdup("-o"));
	g_ptr_array_add(args, g_strdup_printf("loop,sizelimit=%"G_GSIZE_FORMAT, size));
	g_ptr_array_add(args, g_strdup(filename));
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

gboolean umount_loop(const gchar *filename) {
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
