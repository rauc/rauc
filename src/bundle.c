#include <gio/gio.h>

#include <config.h>
#include "bundle.h"

static gboolean mksquashfs(const gchar *bundlename, const gchar *contentdir) {
	GSubprocess *sproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;

	sproc = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE,
				 &error, CMD_MKSQUASHFS,
				 contentdir,
				 bundlename,
				 "-all-root",
				 NULL);
	if (sproc == NULL) {
		g_warning("failed to start mksquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &error);
	if (!res) {
		g_warning("failed to run mksquashfs: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir) {
	gboolean res = FALSE;

	res = mksquashfs(bundlename, contentdir);
	if (!res)
		goto out;

	res = TRUE;
out:
	return res;
}
