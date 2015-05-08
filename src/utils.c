#include <config.h>

#include <ftw.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include "utils.h"

GBytes *read_file(const gchar *filename) {
	gchar *contents;
	gsize length;

	if (!g_file_get_contents(filename, &contents, &length, NULL))
		return NULL;

	return g_bytes_new_take(contents, length);
}

gboolean write_file(const gchar *filename, GBytes *bytes) {
	const gchar *contents;
	gsize length;

	contents = g_bytes_get_data(bytes, &length);

	return g_file_set_contents(filename, contents, length, NULL);
}

static int rm_tree_cb(const char *fpath, const struct stat *sb,
		      int typeflag, struct FTW *ftwbuf) {
	switch(typeflag) {
		case FTW_F:
		case FTW_SL:
			return g_unlink(fpath);
		case FTW_DP:
			return g_rmdir(fpath);
		default:
			return -1;
	}
}

gboolean rm_tree(const gchar *path) {
	int flags = FTW_DEPTH | FTW_MOUNT | FTW_PHYS;

	g_assert_nonnull(path);
	g_assert_cmpuint(strlen(path), >, 1);
	g_assert(path[0] == '/');

	if (nftw(path, &rm_tree_cb, 20, flags)) {
		g_warning("failed to remote tree at %s", path);
		return FALSE;
	}

	return TRUE;
}


gchar *resolve_path(const gchar *basefile, gchar *path) {
	gchar *cwd = NULL, *dir = NULL, *res = NULL;

	if (path == NULL)
		return NULL;

	if (g_path_is_absolute(path))
		return path;

	dir = g_path_get_dirname(basefile);
	if (g_path_is_absolute(dir)) {
		res = g_build_filename(dir, path, NULL);
		goto out;
	}

	cwd = g_get_current_dir();
	res = g_build_filename(cwd, dir, path, NULL);

out:
	g_clear_pointer(&cwd, g_free);
	g_clear_pointer(&dir, g_free);
	g_clear_pointer(&path, g_free);
	return res;
}
