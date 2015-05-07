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


gchar* get_parent_dir(const gchar* path) {
	GFile *file;
	GFile *parent;
	gchar *base_path;

	file = g_file_new_for_path(path);
	if (!file)
		return NULL;
	parent = g_file_get_parent(file);
	if (!parent)
		return NULL;
	base_path = g_file_get_path(parent);
	if (!base_path)
		return NULL;

	g_object_unref(file);
	g_object_unref(parent);

	return base_path;
}
