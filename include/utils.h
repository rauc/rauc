#pragma once

#include <glib.h>

GBytes *read_file(const gchar *filename, GError **error);
gboolean write_file(const gchar *filename, GBytes *bytes, GError **error);

gboolean rm_tree(const gchar *path, GError **error);

gchar *resolve_path(const gchar *basefile, gchar *path);
