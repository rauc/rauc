#pragma once

#include <glib.h>

GBytes *read_file(const gchar *filename);
gboolean write_file(const gchar *filename, GBytes *bytes);
