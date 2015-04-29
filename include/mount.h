#pragma once

#include <glib.h>

gboolean mount_loop(const gchar *filename, const gchar *mountpoint, gsize size);
gboolean umount_loop(const gchar *filename);
