#pragma once

#include <glib.h>

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error);
gboolean check_bundle(const gchar *bundlename, gsize *size, GError **error);
gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir, GError **error);

gboolean mount_bundle(const gchar *bundlename, const gchar *mountpoint, GError **error);
gboolean umount_bundle(const gchar *bundlename, GError **error);
