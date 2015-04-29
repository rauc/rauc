#pragma once

#include <glib.h>

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir);
gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir);

