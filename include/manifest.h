#pragma once

#include <glib.h>

#include <config_file.h>

gboolean update_manifest(const gchar *dir, gboolean signature);
gboolean verify_manifest(const gchar *dir, gboolean signature);
