#pragma once

#include <glib.h>

#include <config_file.h>

typedef struct {
	gchar *update_compatible;
	gchar *update_version;

	gchar *keyring;

	gchar *handler_name;

	GList *images;
} RaucManifest;

gboolean load_manifest(const gchar *filename, RaucManifest **manifest);
gboolean save_manifest(const gchar *filename, RaucManifest *manifest);
void free_manifest(RaucManifest *manifest);

gboolean update_manifest(const gchar *dir, gboolean signature);
gboolean verify_manifest(const gchar *dir, gboolean signature);
