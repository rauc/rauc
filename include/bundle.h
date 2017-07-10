#pragma once

#include <glib.h>

#define R_BUNDLE_ERROR r_bundle_error_quark ()
GQuark r_bundle_error_quark(void);

typedef enum {
	R_BUNDLE_ERROR_SIGNATURE,
	R_BUNDLE_ERROR_KEYRING
} RBundleError;

gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error);
gboolean check_bundle(const gchar *bundlename, gsize *size, gboolean verify, GError **error);
gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir, gboolean verify, GError **error);
gboolean extract_file_from_bundle(const gchar *bundlename, const gchar *outputdir, const gchar *file, gboolean verify, GError **error);

gboolean mount_bundle(const gchar *bundlename, const gchar *mountpoint, gboolean verify, GError **error);
gboolean umount_bundle(const gchar *bundlename, GError **error);
