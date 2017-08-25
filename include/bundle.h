#pragma once

#include <glib.h>

#define R_BUNDLE_ERROR r_bundle_error_quark ()
GQuark r_bundle_error_quark(void);

typedef enum {
	R_BUNDLE_ERROR_SIGNATURE,
	R_BUNDLE_ERROR_KEYRING
} RBundleError;

/**
 * Create a bundle.
 *
 * @param bundlemane filename of the bundle to create
 * @param contentdir directory containing this bundle content
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error);

/**
 * Check a bundle.
 *
 * This will verify and check the bundle content.
 *
 * @param bundlemane filename of the bundle to check
 * @param size Return location for the bundle size
 * @param verify If set to true the bundle signature will also be verified, if
 *               set to FALSE this step will be skipped
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean check_bundle(const gchar *bundlename, gsize *size, gboolean verify, GError **error);

/**
 * Resign a bundle.
 *
 * This will create a copy of a bundle with a new signature but unmodified
 * content.
 *
 * @param inpath filename of the bundle to resign
 * @param outpath filename of the resigned output bundle
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean resign_bundle(const gchar *inpath, const gchar *outpath, GError **error);

/**
 * Extract a bundle.
 *
 * This will extract the entire bundle content into a given directory.
 *
 * @param bundlemane filename of the bundle to extract
 * @param outputdir directory to instract content into
 * @param verify If set to true the bundle signature will also be verified, if
 *               set to FALSE this step will be skipped
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean extract_bundle(const gchar *bundlename, const gchar *outputdir, gboolean verify, GError **error);

/**
 * Extract a single file form a bundle.
 *
 * This will extract a single file into a given directory.
 *
 * @param bundlemane filename of the bundle to extract
 * @param outputdir directory to instract the file into
 * @param file filename of file to extract from bundle
 * @param verify If set to true the bundle signature will also be verified, if
 *               set to FALSE this step will be skipped
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean extract_file_from_bundle(const gchar *bundlename, const gchar *outputdir, const gchar *file, gboolean verify, GError **error);

/**
 * Mount a bundle.
 *
 * @param bundlemane filename of the bundle to mount
 * @param mountpoint path to the desired mount point
 * @param verify If set to true the bundle signature will also be verified, if
 *               set to FALSE this step will be skipped
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean mount_bundle(const gchar *bundlename, const gchar *mountpoint, gboolean verify, GError **error);

/**
 * Unmount a bundle.
 *
 * @param bundlemane filename of the bundle to unmount
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean umount_bundle(const gchar *bundlename, GError **error);
