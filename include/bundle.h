#pragma once

#include <openssl/cms.h>
#include <glib.h>

#define R_BUNDLE_ERROR r_bundle_error_quark()
GQuark r_bundle_error_quark(void);

typedef enum {
	R_BUNDLE_ERROR_SIGNATURE,
	R_BUNDLE_ERROR_KEYRING,
	R_BUNDLE_ERROR_IDENTIFIER
} RBundleError;

typedef struct {
	gchar *path;
	gchar *origpath;
	gchar *storepath;
	gsize size;
	GBytes *sigdata;
	gchar *mount_point;
	STACK_OF(X509) *verified_chain;
} RaucBundle;

/**
 * Create a bundle.
 *
 * @param bundlename filename of the bundle to create
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
 * @param bundlename filename of the bundle to check
 * @param bundle return location for a RaucBundle struct.
 *               This will contain all bundle information obtained by
 *               check_bundle
 * @param verify If set to true the bundle signature will also be verified, if
 *               set to FALSE this step will be skipped
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean check_bundle(const gchar *bundlename, RaucBundle **bundle, gboolean verify, GError **error);

/**
 * Resign a bundle.
 *
 * This will create a copy of a bundle with a new signature but unmodified
 * content.
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outpath filename of the resigned output bundle
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean resign_bundle(RaucBundle *bundle, const gchar *outpath, GError **error);

/**
 * Extract a bundle.
 *
 * This will extract the entire bundle content into a given directory.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outputdir directory to extract content into
 * @param error Return location for a GError
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean extract_bundle(RaucBundle *bundle, const gchar *outputdir, GError **error);

/**
 * Extract a single file from a bundle.
 *
 * This will extract a single file into a given directory.
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outputdir directory to extract the file into
 * @param file filename of file to extract from bundle
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean extract_file_from_bundle(RaucBundle *bundle, const gchar *outputdir, const gchar *file, GError **error);

/**
 * Create casync bundle.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outbundle output location for converted casync bundle
 * @param error Return location for a GError
 */
gboolean create_casync_bundle(RaucBundle *bundle, const gchar *outbundle, GError **error);

/**
 * Mount a bundle.
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean mount_bundle(RaucBundle *bundle, GError **error);

/**
 * Unmount a bundle.
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean umount_bundle(RaucBundle *bundle, GError **error);

/**
 * Frees the memory allocated by a RaucBundle.
 *
 * @param bundle bundle to free
 */
void free_bundle(RaucBundle *bundle);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucBundle, free_bundle);
