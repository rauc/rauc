#pragma once

#include <openssl/cms.h>
#include <glib.h>
#include <gio/gio.h>

#include "manifest.h"
#include "nbd.h"
#include "utils.h"

#define R_BUNDLE_ERROR r_bundle_error_quark()
GQuark r_bundle_error_quark(void);

typedef enum {
	R_BUNDLE_ERROR_SIGNATURE,
	R_BUNDLE_ERROR_KEYRING,
	R_BUNDLE_ERROR_IDENTIFIER,
	R_BUNDLE_ERROR_UNSAFE,
	R_BUNDLE_ERROR_PAYLOAD,
	R_BUNDLE_ERROR_FORMAT,
	R_BUNDLE_ERROR_VERITY,
	R_BUNDLE_ERROR_CRYPT,
	R_BUNDLE_ERROR_UNSUPPORTED,
} RBundleError;

typedef struct {
	gchar *tls_cert;
	gchar *tls_key;
	gchar *tls_ca;
	gboolean tls_no_verify;
	GStrv http_headers;
	GPtrArray *http_info_headers;
} RaucBundleAccessArgs;

typedef struct {
	gchar *path;
	gchar *origpath;
	gchar *storepath;

	RaucNBDDevice *nbd_dev;
	RaucNBDServer *nbd_srv;

	GInputStream *stream;

	goffset size;
	GBytes *enveloped_data;
	GBytes *sigdata;
	gchar *mount_point;
	RaucManifest *manifest;
	gboolean verification_disabled;
	gboolean signature_verified;
	gboolean payload_verified;
	gboolean exclusive_verified;
	gboolean was_encrypted;
	gchar *exclusive_check_error;
	STACK_OF(X509) *verified_chain;
} RaucBundle;

typedef enum {
	CHECK_BUNDLE_DEFAULT       = 0,
	/* skip BIT(0) for now to avoid interpreting a TRUE as NO_VERIFY by mistake */
	CHECK_BUNDLE_NO_VERIFY     = BIT(1),      // If not set the bundle signature
	                                          // will be verified, if set this
	                                          // step will be skipped.
	CHECK_BUNDLE_NO_CHECK_TIME = BIT(2),      // If set, X509_V_FLAG_NO_CHECK_TIME
	                                          // is passed to openssl to suppress
	                                          // checking the validity period of
	                                          // certificates and CRLs against
	                                          // the current time.
	CHECK_BUNDLE_TRUST_ENV     = BIT(3),      // If set, the runtime environment
	                                          // is fully trusted and no attempts
	                                          // will be made to protect against
	                                          // concurrent modification of the
	                                          // bundle.
} CheckBundleParams;

/**
 * Create a bundle.
 *
 * @param bundlename filename of the bundle to create
 * @param contentdir directory containing this bundle content
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean create_bundle(const gchar *bundlename, const gchar *contentdir, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check a bundle.
 *
 * This will verify and check the bundle content.
 *
 * For bundle formats with detached CMS (i.e. 'verity' or 'crypt'),
 * this will also initialize the manifest.
 *
 * @param bundlename filename of the bundle to check
 * @param bundle return location for a RaucBundle struct.
 *               This will contain all bundle information obtained by
 *               check_bundle
 * @param params bit-field enum CheckBundleParams with additional flags for the check
 * @param access_args Optional arguments to control streaming access
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean check_bundle(const gchar *bundlename, RaucBundle **bundle, CheckBundleParams params, RaucBundleAccessArgs *access_args, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check the bundle payload, if needed and possible.
 *
 * For verity bundles, this checks the full squashfs against the dm-verity hash
 * tree and the root hash against the one contained in the manifest.
 * This is mainly useful for when extracting the bundle contents without
 * mounting.
 * It will set the payload_verified struct member to remember that the payload
 * has been verified.
 *
 * @param bundle the RaucBundle struct to verify
 *               This will contain all bundle information obtained by
 *               check_bundle
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean check_bundle_payload(RaucBundle *bundle, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Resign a bundle.
 *
 * This will create a copy of a bundle with a new signature but unmodified
 * content.
 *
 * If append is true, the signature is not replaced but appended to.
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outpath filename of the resigned output bundle
 * @param append whether the signature should be appended
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean resign_bundle(RaucBundle *bundle, const gchar *outpath, gboolean append, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Replace a bundle signature.
 *
 * This will create a copy of a bundle with a new given signature
 * but unmodified content.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param insig filename of the signature for replacement
 * @param outpath filename of the output bundle
 * @param params bit-field enum CheckBundleParams with additional flags for the check
 * @param error Return location for a GError
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean replace_signature(RaucBundle *bundle, const gchar *insig, const gchar *outpath, CheckBundleParams params, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Extract a bundle signature.
 *
 * This will extract the bundle signature into a given file.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outputsig file to extract signature
 * @param error Return location for a GError
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean extract_signature(RaucBundle *bundle, const gchar *outputsig, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
gboolean extract_bundle(RaucBundle *bundle, const gchar *outputdir, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Extract and load the manifest from a bundle.
 *
 * This is mainly useful for plain bundles, as the manifest is already contained in
 * the signature in other cases and available after signature verification.
 *
 * Note that check_bundle() must be called prior to this, to obtain a
 * RaucBundle struct.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param manifest return location for extracted manifest
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean load_manifest_from_bundle(RaucBundle *bundle, RaucManifest **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Create casync bundle.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outbundle output location for converted casync bundle
 * @param ignore_images string list of slot classes of images to ignore during conversion
 * @param error Return location for a GError
 */
gboolean create_casync_bundle(RaucBundle *bundle, const gchar *outbundle, const gchar **ignore_images, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Encrypt a crypt bundle.
 *
 * @param bundle RaucBundle struct as returned by check_bundle()
 * @param outbundle output location for encrypted crypt bundle
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean encrypt_bundle(RaucBundle *bundle, const gchar *outbundle, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
gboolean mount_bundle(RaucBundle *bundle, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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

/**
 * Assembles HTTP Headers for use in the initial streaming request, based on the
 * selection in the system config. Additional headers can be added to the
 * GPtrArray later.
 *
 * @param transaction currently running installation transaction or NULL
 *
 * @return newly allocated GPtrArray with HTTP Header strings
 */
GPtrArray *assemble_info_headers(const gchar *transaction)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Frees the memory pointed to by the RaucBundleAccessArgs, but not the
 * structure itself.
 *
 * @param access_args RaucBundleAccessArgs to clear
 */
void clear_bundle_access_args(RaucBundleAccessArgs *access_args);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(RaucBundleAccessArgs, clear_bundle_access_args);
