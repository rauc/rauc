#pragma once

#include <openssl/cms.h>
#include <openssl/safestack.h>
#include <glib.h>

#include "manifest.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC(CMS_ContentInfo, CMS_ContentInfo_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)

/**
 * Use 'g_autoptr(R_X509_STACK) stack = NULL' to declare an X509 stack whose
 * structure (but not its elements) will be freed when 'stack' goes out of
 * scope.
 */
typedef STACK_OF(X509) R_X509_STACK;
void r_signature_free_x509_stack(R_X509_STACK *stack);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(R_X509_STACK, r_signature_free_x509_stack);

/**
 * Use 'g_autoptr(R_X509_STACK_POP) stack = NULL' to declare an X509 stack
 * whose elements (and the structure itself) will be freed when 'stack' goes
 * out of scope.
 */
typedef STACK_OF(X509) R_X509_STACK_POP;
void r_signature_free_x509_stack_pop(R_X509_STACK_POP *stack);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(R_X509_STACK_POP, r_signature_free_x509_stack_pop);

#define R_SIGNATURE_ERROR r_signature_error_quark()
GQuark r_signature_error_quark(void);

typedef enum {
	R_SIGNATURE_ERROR_UNKNOWN,
	R_SIGNATURE_ERROR_CRYPTOINIT_FAILED,
	R_SIGNATURE_ERROR_LOAD_FAILED,
	R_SIGNATURE_ERROR_PARSE_ERROR,
	R_SIGNATURE_ERROR_CREATE_SIG,
	R_SIGNATURE_ERROR_SERIALIZE_SIG,
	R_SIGNATURE_ERROR_X509_CTX_NEW,
	R_SIGNATURE_ERROR_X509_CTX_INIT,
	R_SIGNATURE_ERROR_VERIFY_CERT,
	R_SIGNATURE_ERROR_GET_SIGNER,
	R_SIGNATURE_ERROR_NUM_SIGNER,
	R_SIGNATURE_ERROR_X509_NEW,
	R_SIGNATURE_ERROR_X509_LOOKUP,
	R_SIGNATURE_ERROR_X509_PURPOSE,
	R_SIGNATURE_ERROR_CA_LOAD,
	R_SIGNATURE_ERROR_PARSE,
	R_SIGNATURE_ERROR_INVALID,
	R_SIGNATURE_ERROR_SIGNER_CN_FORBIDDEN,
} RSignatureError;

/**
 * Initialization routine.
 *
 * Sets up OpenSSL (libcrypto).
 *
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean signature_init(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Prepare an OpenSSL X509_STORE for signature verification.
 *
 * When capath or cadir are NULL, this uses the paths and options configured in
 * the [keyring] section in system.conf or the commandline by default.
 *
 * @param capath optional ca file path
 * @param cadir optional ca directory path
 * @param error return location for a GError, or NULL
 *
 * @return X509_STORE, NULL if failed
 */
X509_STORE* setup_x509_store(const gchar *capath, const gchar *cadir, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sign content with provided certificate and private key
 *
 * @param content content that should be signed
 * @param detached whether the signature should be detached
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param interfiles NULL-terminated array of intermediate certificate file
 *                   name strings to include in the bundle signature
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_sign(GBytes *content, gboolean detached, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sign file with provided certificate and private key
 *
 * @param filename file with content that should be signed
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param interfiles NULL-terminated array of intermediate certificate file
 *                   name strings to include in the bundle signature
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Sign manifest with provided certificate and private key
 *
 * @param manifest manifest that should be serialized and signed
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param interfiles NULL-terminated array of intermediate certificate file
 *                   name strings to include in the bundle signature
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_sign_manifest(RaucManifest *manifest, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Append signature generated with provided certificate and private key
 *
 * @param input_sig existing CMS that should be appended to
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param interfiles NULL-terminated array of intermediate certificate file
 *                   name strings to include in the bundle signature
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_append_signature(GBytes *input_sig, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check whether the CMS signature is detached or not
 *
 * @param sig signature to be checked
 * @param detached return location for the detached/inline result
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_is_detached(GBytes *sig, gboolean *detached, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Check whether the CMS data is 'enveloped' (i.e. encrypted)
 *
 * @param cms raw (ASN.1/DER-encoded) CMS data to check
 *
 * @return TRUE if CMS data type is 'enveloped', FALSE otherwise
 */
gboolean cms_is_envelopeddata(GBytes *cms_data);

/**
 * Extract manifest included in a signature without verification.
 *
 * @param sig signature containing the manifest
 * @param manifest return location for included manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_get_unverified_manifest(GBytes *sig, GBytes **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Verify detached and inline signatures.
 *
 * This function is only used by the tests and internally for cms_verify_fd and
 * cms_verify_sig.
 *
 * @param content content to verify against signature, or NULL (for inline signature)
 * @param sig signature used to verify
 * @param store X509 store to use for verification
 * @param cms Return location for the CMS_ContentInfo used for verification
 * @param manifest return location for included manifest, or NULL (for detached signature)
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify_bytes(GBytes *content, GBytes *sig, X509_STORE *store, CMS_ContentInfo **cms, GBytes **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Verify detached signature for given file.
 *
 * @param fd file descriptor to verify against signature
 * @param sig signature used to verify
 * @param limit size of content to use, 0 if all should be included
 * @param store X509 store to use for verification
 * @param cms Return location for the CMS_ContentInfo used for verification
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify_fd(gint fd, GBytes *sig, goffset limit, X509_STORE *store, CMS_ContentInfo **cms, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Verify inline signature and return included manifest.
 *
 * @param sig signature to verify
 * @param store X509 store to use for verification
 * @param cms Return location for the CMS_ContentInfo used for verification
 * @param manifest return location for included manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify_sig(GBytes *sig, X509_STORE *store, CMS_ContentInfo **cms, GBytes **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Calculates hash for certificate pubkey info.
 *
 * This hashes the complete 'Subject Public Key Info' similar to what DANE
 * does.
 *
 * @param cert certificate to calculate hash for
 *
 * @return colon-separated hexadecimal representation of subject key hash
 */
gchar* get_pubkey_hash(X509 *cert)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Calculates all hashes for certificate stacks pubkeys
 *
 * @param certs Stack of certificates
 *
 * @return Array of pointers to string representations of hashes
 */
gchar** get_pubkey_hashes(STACK_OF(X509) *certs)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns string representation of certificate.
 *
 * @param sig GBytes containing raw CMS signature from bundle
 * @param[out] error return location for a GError, or NULL
 *
 * @return allocated string containing default OpenSSL text representation of
 *         signer certificate (first in chain)
 */
gchar* sigdata_to_string(GBytes *sig, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Return string representation of certificate chain.
 *
 * @param verified_chain Stack of X509 certificates as returned by
 *                       cms_get_signer_info
 * @return allocated string containing text representation of certificate chain
 *         (signer and issuer)
 */
gchar* format_cert_chain(STACK_OF(X509) *verified_chain)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get infos about signer and verification chain.
 *
 * Must be called *after* cms_verify()
 *
 * @param cms CMS_ContentInfo used in cms_verify()
 * @param store Store used in cms_verify()
 * @param[out] verified_chain Return location for the verification chain, or NULL
 *                            [transfer full]
 * @param[out] error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_get_cert_chain(CMS_ContentInfo *cms, X509_STORE *store, STACK_OF(X509) **verified_chain, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Encrypt content for provided recipients
 *
 * @param[in] content content to encrypt
 * @param[in] recipients NULL-terminated array of recipient certificate file
 *                   name strings.
 *                   If the file contains multiple concatenated
 *                   certificates, all will be read.
 * @param[out] error return location for a GError, or NULL
 *
 * @return encrypted CMS data, NULL if failed
 */
GBytes *cms_encrypt(GBytes *content, gchar **recipients, GError **error);

/**
 * Decrypt content with provided keyfile.
 *
 * A cert file of the recipient may be passed to speed up finding the right
 * recipient in the CMS structure (otherwise each must be tried).
 *
 * @param[in] content content to decrypt
 * @param[in] certfile recipient cert file to use for decryption, or NULL
 * @param[in] keyfile recipient key file to use for decryption
 * @param[out] error return location for a GError, or NULL
 *
 * @return decrypted CMS data, NULL if failed
 */
GBytes *cms_decrypt(GBytes *content, const gchar *certfile, const gchar *keyfile, GError **error);

/**
 * Dump content of enevloped CMS.
 *
 * @param[in] sig enveloped CMS data to dump
 * @param[out] error return location for a GError, or NULL
 *
 * @return string representation for printing, or NULL on error
 */
gchar* envelopeddata_to_string(GBytes *sig, GError **error);
