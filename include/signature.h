#pragma once

#include <openssl/cms.h>
#include <glib.h>

#define R_SIGNATURE_ERROR r_signature_error_quark ()
GQuark r_signature_error_quark (void);

typedef enum {
	R_SIGNATURE_ERROR_UNKNOWN,
	R_SIGNATURE_ERROR_LOAD_FAILED,
	R_SIGNATURE_ERROR_PARSE_ERROR,
	R_SIGNATURE_ERROR_CREATE_SIG,
	R_SIGNATURE_ERROR_SERIALIZE_SIG,

	R_SIGNATURE_ERROR_X509_NEW,
	R_SIGNATURE_ERROR_X509_LOOKUP,
	R_SIGNATURE_ERROR_CA_LOAD,
	R_SIGNATURE_ERROR_PARSE,
	R_SIGNATURE_ERROR_INVALID
} RSignatureError;

/**
 * Initalization routine.
 */
void signature_init(void);

/**
 * Sign content with provided certificate and private key
 *
 * @param content content that should be signed
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile, GError **error);

/**
 * Sign file with provided certificate and private key
 *
 * @param filename file with content that should be signed
 * @param certfile certificate file name
 * @param keyfile private key file name
 * @param error return location for a GError, or NULL
 *
 * @return signature bytes, NULL if failed
 */
GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile, GError **error);

/**
 * Verify signature for given content.
 *
 * @param content content to verify against signature
 * @param sig signature used to verify
 * @param cms Return location for the CMS_ContentInfo used for verification
 * @param store Return location for the X509 store used for verification
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify(GBytes *content, GBytes *sig, CMS_ContentInfo **cms, X509_STORE **store, GError **error);


/**
 * Verify signature for given file.
 *
 * @param filename name of file with content to verify against signature
 * @param sig signature used to verify
 * @param limit size of content to use, 0 if all should be included
 * @param cms Return location for the CMS_ContentInfo used for verification
 * @param store Return location for the X509 store used for verification
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit, CMS_ContentInfo **cms, X509_STORE **store, GError **error);
