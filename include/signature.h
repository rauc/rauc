#pragma once

#include <glib.h>

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
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify(GBytes *content, GBytes *sig);


/**
 * @param filename name of file with content to verify against signature
 * @param sig signature used to verify
 * @param limit size of content to use, 0 if all should be included
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit, GError **error);
