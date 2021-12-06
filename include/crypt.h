#pragma once

#include <glib.h>

#define R_CRYPT_ERROR r_crypt_error_quark()
GQuark r_crypt_error_quark(void);

typedef enum {
	R_CRYPT_ERROR_FAILED,
} RCryptError;

/**
 * Creates AES-encrypted image.
 *
 * Creates image to be used with dm-crypt in aes-cbc-plain64 mode.
 *
 * @param in input (source) filename
 * @param out output (encrypted) filename
 * @param key AES key to use for encryption
 * @param error Return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE on error
 */
gboolean r_crypt_encrypt(const gchar *in, const gchar *out, const guint8 *key, GError **error);

/**
 * Decrypts AES-encrypted image.
 *
 * Manually decrypts image to be used with dm-crypt in aes-cbc-plain64 mode.
 *
 * @param in input (source) filename
 * @param out output (decrypted) filename
 * @param key AES key to use for encryption
 * @param maxsize limits decryption of input file to maxsize bytes.
 *        0 means no limitation.
 * @param error Return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE on error
 */
gboolean r_crypt_decrypt(const gchar *in, const gchar *out, const guint8 *key, goffset maxsize, GError **error);
