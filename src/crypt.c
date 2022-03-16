#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <openssl/evp.h>

#include "crypt.h"
#include "utils.h"

#define ENC_SEC_SIZE	4096

GQuark r_crypt_error_quark(void)
{
	return g_quark_from_static_string("r_crypt_error_quark");
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);

static void iv_plain64(guint8 *iv, guint iv_size, guint64 sector)
{
	guint64 iv_val;
	g_return_if_fail(iv);

	memset(iv, 0, iv_size);
	iv_val = GUINT64_TO_LE(sector * ENC_SEC_SIZE / 512);
	memcpy(iv, &iv_val, sizeof(guint64));
}

/*
 * Encrypts or decrypts image to be used with dm-verity in aes-cbc-plain64 mode.
 *
 * Actual operation is chosen by 'encrypt' argument.
 *
 * Meant for internal use only, use r_crypt_encrypt() or r_crypt_decrypt()
 * instead.
 *
 * @param fd input (source) FILE
 * @param out output (encrypted) FILE
 * @param key AES key to use for encryption/decryption
 * @param encrypt whether to encrypt (TRUE) or decrypt (FALSE)
 * @param maxsize limits decryption of input FILE to maxsize bytes.
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean encrypt_or_decrypt(FILE *fd, FILE *out, const uint8_t *key, gboolean encrypt, goffset maxsize, GError **error)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char inbuf[ENC_SEC_SIZE], outbuf[ENC_SEC_SIZE];
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	int ret;
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	guint64 sector_count = 0;
	guint8 iv[16];
	goffset donesize = 0;

	g_return_val_if_fail(fd != NULL, FALSE);
	g_return_val_if_fail(out != NULL, FALSE);

	/* Don't set key or IV right away; we want to check lengths */
	ctx = EVP_CIPHER_CTX_new();
	ret = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt ? 1 : 0);
	if (!ret)
		g_error("Error setting cipher");

	/* disable padding as we expect to have only matching blocks*/
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* assert expected input key and iv size */
	g_assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
	g_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

	/* encrypt/decrypt in 4096 byte sectors */
	for (;;) {
		int inlen, outlen;

		/* plain64 iv mode */
		iv_plain64(iv, 16, sector_count++);

		/* set up with key and iv for encryption/decryption */
		ret = EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt ? 1 : 0);
		if (!ret)
			g_error("Error setting key and iv");

		inlen = fread(inbuf, 1, ENC_SEC_SIZE, fd);
		donesize += inlen;
		/* image size must be multiple of 4096 */
		if (inlen <= 0)
			break;
		if (inlen < ENC_SEC_SIZE) {
			g_set_error(error, R_CRYPT_ERROR, R_CRYPT_ERROR_FAILED, "Incomplete read: Input size must be multiple of %d (got only %d bytes)", ENC_SEC_SIZE, inlen);
			return FALSE;
		}

		/* limit decrypt size to maxsize if set */
		if (maxsize && donesize > maxsize) {
			return TRUE;
		}

		if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, ENC_SEC_SIZE)) {
			g_set_error(error, R_CRYPT_ERROR, R_CRYPT_ERROR_FAILED, "EVP_CipherUpdate() failed");
			return FALSE;
		}

		fwrite(outbuf, 1, outlen, out);

		if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
			g_set_error(error, R_CRYPT_ERROR, R_CRYPT_ERROR_FAILED, "EVP_CipherFinal_ex() failed");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean r_crypt_encrypt_or_decrypt(const gchar *inpath, const gchar *outpath, const uint8_t *key, gboolean encrypt, goffset maxsize, GError **error)
{
	FILE *infile = NULL, *outfile = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(inpath, FALSE);
	g_return_val_if_fail(outpath, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	infile = g_fopen(inpath, "r");
	if (!infile) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"Failed opening %s for reading: %s", inpath, g_strerror(err));
		res = FALSE;
		goto out;
	}

	outfile = g_fopen(outpath, "w");
	if (!outfile) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"Failed opening temporary file %s for writing: %s", outpath, g_strerror(err));
		res = FALSE;
		goto out;
	}

	res = encrypt_or_decrypt(infile, outfile, key, encrypt, maxsize, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to %s image: ", encrypt ? "encrypt" : "decrypt");
		goto out;
	}

	res = TRUE;
out:
	if (infile)
		fclose(infile);
	if (outfile)
		fclose(outfile);
	return res;
}

gboolean r_crypt_encrypt(const gchar *in, const gchar *out, const guint8 *key, GError **error)
{
	return r_crypt_encrypt_or_decrypt(in, out, key, TRUE, 0, error);
}

gboolean r_crypt_decrypt(const gchar *in, const gchar *out, const guint8 *key, goffset maxsize, GError **error)
{
	return r_crypt_encrypt_or_decrypt(in, out, key, FALSE, maxsize, error);
}
