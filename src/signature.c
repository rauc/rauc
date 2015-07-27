#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <context.h>
#include "signature.h"

#define R_SIGNATURE_ERROR r_signature_error_quark ()

static GQuark r_signature_error_quark (void)
{
  return g_quark_from_static_string ("r_signature_error_quark");
}

#define R_SIGNATURE_ERROR_UNKNOWN	0
#define R_SIGNATURE_ERROR_LOAD_FAILED	1
#define R_SIGNATURE_ERROR_PARSE_ERROR	2
#define R_SIGNATURE_ERROR_CREATE_SIG	3
#define R_SIGNATURE_ERROR_SERIALIZE_SIG	4

#define R_SIGNATURE_ERROR_X509_NEW	10
#define R_SIGNATURE_ERROR_X509_LOOKUP	11
#define R_SIGNATURE_ERROR_CA_LOAD	12
#define R_SIGNATURE_ERROR_PARSE		13
#define R_SIGNATURE_ERROR_INVALID	14

void signature_init(void) {
	OPENSSL_no_config();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

static EVP_PKEY *load_key(const gchar *keyfile, GError **error) {
        EVP_PKEY *res = NULL;
	BIO *key = NULL;

	g_assert(error == NULL || *error == NULL);

	key = BIO_new_file(keyfile, "r");
	if (key == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load key file '%s'", keyfile);
		goto out;
	}

	res = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
	if (res == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse key file '%s'", keyfile);
		goto out;
	}
out:
	BIO_free_all(key);
	return res;
}

static X509 *load_cert(const gchar *certfile, GError **error) {
	X509 *res = NULL;
	BIO *cert = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	cert = BIO_new_file(certfile, "r");
	if (cert == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load cert file '%s'", certfile);
		goto out;
	}

	res = PEM_read_bio_X509(cert, NULL, NULL, NULL);
	if (res == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse cert file '%s'", certfile);
		goto out;
	}
out:
	BIO_free_all(cert);
	return res;
}

static GBytes *bytes_from_bio(BIO *bio) {
	long size;
	char *data;

	size = BIO_get_mem_data(bio, &data);
	return g_bytes_new(data, size);
}

GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile, GError **error) {
	GError *ierror = NULL;
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
					 g_bytes_get_size(content));
	BIO *outsig = BIO_new(BIO_s_mem());
	X509 *signcert = NULL;
	EVP_PKEY *pkey = NULL;
	CMS_ContentInfo *cms = NULL;
	GBytes *res = NULL;
	int flags = CMS_DETACHED | CMS_BINARY;

	signcert = load_cert(certfile, &ierror);
	if (signcert == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	pkey = load_key(keyfile, &ierror);
	if (pkey == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	cms = CMS_sign(signcert, pkey, NULL, incontent, flags);
	if (cms == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CREATE_SIG,
				"failed to create signature");
		goto out;
	}
	if (!i2d_CMS_bio(outsig, cms)) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_SERIALIZE_SIG,
				"failed to serialize signature");
		goto out;
	}

	res = bytes_from_bio(outsig);

	if (!res) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_UNKNOWN,
				"Read zero bytes");
		goto out;
	}
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(outsig);
	return res;
}

gboolean cms_verify(GBytes *content, GBytes *sig, GError **error) {
	const gchar *capath = r_context()->config->keyring_path;
	STACK_OF(X509) *other = NULL;
	X509_STORE *store = NULL;
	X509_LOOKUP *lookup = NULL;
	CMS_ContentInfo *cms = NULL;
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
					 g_bytes_get_size(content));
	BIO *insig = BIO_new_mem_buf((void *)g_bytes_get_data(sig, NULL),
				     g_bytes_get_size(sig));
	BIO *outcontent = BIO_new(BIO_s_mem());
	gboolean res = FALSE;

	if (!(store = X509_STORE_new())) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_NEW,
				"failed to allocate new X509 store");
		goto out;
	}
	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_LOOKUP,
				"failed to add X509 store lookup");
		goto out;
	}
	if (!X509_LOOKUP_load_file(lookup, capath, X509_FILETYPE_PEM)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CA_LOAD,
				"failed to load CA file '%s'", capath);
		goto out;
	}

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		goto out;
	}

	if (!CMS_verify(cms, other, store, incontent, outcontent, CMS_DETACHED)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"invalid signature");
		goto out;
	}

	res = TRUE;
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(insig);
	BIO_free_all(outcontent);
	X509_STORE_free(store);
	return res;
}

GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile, GError **error) {
	GError *ierror = NULL;
	GMappedFile *file;
	GBytes *content = NULL;
	GBytes *sig = NULL;

	file = g_mapped_file_new(filename, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	sig = cms_sign(content, certfile, keyfile, &ierror);
	if (sig == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_bytes_unref(content);
	g_mapped_file_unref(file);
	return sig;
}

gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit, GError **error) {
	GError *ierror = NULL;
	GMappedFile *file;
	GBytes *content = NULL;
	gboolean res = FALSE;

	file = g_mapped_file_new(filename, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	if (limit) {
		GBytes *tmp = g_bytes_new_from_bytes(content, 0, limit);
		g_bytes_unref(content);
		content = tmp;
	}

	res = cms_verify(content, sig, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_bytes_unref(content);
	g_mapped_file_unref(file);
	return res;
}
