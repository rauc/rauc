#include <openssl/err.h>
#include <openssl/pem.h>

#include "signature.h"

static EVP_PKEY *load_key(const gchar *keyfile) {
        EVP_PKEY *res = NULL;
	BIO *key = NULL;

	key = BIO_new_file(keyfile, "r");
	if (key == NULL) {
		g_warning("failed to load key file");
		goto out;
	}

	res = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
	if (res == NULL) {
		g_warning("failed to parse key file");
		goto out;
	}
out:
	BIO_free_all(key);
	return res;
}

static X509 *load_cert(const gchar *certfile) {
	X509 *res = NULL;
	BIO *cert = NULL;

	cert = BIO_new_file(certfile, "r");
	if (cert == NULL) {
		g_warning("failed to load cert file");
		goto out;
	}

	res = PEM_read_bio_X509(cert, NULL, NULL, NULL);
	if (res == NULL) {
		g_warning("failed to parse cert file");
		goto out;
	}
out:
	BIO_free_all(cert);
	return res;
}

GByteArray *cms_sign(GByteArray *content, const gchar *certfile, const gchar *keyfile) {
	GByteArray *res = g_byte_array_new();
	BIO *content_bio = BIO_new_mem_buf(content->data, content->len);
	X509 *signcert = load_cert(certfile);
	EVP_PKEY *pkey = load_key(keyfile);
	CMS_ContentInfo *cms = NULL;

	cms = CMS_sign(signcert, pkey, NULL, content_bio, CMS_DETACHED | CMS_TEXT | CMS_PARTIAL);
	if (cms == NULL) {
		g_warning("failed to create signature");
		goto out;
	}

out:
	ERR_print_errors_fp(stderr);
	BIO_free_all(content_bio);
	return res;
}

gboolean cms_verify(GByteArray *content, GByteArray *sig) {
	STACK_OF(X509) *other = NULL;
	X509_STORE *store = NULL;
	X509_LOOKUP *lookup = NULL;
	CMS_ContentInfo *cms = NULL;
	BIO *incontent = BIO_new_mem_buf(content->data, content->len);
	BIO *insig = BIO_new_mem_buf(sig->data, sig->len);
	BIO *out = BIO_new(BIO_s_mem());
	gboolean res = FALSE;

	if (!(store = X509_STORE_new()))
		goto out;
	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())))
		goto out;
	if (!X509_LOOKUP_load_file(lookup,
				   "test/openssl-ca/dev-ca.pem",
				   X509_FILETYPE_PEM)) {
		g_warning("failed to load CA file");
		goto out;
	}

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_warning("failed to parse signature");
		goto out;
	}

	ERR_print_errors_fp(stderr);
	if (!CMS_verify(cms, other, store, incontent, out, CMS_DETACHED)) {
		g_print("signature invalid");
		goto out;
	}

	res = TRUE;
out:
	ERR_print_errors_fp(stderr);
	BIO_free_all(incontent);
	BIO_free_all(insig);
	BIO_free_all(out);
	X509_STORE_free(store);
	return res;
}
