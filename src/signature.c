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

static GBytes *bytes_from_bio(BIO *bio) {
	long size;
	char *data;

	size = BIO_get_mem_data(bio, &data);
	return g_bytes_new(data, size);
}

GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile) {
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
					 g_bytes_get_size(content));
	BIO *outsig = BIO_new(BIO_s_mem());
	X509 *signcert = load_cert(certfile);
	EVP_PKEY *pkey = load_key(keyfile);
	CMS_ContentInfo *cms = NULL;
	GBytes *res = NULL;
	int flags = CMS_DETACHED | CMS_BINARY;

	cms = CMS_sign(signcert, pkey, NULL, incontent, flags);
	if (cms == NULL) {
		g_warning("failed to create signature");
		goto out;
	}
	if (!i2d_CMS_bio(outsig, cms)) {
		g_warning("failed to serialize signature");
		goto out;
	}

	res = bytes_from_bio(outsig);
out:
	BIO_free_all(incontent);
	BIO_free_all(outsig);
	return res;
}

gboolean cms_verify(GBytes *content, GBytes *sig) {
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

	if (!CMS_verify(cms, other, store, incontent, outcontent, CMS_DETACHED)) {
		/* g_print("signature invalid"); */
		goto out;
	}

	res = TRUE;
out:
	BIO_free_all(incontent);
	BIO_free_all(insig);
	BIO_free_all(outcontent);
	X509_STORE_free(store);
	return res;
}

GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile) {
	GMappedFile *file;
	GBytes *content = NULL;
	GBytes *sig = NULL;

	file = g_mapped_file_new(filename, FALSE, NULL);
	if (file == NULL) {
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	sig = cms_sign(content, certfile, keyfile);

out:
	g_bytes_unref(content);
	g_mapped_file_unref(file);
	return sig;
}

gboolean cms_verify_file(const gchar *filename, GBytes *sig) {
	GMappedFile *file;
	GBytes *content = NULL;
	gboolean res = FALSE;

	file = g_mapped_file_new(filename, FALSE, NULL);
	if (file == NULL) {
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	res = cms_verify(content, sig);

out:
	g_bytes_unref(content);
	g_mapped_file_unref(file);
	return res;
}
