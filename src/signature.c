#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "context.h"
#include "signature.h"

GQuark r_signature_error_quark(void)
{
	return g_quark_from_static_string("r_signature_error_quark");
}

void signature_init(void)
{
	OPENSSL_no_config();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

static EVP_PKEY *load_key(const gchar *keyfile, GError **error)
{
	EVP_PKEY *res = NULL;
	BIO *key = NULL;
	unsigned long err;
	const gchar *data;
	int flags;

	g_return_val_if_fail(keyfile != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

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
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse key file '%s': %s", keyfile,
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		goto out;
	}
out:
	BIO_free_all(key);
	return res;
}

static X509 *load_cert(const gchar *certfile, GError **error)
{
	X509 *res = NULL;
	BIO *cert = NULL;
	unsigned long err;
	const gchar *data;
	int flags;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

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
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse cert file '%s': %s", certfile,
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		goto out;
	}

out:
	BIO_free_all(cert);
	return res;
}

static GBytes *bytes_from_bio(BIO *bio)
{
	long size;
	char *data;

	g_return_val_if_fail(bio != NULL, NULL);

	size = BIO_get_mem_data(bio, &data);
	return g_bytes_new(data, size);
}

GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
{
	GError *ierror = NULL;
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
			g_bytes_get_size(content));
	BIO *outsig = BIO_new(BIO_s_mem());
	X509 *signcert = NULL;
	EVP_PKEY *pkey = NULL;
	STACK_OF(X509) *intercerts = NULL;
	CMS_ContentInfo *cms = NULL;
	GBytes *res = NULL;
	int flags = CMS_DETACHED | CMS_BINARY;

	g_return_val_if_fail(content != NULL, NULL);
	g_return_val_if_fail(certfile != NULL, NULL);
	g_return_val_if_fail(keyfile != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

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

	intercerts = sk_X509_new_null();

	for (gchar **intercertpath = interfiles; intercertpath && *intercertpath != NULL; intercertpath++) {

		X509 *intercert = load_cert(*intercertpath, &ierror);
		if (intercert == NULL) {
			g_propagate_error(error, ierror);
			goto out;
		}

		sk_X509_push(intercerts, intercert);
	}

	cms = CMS_sign(signcert, pkey, intercerts, incontent, flags);
	if (cms == NULL) {
		unsigned long err;
		const gchar *data;
		int errflags;
		err = ERR_get_error_line_data(NULL, NULL, &data, &errflags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"failed to create signature: %s", (errflags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
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

gchar* get_pubkey_hash(X509 *cert)
{
	gchar *data = NULL;
	GString *string;
	g_autofree unsigned char *der_buf = NULL;
	unsigned char *tmp_buf = NULL;
	unsigned int len = 0;
	unsigned int n = 0;
	unsigned char md[SHA256_DIGEST_LENGTH];

	g_return_val_if_fail(cert != NULL, NULL);

	/* As we print colon-separated hex, we need 3 chars per byte */
	string = g_string_sized_new(SHA256_DIGEST_LENGTH * 3);

	len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
	if (len <= 0) {
		g_warning("DER Encoding failed\n");
		goto out;
	}
	/* As i2d_X509_PUBKEY() moves pointer after end of data,
	 * we must use a tmp pointer, here */
	der_buf = tmp_buf = g_malloc(len);
	i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &tmp_buf);

	g_assert(((unsigned int)(tmp_buf - der_buf)) == len);

	if (!EVP_Digest(der_buf, len, md, &n, EVP_sha256(), NULL)) {
		g_warning("Error in EVP_Digest\n");
		goto out;
	}

	g_assert_cmpint(n, ==, SHA256_DIGEST_LENGTH);

	for (int j = 0; j < (int)n; j++) {
		g_string_append_printf(string, "%02X:", md[j]);
	}
	g_string_truncate(string, SHA256_DIGEST_LENGTH * 3 - 1);

	data = g_string_free(string, FALSE);
out:
	return data;
}

gchar** get_pubkey_hashes(STACK_OF(X509) *verified_chain)
{
	GPtrArray *hashes = g_ptr_array_new_full(4, g_free);
	gchar **ret = NULL;

	g_return_val_if_fail(verified_chain != NULL, NULL);

	for (int i = 0; i < sk_X509_num(verified_chain); i++) {
		gchar *hash;

		hash = get_pubkey_hash(sk_X509_value(verified_chain, i));
		if (hash == NULL) {
			g_ptr_array_free(hashes, TRUE);
			goto out;
		}
		g_ptr_array_add(hashes, hash);
	}
	g_ptr_array_add(hashes, NULL);

	ret = (gchar**) g_ptr_array_free(hashes, FALSE);
out:
	return ret;
}

gchar* print_signer_cert(STACK_OF(X509) *verified_chain)
{
	BIO *mem;
	gchar *data, *ret;
	gsize size;

	g_return_val_if_fail(verified_chain != NULL, NULL);

	mem = BIO_new(BIO_s_mem());
	X509_print_ex(mem, sk_X509_value(verified_chain, 0), 0, 0);

	size = BIO_get_mem_data(mem, &data);
	ret = g_strndup(data, size);

	BIO_set_close(mem, BIO_CLOSE);
	BIO_free(mem);

	return ret;
}

gchar* print_cert_chain(STACK_OF(X509) *verified_chain)
{
	GString *text = NULL;
	char buf[BUFSIZ];

	g_return_val_if_fail(verified_chain != NULL, NULL);

	text = g_string_new("Certificate Chain:\n");
	for (int i = 0; i < sk_X509_num(verified_chain); i++) {
		X509_NAME_oneline(X509_get_subject_name(sk_X509_value(verified_chain, i)),
				buf, sizeof buf);
		g_string_append_printf(text, "%2d Subject: %s\n", i, buf);
		X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(verified_chain, i)),
				buf, sizeof buf);
		g_string_append_printf(text, "   Issuer: %s\n", buf);
		g_string_append_printf(text, "   SPKI sha256: %s\n", get_pubkey_hash(sk_X509_value(verified_chain, i)));
	}

	return g_string_free(text, FALSE);
}

gboolean cms_get_cert_chain(CMS_ContentInfo *cms, X509_STORE *store, STACK_OF(X509) **verified_chain, GError **error)
{
	STACK_OF(X509) *signers = NULL;
	STACK_OF(X509) *intercerts = NULL;
	X509_STORE_CTX *cert_ctx = NULL;
	gint signer_cnt;
	gboolean res = FALSE;

	g_return_val_if_fail(cms != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(verified_chain == NULL || *verified_chain == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	signers = CMS_get0_signers(cms);
	if (signers == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_GET_SIGNER,
				"Failed to obtain signer info");
		goto out;
	}

	signer_cnt = sk_X509_num(signers);
	if (signer_cnt != 1) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_NUM_SIGNER,
				"Unsupported number of signers: %d", signer_cnt);
		goto out;
	}

	intercerts = CMS_get1_certs(cms);

	cert_ctx = X509_STORE_CTX_new();
	if (cert_ctx == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_CTX_NEW,
				"Failed to allocate new X509 CTX store");
		goto out;
	}

	if (!X509_STORE_CTX_init(cert_ctx, store, sk_X509_value(signers, 0), intercerts)) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_CTX_INIT,
				"Failed to init new X509 CTX store");
		goto out;
	}

	if(X509_verify_cert(cert_ctx) != 1) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_VERIFY_CERT,
				"Failed to verify X509 cert: %s",
				X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)));
		goto out;
	}

	*verified_chain = X509_STORE_CTX_get1_chain(cert_ctx);

	/* The first element in the chain must be the signer certificate */
	g_assert(X509_cmp(sk_X509_value(signers, 0), sk_X509_value(*verified_chain, 0)) == 0);

	g_debug("Got %d chain elements", sk_X509_num(*verified_chain));

	res = TRUE;
out:
	if (cert_ctx)
		X509_STORE_CTX_free(cert_ctx);
	if (signers)
		sk_X509_free(signers);

	return res;
}

gboolean cms_verify(GBytes *content, GBytes *sig, CMS_ContentInfo **cms, X509_STORE **store, GError **error)
{
	const gchar *capath = r_context()->config->keyring_path;
	X509_STORE *istore = NULL;
	X509_LOOKUP *lookup = NULL;
	CMS_ContentInfo *icms = NULL;
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
			g_bytes_get_size(content));
	BIO *insig = BIO_new_mem_buf((void *)g_bytes_get_data(sig, NULL),
			g_bytes_get_size(sig));
	gboolean res = FALSE;

	g_return_val_if_fail(content != NULL, FALSE);
	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(store == NULL || *store == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("cms_verify", "Verifying signature", 0);

	if (!(istore = X509_STORE_new())) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_NEW,
				"failed to allocate new X509 store");
		goto out;
	}
	if (!(lookup = X509_STORE_add_lookup(istore, X509_LOOKUP_file()))) {
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

	if (!(icms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		goto out;
	}

	if (!CMS_verify(icms, NULL, istore, incontent, NULL, CMS_DETACHED | CMS_BINARY)) {
		unsigned long err;
		const gchar *data;
		int flags;
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"signature verification failed: %s", (flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		goto out;
	}

	if (cms)
		*cms = icms;

	if (store)
		*store = istore;


	res = TRUE;
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(insig);
	if (!store)
		X509_STORE_free(istore);
	if (!cms)
		CMS_ContentInfo_free(icms);
	r_context_end_step("cms_verify", res);
	return res;
}

GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GMappedFile) file = NULL;
	g_autoptr(GBytes) content = NULL;
	GBytes *sig = NULL;

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(certfile != NULL, FALSE);
	g_return_val_if_fail(keyfile != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	file = g_mapped_file_new(filename, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	sig = cms_sign(content, certfile, keyfile, interfiles, &ierror);
	if (sig == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return sig;
}

gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit, CMS_ContentInfo **cms, X509_STORE **store, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GMappedFile) file = NULL;
	g_autoptr(GBytes) content = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(store == NULL || *store == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

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

	res = cms_verify(content, sig, cms, store, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

