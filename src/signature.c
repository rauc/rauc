#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/x509.h>

#include "context.h"
#include "signature.h"

/* Define for OpenSSL 1.0.x backwards compatiblity.
 * We use newer get0 names to be clear about memory ownership and to not use
 * API deprecated in OpenSSL 1.1.x */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define X509_get0_notAfter X509_get_notAfter
#define X509_get0_notBefore X509_get_notBefore
#endif

GQuark r_signature_error_quark(void)
{
	return g_quark_from_static_string("r_signature_error_quark");
}

gboolean signature_init(GError **error)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#else
	int ret;

	g_return_val_if_fail(error == FALSE || *error == NULL, FALSE);

	ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	if (!ret) {
		unsigned long err;
		const gchar *data;
		int flags;

		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CRYPTOINIT_FAILED,
				"Failed to initialize OpenSSL crypto: %s",
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		return FALSE;
	}
#endif

	return TRUE;
}

static ENGINE *get_pkcs11_engine(GError **error)
{
	static ENGINE *e = NULL;
	unsigned long err;
	const gchar *data;
	const gchar *env;
	int flags;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("pkcs11");
	if (e == NULL) {
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load PKCS11 engine: %s",
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));

		goto out;
	}

	env = g_getenv("RAUC_PKCS11_MODULE");
	if (env != NULL) {
		if (!ENGINE_ctrl_cmd_string(e, "MODULE_PATH", env, 0)) {
			err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_PARSE_ERROR,
					"failed to configure PKCS11 module path: %s",
					(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
			goto free;
		}
	}

	if (ENGINE_init(e) == 0) {
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to initialize PKCS11 engine: %s",
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));

		goto free;
	}

	env = g_getenv("RAUC_PKCS11_PIN");
	if (env != NULL && env[0] != '\0') {
		if (!ENGINE_ctrl_cmd_string(e, "PIN", env, 0)) {
			err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_PARSE_ERROR,
					"failed to configure PKCS11 PIN: %s",
					(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
			goto finish;
		}
	}

	goto out;

finish:
	ENGINE_finish(e);
free:
	ENGINE_free(e);
	e = NULL;
out:
	return e;
}

static EVP_PKEY *load_key_file(const gchar *keyfile, GError **error)
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

static EVP_PKEY *load_key_pkcs11(const gchar *url, GError **error)
{
	EVP_PKEY *res = NULL;
	unsigned long err;
	const gchar *data;
	GError *ierror = NULL;
	int flags;
	ENGINE *e;

	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	e = get_pkcs11_engine(&ierror);
	if (e == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = ENGINE_load_private_key(e, url, NULL, NULL);
	if (res == NULL) {
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load PKCS11 private key for '%s': %s", url,
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		goto out;
	}
out:
	return res;
}

static EVP_PKEY *load_key(const gchar *name, GError **error)
{
	g_return_val_if_fail(name != NULL, NULL);

	if (g_str_has_prefix(name, "pkcs11:"))
		return load_key_pkcs11(name, error);
	else
		return load_key_file(name, error);
}

static X509 *load_cert_file(const gchar *certfile, GError **error)
{
	X509 *res = NULL;
	BIO *cert = NULL;
	unsigned long err;
	const gchar *data;
	int flags;

	g_return_val_if_fail(certfile != NULL, NULL);
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

static X509 *load_cert_pkcs11(const gchar *url, GError **error)
{
	X509 *res = NULL;
	unsigned long err;
	const gchar *data;
	GError *ierror = NULL;
	int flags;
	ENGINE *e;

	/* this is defined in libp11 src/eng_back.c ctx_ctrl_load_cert() */
	struct {
		const char *url;
		X509 *cert;
	} parms;

	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	e = get_pkcs11_engine(&ierror);
	if (e == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	parms.url = url;
	parms.cert = NULL;
	if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &parms, NULL, 0) || (parms.cert == NULL)) {
		err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to load PKCS11 certificate for '%s': %s", url,
				(flags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL));
		goto out;
	}
	res = parms.cert;

out:
	return res;
}

static X509 *load_cert(const gchar *name, GError **error)
{
	g_return_val_if_fail(name != NULL, NULL);

	if (g_str_has_prefix(name, "pkcs11:"))
		return load_cert_pkcs11(name, error);
	else
		return load_cert_file(name, error);
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
	gchar *keyring_path = NULL;

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

	/* keyring was given, perform verification to obtain trust chain */
	if (r_context()->signing_keyringpath) {
		keyring_path = r_context()->signing_keyringpath;
	} else if (r_context()->config->keyring_path) {
		keyring_path = r_context()->config->keyring_path;
	}

	if (keyring_path) {
		g_autoptr(CMS_ContentInfo) vcms = NULL;
		g_autoptr(X509_STORE) store = NULL;
		STACK_OF(X509) *verified_chain = NULL;

		if (!(store = X509_STORE_new())) {
			g_set_error_literal(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_X509_NEW,
					"failed to allocate new X509 store");
			goto out;
		}
		if (!X509_STORE_load_locations(store, keyring_path, NULL)) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_CA_LOAD,
					"failed to load CA file '%s'", keyring_path);
			goto out;
		}

		g_message("Keyring given, doing signature verification");
		if (!cms_verify(content, res, store, &vcms, &ierror)) {
			g_propagate_error(error, ierror);
			res = NULL;
			goto out;
		}

		if (!cms_get_cert_chain(vcms, store, &verified_chain, &ierror)) {
			g_propagate_error(error, ierror);
			res = NULL;
			goto out;
		}

		for (int i = 0; i < sk_X509_num(verified_chain); i++) {
			const ASN1_TIME *expiry_time;
			time_t comp;

			comp = time(NULL) + 30*24*60*60;
			expiry_time = X509_get0_notAfter(sk_X509_value(verified_chain, i));

			/* Check if expiry time is within last month */
			if (X509_cmp_current_time(expiry_time) == 1 && X509_cmp_time(expiry_time, &comp) == -1) {
				char buf[BUFSIZ];
				X509_NAME_oneline(X509_get_subject_name(sk_X509_value(verified_chain, i)),
						buf, sizeof buf);
				g_warning("Certificate %d (%s) will exipre in less than a month!", i + 1, buf);
			}
		}

		sk_X509_pop_free(verified_chain, X509_free);
	} else {
		g_message("No keyring given, skipping signature verification");
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
		g_warning("DER Encoding failed");
		goto out;
	}
	/* As i2d_X509_PUBKEY() moves pointer after end of data,
	 * we must use a tmp pointer, here */
	der_buf = tmp_buf = g_malloc(len);
	i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &tmp_buf);

	g_assert(((unsigned int)(tmp_buf - der_buf)) == len);

	if (!EVP_Digest(der_buf, len, md, &n, EVP_sha256(), NULL)) {
		g_warning("Error in EVP_Digest");
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

static gchar* dump_cms(STACK_OF(X509) *x509_certs)
{
	BIO *mem;
	gchar *data, *ret;
	gsize size;

	g_return_val_if_fail(x509_certs != NULL, NULL);

	mem = BIO_new(BIO_s_mem());
	X509_print_ex(mem, sk_X509_value(x509_certs, 0), 0, 0);

	size = BIO_get_mem_data(mem, &data);
	ret = g_strndup(data, size);

	BIO_set_close(mem, BIO_CLOSE);
	BIO_free(mem);

	return ret;
}

gchar* sigdata_to_string(GBytes *sig, GError **error)
{
	CMS_ContentInfo *cms = NULL;
	STACK_OF(X509) *signers = NULL;
	gchar *ret;
	BIO *insig = BIO_new_mem_buf((void *)g_bytes_get_data(sig, NULL),
			g_bytes_get_size(sig));

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		return NULL;
	}

	signers = CMS_get1_certs(cms);
	if (signers == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_GET_SIGNER,
				"Failed to obtain signer info");
		return NULL;
	}

	ret = dump_cms(signers);

	sk_X509_free(signers);

	return ret;
}

static gchar* get_cert_time(const ASN1_TIME *time)
{
	BIO *mem;
	gchar *data, *ret;
	gsize size;

	mem = BIO_new(BIO_s_mem());
	ASN1_TIME_print(mem, time);

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
		g_string_append_printf(text, "   Not Before: %s\n", get_cert_time(X509_get0_notBefore((const X509*) sk_X509_value(verified_chain, i))));
		g_string_append_printf(text, "   Not After:  %s\n", get_cert_time(X509_get0_notAfter((const X509*) sk_X509_value(verified_chain, i))));
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

	if (X509_verify_cert(cert_ctx) != 1) {
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

	g_debug("Got %d elements for trust chain", sk_X509_num(*verified_chain));

	res = TRUE;
out:
	if (cert_ctx)
		X509_STORE_CTX_free(cert_ctx);
	if (signers)
		sk_X509_free(signers);

	return res;
}

/* while OpenSSL 1.1.x provides a function for converting ASN1_TIME to tm,
 * OpenSSL 1.0.x does not.
 * Instead of coding an own conversion routine which might introduce bugs
 * unnecessarily, we use the existing conversion capabilities of
 * ASN1_TIME_print() and strptime() by taking the string representation as
 * intermediate format. */
static gboolean asn1_time_to_tm(const ASN1_TIME *intime, struct tm *tm)
{
	BIO *mem;
	long size;
	gchar *data;
	g_autofree gchar *ret;

	mem = BIO_new(BIO_s_mem());

	ASN1_TIME_print(mem, intime);

	size = BIO_get_mem_data(mem, &data);
	ret = g_strndup(data, size);

	g_debug("Obtained signing time: %s", ret);

	if (!strptime(ret, "%b %d %H:%M:%S %Y GMT", tm))
		return FALSE;

	BIO_set_close(mem, BIO_CLOSE);
	BIO_free(mem);

	return TRUE;
}

gboolean cms_verify(GBytes *content, GBytes *sig, X509_STORE *store, CMS_ContentInfo **cms, GError **error)
{
	CMS_ContentInfo *icms = NULL;
	BIO *incontent = BIO_new_mem_buf((void *)g_bytes_get_data(content, NULL),
			g_bytes_get_size(content));
	BIO *insig = BIO_new_mem_buf((void *)g_bytes_get_data(sig, NULL),
			g_bytes_get_size(sig));
	gboolean res = FALSE;

	g_return_val_if_fail(content != NULL, FALSE);
	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("cms_verify", "Verifying signature", 0);

	if (!(icms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		goto out;
	}

	/* Optionally use certificate signing timestamp for verification */
	if (r_context()->config->use_bundle_signing_time) {
		STACK_OF(CMS_SignerInfo) *sinfos;
		CMS_SignerInfo *si;
		X509_ATTRIBUTE *xa;
		ASN1_TYPE *so;
		X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
		struct tm tm;
		time_t signingtime;

		/* Extract signing time from pkcs9 attributes */
		sinfos = CMS_get0_SignerInfos(icms);
		si = sk_CMS_SignerInfo_value(sinfos, 0);
		xa = CMS_signed_get_attr(si, CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1));
		so = X509_ATTRIBUTE_get0_type(xa, 0);

		/* convert to time_t to make it usable for seting verify parameter */
		if (!asn1_time_to_tm(so->value.utctime, &tm)) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_UNKNOWN,
					"Failed to convert bundle signing time");
			goto out;
		}
		signingtime = timegm(&tm);

		/* use signing time for verification */
		X509_VERIFY_PARAM_set_time(param, signingtime);
		X509_STORE_set1_param(store, param);
		X509_VERIFY_PARAM_free(param);
	}

	if (!CMS_verify(icms, NULL, store, incontent, NULL, CMS_DETACHED | CMS_BINARY)) {
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

	res = TRUE;
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(insig);
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

gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit, X509_STORE *store, CMS_ContentInfo **cms, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GMappedFile) file = NULL;
	g_autoptr(GBytes) content = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
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

	res = cms_verify(content, sig, store, cms, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

