#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#if ENABLE_OPENSSL_PKCS11_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/x509.h>
#include <string.h>

#include "context.h"
#include "signature.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE_CTX, X509_STORE_CTX_free);

void r_signature_free_x509_stack(R_X509_STACK *stack)
{
	sk_X509_free(stack);
}

void r_signature_free_x509_stack_pop(R_X509_STACK_POP *stack)
{
	sk_X509_pop_free(stack, X509_free);
}

GQuark r_signature_error_quark(void)
{
	return g_quark_from_static_string("r_signature_error_quark");
}

static const gchar *get_openssl_err_string(void)
{
	unsigned long err;
	const gchar *data = NULL;
	int errflags = 0;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	err = ERR_get_error_line_data(NULL, NULL, &data, &errflags);
#else
	err = ERR_get_error_all(NULL, NULL, NULL, &data, &errflags);
#endif

	return (errflags & ERR_TXT_STRING) ? data : ERR_error_string(err, NULL);
}

/* return 0 for error, 1 for success */
static int check_purpose_code_sign(const X509_PURPOSE *xp, const X509 *const_x, int ca)
{
	/* The external OpenSSL API only takes a non-const X509 pointer, but
	 * the ex_ variables have already been calculated by other code when
	 * we are in this callback. */
	X509 *x = (X509 *)const_x;
	uint32_t ex_flags = X509_get_extension_flags(x);
	uint32_t ex_kusage = X509_get_key_usage(x);
	uint32_t ex_xkusage = X509_get_extended_key_usage(x);

	if (ca) {
		/* If extended key usage is present, it must contain codeSigning for all
		 * certs in the chain. */
		if ((ex_flags & EXFLAG_XKUSAGE) && !(ex_xkusage & XKU_CODE_SIGN)) {
			g_message("CA certificate extended key usage does not allow code signing");
			return 0;
		}

		return X509_check_ca(x);
	}

	/* If key usage is present, it must contain digitalSignature. */
	if ((ex_flags & EXFLAG_KUSAGE) && !(ex_kusage & KU_DIGITAL_SIGNATURE)) {
		g_message("Signer certificate key usage does not allow digital signatures");
		return 0;
	}

	/* Extended key usage codeSigning must be present on the leaf. */
	if (!(ex_flags & EXFLAG_XKUSAGE) || !(ex_xkusage & XKU_CODE_SIGN)) {
		g_message("Signer certificate does not specify extended key usage code signing");
		return 0;
	}

	/* Despite we do not enforce it, CA browser forum notes a MUST on key usage.
	 * (https://cabforum.org/wp-content/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.2.pdf
	 * Section 7.1.2.3f)
	 * For now, do not fail here, but at least emit a warning. */
	if (!(ex_flags & EXFLAG_KUSAGE)) {
		g_warning("Signer certificate should specify 'Key Usage' and mark it 'critical' to be fully CAB Forum compliant.");
	}

	return 1;
}

gboolean signature_init(GError **error)
{
	int ret, id;

	g_return_val_if_fail(error == FALSE || *error == NULL, FALSE);

	ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	if (!ret) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CRYPTOINIT_FAILED,
				"Failed to initialize OpenSSL crypto: %s", get_openssl_err_string());
		return FALSE;
	}

	/* OpenSSL 3.5 warns that there may be gaps, so we need to search.
	 * When we have 3.5 as the minimum version, we can use
	 * X509_PURPOSE_get_unused_id instead. */
	id = X509_PURPOSE_MAX + 1;
	while (X509_PURPOSE_get_by_id(id) != -1) {
		id++;
	}

	/* X509_TRUST_OBJECT_SIGN maps to the Code Signing ID (via OpenSSL's NID_code_sign) */
	ret = X509_PURPOSE_add(id, X509_TRUST_OBJECT_SIGN, 0, check_purpose_code_sign, "Code signing", "codesign-rauc", NULL);
	if (!ret) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CRYPTOINIT_FAILED,
				"Failed to configure OpenSSL X509 purpose: %s", get_openssl_err_string());
		return FALSE;
	}

	return TRUE;
}

#if ENABLE_OPENSSL_PKCS11_ENGINE
static ENGINE *get_pkcs11_engine(GError **error)
{
	static ENGINE *e = NULL;
	const gchar *env;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("pkcs11");
	if (e == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load PKCS11 engine: %s", get_openssl_err_string());

		goto out;
	}

	env = g_getenv("RAUC_PKCS11_MODULE");
	if (env != NULL) {
		if (!ENGINE_ctrl_cmd_string(e, "MODULE_PATH", env, 0)) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_PARSE_ERROR,
					"failed to configure PKCS11 module path: %s", get_openssl_err_string());
			goto free;
		}
	}

	if (ENGINE_init(e) == 0) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to initialize PKCS11 engine: %s", get_openssl_err_string());

		goto free;
	}

	env = g_getenv("RAUC_PKCS11_PIN");
	if (env != NULL && env[0] != '\0') {
		if (!ENGINE_ctrl_cmd_string(e, "PIN", env, 0)) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_PARSE_ERROR,
					"failed to configure PKCS11 PIN: %s", get_openssl_err_string());
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
#endif

static EVP_PKEY *load_key_file(const gchar *keyfile, GError **error)
{
	EVP_PKEY *res = NULL;
	BIO *key = NULL;
	const gchar *passphrase;

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

	passphrase = g_getenv("RAUC_KEY_PASSPHRASE");
	if (passphrase && passphrase[0] == '\0')
		passphrase = NULL;
	res = PEM_read_bio_PrivateKey(key, NULL, NULL, (void *)passphrase);
	if (res == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse key file '%s': %s", keyfile, get_openssl_err_string());
		goto out;
	}
out:
	BIO_free_all(key);
	return res;
}

static EVP_PKEY *load_key_pkcs11(const gchar *url, GError **error)
{
	EVP_PKEY *res = NULL;
#if ENABLE_OPENSSL_PKCS11_ENGINE
	GError *ierror = NULL;
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
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"failed to load PKCS11 private key for '%s': %s", url, get_openssl_err_string());
		goto out;
	}
#else
	g_set_error(
			error,
			R_SIGNATURE_ERROR,
			R_SIGNATURE_ERROR_LOAD_FAILED,
			"failed to load PKCS11 private key for '%s': OpenSSL engine support disabled", url);
#endif

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
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to parse cert file '%s': %s", certfile, get_openssl_err_string());
		goto out;
	}

out:
	BIO_free_all(cert);
	return res;
}

static STACK_OF(X509) *load_certs_from_file(const gchar *certfile, GError **error)
{
	BIO *cert_bio = NULL;
	X509 *cert_x509 = NULL;
	g_autoptr(R_X509_STACK_POP) certs = NULL;
	unsigned long err;

	g_return_val_if_fail(certfile != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	cert_bio = BIO_new_file(certfile, "r");
	if (cert_bio == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_LOAD_FAILED,
				"Failed to load cert file '%s'", certfile);
		goto out;
	}

	certs = sk_X509_new_null();

	for (;;) {
		cert_x509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		if (cert_x509 == NULL) {
			err = ERR_peek_last_error();

			if (ERR_GET_REASON(err) == PEM_R_NO_START_LINE &&
			    sk_X509_num(certs) != 0) {
				/* simply reached end of file */
				ERR_clear_error();
				break;
			}

			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_PARSE_ERROR,
					"Failed to parse cert file '%s': %s", certfile, get_openssl_err_string());
			/* other certs loaded so far are not required anymore and must be freed */
			g_clear_pointer(&certs, r_signature_free_x509_stack_pop);
			goto out;
		}

		sk_X509_push(certs, cert_x509);
	}

out:
	BIO_free_all(cert_bio);
	return g_steal_pointer(&certs);
}

static X509 *load_cert_pkcs11(const gchar *url, GError **error)
{
	X509 *res = NULL;
#if ENABLE_OPENSSL_PKCS11_ENGINE
	GError *ierror = NULL;
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
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE_ERROR,
				"failed to load PKCS11 certificate for '%s': %s", url, get_openssl_err_string());
		goto out;
	}
	res = parms.cert;
#else
	g_set_error(
			error,
			R_SIGNATURE_ERROR,
			R_SIGNATURE_ERROR_PARSE_ERROR,
			"failed to load PKCS11 certificate for '%s': OpenSSL engine support disabled", url);
#endif

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

/* this does not take ownership of the memory, so the GBytes needs to be kept alive */
static BIO *bytes_as_bio(GBytes *bytes)
{
	gsize size = 0;
	const void *data = NULL;
	BIO *bio = NULL;

	g_return_val_if_fail(bytes != NULL, NULL);

	data = g_bytes_get_data(bytes, &size);
	if (!data)
		g_error("bytes_as_bio: no data");
	if (size == 0)
		g_error("bytes_as_bio: size is zero");

	bio = BIO_new_mem_buf(data, size);
	if (!bio)
		g_error("bytes_as_bio: BIO_new_mem_buf() failed");

	return bio;
}

static gboolean file_contains_crl(const gchar *capath)
{
	g_autofree gchar *contents = NULL;

	if (!g_file_test(capath, G_FILE_TEST_IS_REGULAR))
		return FALSE;

	if (!g_file_get_contents(capath, &contents, NULL, NULL))
		return FALSE;

	if (strstr(contents, "-----BEGIN X509 CRL-----"))
		return TRUE;

	return FALSE;
}

static gboolean contains_crl(const gchar *load_capath, const gchar *load_cadir)
{
	if (load_capath && file_contains_crl(load_capath))
		return TRUE;

	if (load_cadir) {
		g_autoptr(GDir) dir;
		const gchar *filename;

		dir = g_dir_open(load_cadir, 0, NULL);
		if (!dir)
			return FALSE;

		while ((filename = g_dir_read_name(dir))) {
			g_autofree gchar *certpath = g_build_filename(load_cadir, filename, NULL);

			if (file_contains_crl(certpath))
				return TRUE;
		}
	}

	return FALSE;
}

X509_STORE* setup_x509_store(const gchar *capath, const gchar *cadir, GError **error)
{
	const gchar *load_capath = r_context()->config->keyring_path;
	const gchar *load_cadir = r_context()->config->keyring_directory;
	const gchar *check_purpose = r_context()->config->keyring_check_purpose;
	g_autoptr(X509_STORE) store = NULL;

	if (capath)
		load_capath = strlen(capath) ? capath : NULL;
	if (cadir)
		load_cadir = strlen(cadir) ? cadir : NULL;

	if (!(store = X509_STORE_new())) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_NEW,
				"failed to allocate new X509 store");
		return NULL;
	}
	if (!X509_STORE_load_locations(store, load_capath, load_cadir)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CA_LOAD,
				"failed to load CA file '%s' and/or directory '%s'", load_capath, load_cadir);
		return NULL;
	}

	/* Enable CRL checking if configured */
	if (r_context()->config->keyring_check_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_EXTENDED_CRL_SUPPORT);
	else if (contains_crl(load_capath, load_cadir))
		g_warning("Detected CRL but CRL checking is disabled!");

	/* Allow partial chain if configured */
	if (r_context()->config->keyring_allow_partial_chain)
		X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);

	/* Enable purpose checking if configured */
	if (check_purpose) {
		const X509_PURPOSE *xp = X509_PURPOSE_get0(X509_PURPOSE_get_by_sname(check_purpose));
		if (!xp || !X509_STORE_set_purpose(store, X509_PURPOSE_get_id(xp))) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_X509_PURPOSE,
					"failed to configure X509 purpose '%s'", check_purpose);
			return NULL;
		}
	}

	return g_steal_pointer(&store);
}

GBytes *cms_sign(GBytes *content, gboolean detached, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
{
	GError *ierror = NULL;
	BIO *incontent = bytes_as_bio(content);
	BIO *outsig = BIO_new(BIO_s_mem());
	g_autoptr(X509) signcert = NULL;
	g_autoptr(EVP_PKEY) pkey = NULL;
	g_autoptr(R_X509_STACK_POP) intercerts = NULL;
	g_autoptr(CMS_ContentInfo) cms = NULL;
	GBytes *res = NULL;
	int flags = CMS_BINARY | CMS_NOSMIMECAP;
	const gchar *keyring_path = NULL, *keyring_dir = NULL;

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

	if (detached)
		flags |= CMS_DETACHED;

	cms = CMS_sign(signcert, pkey, intercerts, incontent, flags);
	if (cms == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CREATE_SIG,
				"failed to create signature: %s", get_openssl_err_string());
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
		keyring_dir = "";
	} else {
		keyring_path = r_context()->config->keyring_path;
		keyring_dir = r_context()->config->keyring_directory;
	}

	if (keyring_path || keyring_dir) {
		g_autoptr(CMS_ContentInfo) vcms = NULL;
		g_autoptr(X509_STORE) store = NULL;
		g_autoptr(R_X509_STACK_POP) verified_chain = NULL;
		g_autoptr(GBytes) manifest = NULL;

		if (!(store = setup_x509_store(keyring_path, keyring_dir, &ierror))) {
			g_propagate_error(error, ierror);
			g_clear_pointer(&res, g_bytes_unref);
			goto out;
		}

		g_message("Keyring given, doing signature verification");
		if (detached) {
			if (!cms_verify_bytes(content, res, store, &vcms, NULL, &ierror)) {
				g_propagate_error(error, ierror);
				g_clear_pointer(&res, g_bytes_unref);
				goto out;
			}
		} else {
			if (!cms_verify_bytes(NULL, res, store, &vcms, &manifest, &ierror)) {
				g_propagate_error(error, ierror);
				g_clear_pointer(&res, g_bytes_unref);
				goto out;
			}
		}
		if (!cms_get_cert_chain(vcms, store, &verified_chain, &ierror)) {
			g_propagate_error(error, ierror);
			g_clear_pointer(&res, g_bytes_unref);
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
				g_warning("Certificate %d (%s) will expire in less than a month!", i + 1, buf);
			}
		}
	} else {
		g_message("No keyring given, skipping signature verification");
	}
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(outsig);
	return res;
}

static void debug_cms_ci(CMS_ContentInfo *cms);

GBytes *cms_append_signature(GBytes *input_sig, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(CMS_ContentInfo) cms = NULL;
	BIO *insig = bytes_as_bio(input_sig);
	BIO *outsig = BIO_new(BIO_s_mem());
	g_autoptr(X509) signcert = NULL;
	g_autoptr(EVP_PKEY) pkey = NULL;
	GBytes *output_sig = NULL;
	int flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_REUSE_DIGEST;

	g_return_val_if_fail(input_sig != NULL, NULL);
	g_return_val_if_fail(certfile != NULL, NULL);
	g_return_val_if_fail(keyfile != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		goto out;
	}

	debug_cms_ci(cms);

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

	for (gchar **intercertpath = interfiles; intercertpath && *intercertpath != NULL; intercertpath++) {
		X509 *intercert = load_cert(*intercertpath, &ierror);
		if (intercert == NULL) {
			g_propagate_error(error, ierror);
			goto out;
		}

		if (!CMS_add0_cert(cms, intercert)) {
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_CREATE_SIG,
					"failed to add intermediate certificate: %s", get_openssl_err_string());
			goto out;
		}
	}

	if (!CMS_add1_signer(cms, signcert, pkey, NULL, flags)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_CREATE_SIG,
				"failed to create signature: %s", get_openssl_err_string());
		goto out;
	}

	debug_cms_ci(cms);

	if (!i2d_CMS_bio(outsig, cms)) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_SERIALIZE_SIG,
				"failed to serialize signature");
		goto out;
	}

	output_sig = bytes_from_bio(outsig);

	if (!output_sig) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_UNKNOWN,
				"Read zero bytes");
		goto out;
	}

out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(insig);
	BIO_free_all(outsig);
	return output_sig;
}

gchar* get_pubkey_hash(X509 *cert)
{
	g_autoptr(GString) string = NULL;
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
		return NULL;
	}
	/* As i2d_X509_PUBKEY() moves pointer after end of data,
	 * we must use a tmp pointer, here */
	der_buf = tmp_buf = g_malloc(len);
	i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &tmp_buf);

	g_assert(((unsigned int)(tmp_buf - der_buf)) == len);

	if (!EVP_Digest(der_buf, len, md, &n, EVP_sha256(), NULL)) {
		g_warning("Error in EVP_Digest");
		return NULL;
	}

	g_assert_cmpint(n, ==, SHA256_DIGEST_LENGTH);

	for (int j = 0; j < (int)n; j++) {
		g_string_append_printf(string, "%02X:", md[j]);
	}
	g_string_truncate(string, SHA256_DIGEST_LENGTH * 3 - 1);

	return g_string_free(g_steal_pointer(&string), FALSE);
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

/*
 * Reads text out of BIO.
 *
 * @param input BIO, will be freed
 *
 * @return newly allocated string or NULL
 */
static gchar* bio_mem_unwrap(BIO *mem)
{
	long size;
	gchar *data, *ret;

	g_return_val_if_fail(mem != NULL, NULL);

	size = BIO_get_mem_data(mem, &data);
	ret = g_strndup(data, size);
	BIO_free(mem);

	return ret;
}

static gchar* dump_cms(STACK_OF(X509) *x509_certs)
{
	BIO *mem;

	g_return_val_if_fail(x509_certs != NULL, NULL);

	mem = BIO_new(BIO_s_mem());
	X509_print_ex(mem, sk_X509_value(x509_certs, 0), 0, 0);

	return bio_mem_unwrap(mem);
}

gchar* sigdata_to_string(GBytes *sig, GError **error)
{
	g_autoptr(CMS_ContentInfo) cms = NULL;
	g_autoptr(R_X509_STACK_POP) signers = NULL;
	gchar *ret;
	BIO *insig = bytes_as_bio(sig);

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

	BIO_free(insig);

	return ret;
}

static void bio_print_recipient(BIO *text, guint id, gchar* algorithm, ASN1_OCTET_STRING *keyid, X509_NAME *issuer, ASN1_INTEGER *sno)
{
	g_autofree gchar *s = NULL;

	/* OpenSSL documentation says
	 * "Either the keyidentifier will be set in keyid or both
	 * issuer name and serial number in issuer and sno."
	 */
	if (keyid) {
		/* dummy printout first of all */
		BIO_printf(text, "%3d   <keyid>", id);
		return;
	}

	if (!issuer || !sno) {
		BIO_printf(text, "%3d   <unknown>", id);
		return;
	}

	BIO_printf(text, "%3d   Issuer:    ", id);
	X509_NAME_print_ex(text, issuer, 0, XN_FLAG_ONELINE);
	BIO_puts(text, "\n");
	BIO_puts(text, "      Serial:    ");
	s = i2s_ASN1_INTEGER(NULL, sno);
	BIO_puts(text, s);
	BIO_puts(text, "\n");
	if (algorithm)
		BIO_printf(text, "      Algorithm: %s\n", algorithm);
}

gchar* envelopeddata_to_string(GBytes *sig, GError **error)
{
	g_autoptr(CMS_ContentInfo) cms = NULL;
	BIO *insig = NULL;
	STACK_OF(CMS_RecipientInfo) *ris;
	BIO *text;
	gchar *ret;

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	insig = bytes_as_bio(sig);

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		BIO_free(insig);
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"Failed to parse signature");
		return NULL;
	}
	ris = CMS_get0_RecipientInfos(cms);

	text = BIO_new(BIO_s_mem());
	BIO_printf(text, "%d Recipients:\n", sk_CMS_RecipientInfo_num(ris));

	for (int i = 0; i < sk_CMS_RecipientInfo_num(ris); i++) {
		CMS_RecipientInfo *ri;

		ri = sk_CMS_RecipientInfo_value(ris, i);

		switch (CMS_RecipientInfo_type(ri)) {
			case CMS_RECIPINFO_TRANS: {
				ASN1_OCTET_STRING *keyid = NULL;
				X509_NAME *issuer = NULL;
				ASN1_INTEGER *sno = NULL;
				X509_ALGOR *alg = NULL;
				gchar algo_buf[80];

				if (CMS_RecipientInfo_ktri_get0_signer_id(ri, &keyid, &issuer, &sno) != 1) {
					g_warning("Unable to obtain recipient information for recipient %d", i);
				}

				if (CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg) != 1) {
					g_warning("Unable to obtain algorithm information for recipient %d", i);
				}

				OBJ_obj2txt(algo_buf, sizeof(algo_buf), alg->algorithm, 0);

				bio_print_recipient(text, i, algo_buf, keyid, issuer, sno);
			} break;
			case CMS_RECIPINFO_AGREE: {
				STACK_OF(CMS_RecipientEncryptedKey) *reks = NULL;
				X509_ALGOR *alg = NULL;
				gchar algo_buf[80];

				reks = CMS_RecipientInfo_kari_get0_reks(ri);
				if (!reks) {
					g_warning("Unable to obtain recipient information for recipient %d", i);
				}

				if (CMS_RecipientInfo_kari_get0_alg(ri, &alg, NULL) != 1) {
					g_warning("Unable to obtain algorithm information for recipient %d", i);
				}

				OBJ_obj2txt(algo_buf, sizeof(algo_buf), alg->algorithm, 0);

				for (int j = 0; j < sk_CMS_RecipientEncryptedKey_num(reks); j++) {
					ASN1_OCTET_STRING *keyid = NULL;
					X509_NAME *issuer = NULL;
					ASN1_INTEGER *sno = NULL;

					CMS_RecipientEncryptedKey *rek = sk_CMS_RecipientEncryptedKey_value(reks, j);
					CMS_RecipientEncryptedKey_get0_id(rek, &keyid, NULL, NULL, &issuer, &sno);

					bio_print_recipient(text, i, algo_buf, keyid, issuer, sno);
				}
			} break;
			default:
				g_warning("Unknown recipient information for recipient %d", i);
				break;
		}
	}

	ret = bio_mem_unwrap(text);
	if (!ret) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_GET_SIGNER,
				"Failed to obtain recipient infos: ");
	}

	BIO_free(insig);
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

	g_assert(BIO_set_close(mem, BIO_CLOSE));
	BIO_free(mem);

	return ret;
}

gchar* format_cert_chain(STACK_OF(X509) *verified_chain)
{
	BIO *text = NULL;
	gchar *tmp = NULL;

	g_return_val_if_fail(verified_chain != NULL, NULL);

	text = BIO_new(BIO_s_mem());
	BIO_printf(text, "Certificate Chain:\n");
	for (int i = 0; i < sk_X509_num(verified_chain); i++) {
		BIO_printf(text, "%2d Subject: ", i);
		X509_NAME_print_ex(text, X509_get_subject_name(sk_X509_value(verified_chain, i)), 0, XN_FLAG_ONELINE);
		BIO_printf(text, "\n");

		BIO_printf(text, "   Issuer: ");
		X509_NAME_print_ex(text, X509_get_issuer_name(sk_X509_value(verified_chain, i)), 0, XN_FLAG_ONELINE);
		BIO_printf(text, "\n");

		tmp = get_pubkey_hash(sk_X509_value(verified_chain, i));
		BIO_printf(text, "   SPKI sha256: %s\n", tmp);
		g_free(tmp);

		tmp = get_cert_time(X509_get0_notBefore((const X509*) sk_X509_value(verified_chain, i)));
		BIO_printf(text, "   Not Before: %s\n", tmp);
		g_free(tmp);

		tmp = get_cert_time(X509_get0_notAfter((const X509*) sk_X509_value(verified_chain, i)));
		BIO_printf(text, "   Not After:  %s\n", tmp);
		g_free(tmp);
	}

	return bio_mem_unwrap(text);
}

static int cmp_x509(const X509 * const *a, const X509 * const *b)
{
	return X509_cmp(*a, *b);
}

static STACK_OF(X509) *cms_get_signer_certs(CMS_ContentInfo *cms, GError **error)
{
	g_return_val_if_fail(cms != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autoptr(R_X509_STACK) signers = NULL;
#if !ENABLE_OPENSSL_VERIFY_PARTIAL
	signers = CMS_get0_signers(cms);
	if (signers == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_GET_SIGNER,
				"Failed to obtain signer info");
		return NULL;
	}
#else
	signers = sk_X509_new_null();
	STACK_OF(CMS_SignerInfo) *sinfos = CMS_get0_SignerInfos(cms);
	for (int i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
		CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sinfos, i);

		/* We only want to consider signatures that passed OpenSSL's
		 * verification. */
		if (!CMS_SignerInfo_get_verification_result(si, CMS_VERIFY_RESULT))
			continue;

		X509 *si_signer = CMS_SignerInfo_get0_signer_cert(si);
		if (si_signer == NULL) {
			g_set_error_literal(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_GET_SIGNER,
					"Failed to obtain signer certificate from signer info");
			return NULL;
		}

		if (!sk_X509_push(signers, si_signer))
			g_error("cms_get_signer_cert: sk_X509_push failed");
	}
#endif

	/* provide a stable order of signers */
	sk_X509_set_cmp_func(signers, cmp_x509);
	sk_X509_sort(signers);

	return g_steal_pointer(&signers);
}

static gchar *cms_get_signers_string(CMS_ContentInfo *cms, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(cms != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autoptr(R_X509_STACK) signers = cms_get_signer_certs(cms, &ierror);
	if (signers == NULL) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	BIO *text = BIO_new(BIO_s_mem());
	BIO_printf(text, "'");
	for (int i = 0; i < sk_X509_num(signers); i++) {
		if (i)
			BIO_printf(text, "', '");
		X509_NAME_print_ex(text, X509_get_subject_name(sk_X509_value(signers, i)), 0, XN_FLAG_ONELINE);
	}
	BIO_printf(text, "'");

	return bio_mem_unwrap(text);
}

static gboolean cms_check_signer_cns(CMS_ContentInfo *cms, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(cms != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const GStrv allowed_cns = r_context()->config->keyring_allowed_signer_cns;

	// config option not used, so the cert is valid for all devices and we can skip everything
	if (!allowed_cns) {
		return TRUE;
	}

	g_autoptr(R_X509_STACK) signers = cms_get_signer_certs(cms, &ierror);
	if (signers == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	for (int i = 0; i < sk_X509_num(signers); i++) {
		X509_NAME *current_signer = X509_get_subject_name(sk_X509_value(signers, i));
		int index = X509_NAME_get_index_by_NID(current_signer, NID_commonName, -1);
		// no matching CN entry in the current signer found, so check next signer
		if (index == -1)
			continue;

		const X509_NAME_ENTRY *cn = X509_NAME_get_entry(current_signer, index);
		// as soon as one matching entry is found, device is eligible to use this update
		const unsigned char* cn_value = ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(cn));
		if (g_strv_contains((const gchar *const *)allowed_cns, (gchar*)cn_value)) {
			return TRUE;
		}
	}

	g_set_error_literal(
			error,
			R_SIGNATURE_ERROR,
			R_SIGNATURE_ERROR_SIGNER_CN_FORBIDDEN,
			"No signature CN matching allowed-signer-cns found");
	return FALSE;
}

gboolean cms_get_cert_chain(CMS_ContentInfo *cms, X509_STORE *store, STACK_OF(X509) **verified_chain, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(cms != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(verified_chain == NULL || *verified_chain == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(R_X509_STACK) signers = cms_get_signer_certs(cms, &ierror);
	if (signers == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Allow one or more signers.
	 * If we have multiple signers, build the chain for the first, as there is
	 * currently no way in RAUC to require more than one and so the additional
	 * ones can be ignored.
	 * When we support requiring multiple signers, we'll need to extend this
	 * and the bundle info output to support multiple chains. */
	gint signer_cnt = sk_X509_num(signers);
	if (signer_cnt < 1) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_NUM_SIGNER,
				"Unsupported number of signers: %d", signer_cnt);
		return FALSE;
	}

	g_autoptr(R_X509_STACK_POP) intercerts = CMS_get1_certs(cms);

	g_autoptr(X509_STORE_CTX) cert_ctx = X509_STORE_CTX_new();
	if (cert_ctx == NULL) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_CTX_NEW,
				"Failed to allocate new X509 CTX store");
		return FALSE;
	}

	if (!X509_STORE_CTX_init(cert_ctx, store, sk_X509_value(signers, 0), intercerts)) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_X509_CTX_INIT,
				"Failed to init new X509 CTX store");
		return FALSE;
	}

	if (X509_verify_cert(cert_ctx) != 1) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_VERIFY_CERT,
				"Failed to verify X509 cert: %s",
				X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)));
		return FALSE;
	}

	*verified_chain = X509_STORE_CTX_get1_chain(cert_ctx);

	/* The first element in the chain must be the signer certificate */
	g_assert(X509_cmp(sk_X509_value(signers, 0), sk_X509_value(*verified_chain, 0)) == 0);

	g_debug("Got %d elements for trust chain", sk_X509_num(*verified_chain));

	return TRUE;
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

	g_assert(BIO_set_close(mem, BIO_CLOSE));
	BIO_free(mem);

	return TRUE;
}

static void debug_cms_ci(CMS_ContentInfo *cms)
{
	BIO *out;
	const gchar *domains = g_getenv("G_MESSAGES_DEBUG");
	gchar *out_str = NULL;
	long size;

	if (domains == NULL)
		return;
	if (!g_str_equal(domains, "all") && strstr(domains, G_LOG_DOMAIN "-signature") == NULL)
		return;

	out = BIO_new(BIO_s_mem());
	CMS_ContentInfo_print_ctx(out, cms, 2, NULL);
	if ((size = BIO_get_mem_data(out, &out_str)) > 0) {
		/* replace final newline with nul */
		out_str[size-1] = '\0';
		g_log(G_LOG_DOMAIN "-signature", G_LOG_LEVEL_DEBUG, "\n%s", out_str);
	}
	BIO_free_all(out);
}

gboolean cms_is_detached(GBytes *sig, gboolean *detached, GError **error)
{
	g_autoptr(CMS_ContentInfo) cms = NULL;
	BIO *insig = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(detached != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(g_bytes_get_size(sig) > 0);

	insig = bytes_as_bio(sig);

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"Signature data is no valid CMS");
		goto out;
	}

	*detached = CMS_is_detached(cms);

	res = TRUE;

out:
	BIO_free(insig);
	return res;
}

gboolean cms_is_envelopeddata(GBytes *cms_data)
{
	g_autoptr(CMS_ContentInfo) cms = NULL;
	BIO *insig = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(cms_data != NULL, FALSE);

	insig = bytes_as_bio(cms_data);

	if (!(cms = d2i_CMS_bio(insig, NULL)))
		goto out;

	res = (OBJ_obj2nid(CMS_get0_type(cms)) == NID_pkcs7_enveloped);

out:
	BIO_free(insig);
	return res;
}

gboolean cms_get_unverified_manifest(GBytes *sig, GBytes **manifest, GError **error)
{
	g_autoptr(CMS_ContentInfo) cms = NULL;
	BIO *insig = bytes_as_bio(sig);
	ASN1_OCTET_STRING **content = NULL;
	GBytes *tmp = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(manifest != NULL && *manifest == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!(cms = d2i_CMS_bio(insig, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"failed to parse signature");
		goto out;
	}

	content = CMS_get0_content(cms);
	if (!content) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"unsupported signature content type");
		goto out;
	}
	if (!(*content)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"missing manifest in inline signature");
		goto out;
	}
	if (!(*content)->data || ((*content)->length <= 0)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"invalid manifest length in inline signature");
		goto out;
	}

	tmp = g_bytes_new((*content)->data, (*content)->length);
	if (!tmp) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_UNKNOWN,
				"failed to get manifest from inline signature");
		goto out;
	}
	*manifest = tmp;

	res = TRUE;

out:
	BIO_free(insig);
	return res;
}

gboolean cms_verify_bytes(GBytes *content, GBytes *sig, X509_STORE *store, CMS_ContentInfo **cms, GBytes **manifest, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(CMS_ContentInfo) icms = NULL;
	BIO *incontent = NULL;
	BIO *insig = bytes_as_bio(sig);
	BIO *outcontent = BIO_new(BIO_s_mem());
	g_autofree gchar *signers_string = NULL;
	gboolean res = FALSE;
	gboolean verified = FALSE;
	gboolean detached;
	unsigned int verify_flags = CMS_BINARY;

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(manifest == NULL || *manifest == NULL, FALSE);
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

	debug_cms_ci(icms);

	detached = CMS_is_detached(icms);
	if (detached) {
		if (content == NULL) {
			/* we have a detached signature but no content to verify */
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_INVALID,
					"no content provided for detached signature");
			goto out;
		}
		if (manifest != NULL) {
			/* we have a detached signature but a place for the manifest */
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_INVALID,
					"unexpected manifest output location for detached signature");
			goto out;
		}
		incontent = bytes_as_bio(content);
	} else {
		if (content != NULL) {
			/* we have an inline signature but some content to verify */
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_INVALID,
					"unexpected content provided for inline signature");
			goto out;
		}
		if (manifest == NULL) {
			/* we have an inline signature but no place to store manifest */
			g_set_error(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_INVALID,
					"no manifest output location for inline signature");
			goto out;
		}
	}

	/* Optionally use certificate signing timestamp for verification */
	if (r_context()->config->use_bundle_signing_time) {
		STACK_OF(CMS_SignerInfo) *sinfos;
		CMS_SignerInfo *si;
		X509_ATTRIBUTE *xa;
		ASN1_TYPE *so;
		X509_VERIFY_PARAM *param = X509_STORE_get0_param(store);
		struct tm tm;
		time_t signingtime;

		/* Extract signing time from pkcs9 attributes */
		sinfos = CMS_get0_SignerInfos(icms);
		si = sk_CMS_SignerInfo_value(sinfos, 0);
		xa = CMS_signed_get_attr(si, CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1));
		so = X509_ATTRIBUTE_get0_type(xa, 0);

		/* convert to time_t to make it usable for setting verify parameter */
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
	}

#if ENABLE_OPENSSL_VERIFY_PARTIAL
	if (r_context()->config->keyring_allow_single_signature)
		verify_flags |= CMS_VERIFY_PARTIAL;
#endif

	if (detached)
		verified = CMS_verify(icms, NULL, store, incontent, NULL, verify_flags | CMS_DETACHED);
	else
		verified = CMS_verify(icms, NULL, store, NULL, outcontent, verify_flags);
	if (!verified) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"signature verification failed: %s", get_openssl_err_string());
		goto out;
	}

	if (!cms_check_signer_cns(icms, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	signers_string = cms_get_signers_string(icms, &ierror);
	if (!signers_string) {
		g_propagate_error(error, ierror);
		goto out;
	}
	g_message("Verified %s signature by %s", detached ? "detached" : "inline", signers_string);

	if (!detached) {
		GBytes *tmp = bytes_from_bio(outcontent);
		if (!tmp) {
			g_set_error_literal(
					error,
					R_SIGNATURE_ERROR,
					R_SIGNATURE_ERROR_UNKNOWN,
					"missing manifest in inline signature");
			goto out;
		}
		*manifest = tmp;
	}

	if (cms)
		*cms = g_steal_pointer(&icms);

	res = TRUE;
out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(insig);
	BIO_free_all(outcontent);
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

	sig = cms_sign(content, TRUE, certfile, keyfile, interfiles, &ierror);
	if (sig == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return sig;
}

GBytes *cms_sign_manifest(RaucManifest *manifest, const gchar *certfile, const gchar *keyfile, gchar **interfiles, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GBytes) content = NULL;
	GBytes *sig = NULL;

	g_return_val_if_fail(manifest != NULL, FALSE);
	g_return_val_if_fail(certfile != NULL, FALSE);
	g_return_val_if_fail(keyfile != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!save_manifest_mem(&content, manifest)) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_UNKNOWN,
				"Failed to serialize manifest!");
		goto out;
	}

	sig = cms_sign(content, FALSE, certfile, keyfile, interfiles, &ierror);
	if (sig == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return sig;
}

gboolean cms_verify_fd(gint fd, GBytes *sig, goffset limit, X509_STORE *store, CMS_ContentInfo **cms, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GMappedFile) file = NULL;
	g_autoptr(GBytes) content = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(fd >= 0, FALSE);
	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	file = g_mapped_file_new_from_fd(fd, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	/* On 32 bit systems, G_MAXSIZE will be only 32 bit (unsigned) while
	 * 'limit' is 64 bit (signed). Thus we must take care of not passing
	 * 'limit' values exceeding G_MAXSIZE to g_bytes_new_from_bytes.
	 * However, mmapping for large limit values will cause problems,
	 * anyway.
	 */
	if ((guint64)limit > (guint64)G_MAXSIZE) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"Bundle size exceeds maximum size!");
		goto out;
	}

	if (limit) {
		GBytes *tmp = g_bytes_new_from_bytes(content, 0, limit);
		g_bytes_unref(content);
		content = tmp;
	}

	res = cms_verify_bytes(content, sig, store, cms, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

gboolean cms_verify_sig(GBytes *sig, X509_STORE *store, CMS_ContentInfo **cms, GBytes **manifest, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(sig != NULL, FALSE);
	g_return_val_if_fail(store != NULL, FALSE);
	g_return_val_if_fail(cms == NULL || *cms == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = cms_verify_bytes(NULL, sig, store, cms, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

GBytes *cms_encrypt(GBytes *content, gchar **recipients, GError **error)
{
	GError *ierror = NULL;
	BIO *incontent = NULL;
	BIO *outsig = BIO_new(BIO_s_mem());
	g_autoptr(R_X509_STACK_POP) recipcerts = NULL;
	g_autoptr(CMS_ContentInfo) cms = NULL;
	GBytes *res = NULL;

	g_return_val_if_fail(content, NULL);
	g_return_val_if_fail(recipients, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	incontent = bytes_as_bio(content);

	recipcerts = sk_X509_new_null();

	/* load all recipient certificates from all provided PEM files */
	for (gchar **recipcertpath = recipients; recipcertpath && *recipcertpath != NULL; recipcertpath++) {
		g_autoptr(R_X509_STACK) filecerts = load_certs_from_file(*recipcertpath, &ierror);
		if (filecerts == NULL) {
			g_propagate_error(error, ierror);
			goto out;
		}

		/* add all recipient certs from recent file */
		for (gint i = 0; i < sk_X509_num(filecerts); i++) {
			sk_X509_push(recipcerts, sk_X509_value(filecerts, i));
		}
	}

	cms = CMS_encrypt(recipcerts, incontent, EVP_aes_256_cbc(), CMS_BINARY);
	if (cms == NULL) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"Failed to encrypt: %s", get_openssl_err_string());
		goto out;
	}
	if (!i2d_CMS_bio(outsig, cms)) {
		g_set_error_literal(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_SERIALIZE_SIG,
				"Failed to serialize signature");
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

	g_message("Encrypted for %d recipient%s", sk_X509_num(recipcerts), sk_X509_num(recipcerts) > 1 ? "s" : "");

out:
	ERR_print_errors_fp(stdout);
	BIO_free_all(incontent);
	BIO_free_all(outsig);
	return res;
}

GBytes *cms_decrypt(GBytes *content, const gchar *certfile, const gchar *keyfile, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(CMS_ContentInfo) icms = NULL;
	g_autoptr(X509) decrypt_cert = NULL;
	g_autoptr(EVP_PKEY) privkey = NULL;
	BIO *outdecrypt = BIO_new(BIO_s_mem());
	BIO *inenc = NULL;
	GBytes *res = NULL;

	g_return_val_if_fail(content != NULL, NULL);
	g_return_val_if_fail(keyfile != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	inenc = bytes_as_bio(content);

	if (certfile) {
		decrypt_cert = load_cert(certfile, &ierror);
		if (decrypt_cert == NULL) {
			g_propagate_error(error, ierror);
			res = NULL;
			goto out;
		}
	}

	privkey = load_key(keyfile, &ierror);
	if (privkey == NULL) {
		g_propagate_error(error, ierror);
		res = NULL;
		goto out;
	}

	g_message("Decrypting signature...");

	if (!(icms = d2i_CMS_bio(inenc, NULL))) {
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_PARSE,
				"Failed to parse CMS");
		res = NULL;
		goto out;
	}

	/* assert we received envelopedData */
	if (OBJ_obj2nid(CMS_get0_type(icms)) != NID_pkcs7_enveloped) {
		g_set_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID, "Expected CMS of type '%s' but got '%s'", OBJ_nid2sn(NID_pkcs7_enveloped), OBJ_nid2sn(OBJ_obj2nid(CMS_get0_type(icms))));
		res = NULL;
		goto out;
	}

	if (!CMS_decrypt(icms, privkey, decrypt_cert, NULL, outdecrypt, 0)) {
		res = NULL;
		g_set_error(
				error,
				R_SIGNATURE_ERROR,
				R_SIGNATURE_ERROR_INVALID,
				"Failed to decrypt CMS EnvelopedData: %s", get_openssl_err_string());
		goto out;
	}

	res = bytes_from_bio(outdecrypt);
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
	BIO_free_all(inenc);
	BIO_free_all(outdecrypt);
	return res;
}
