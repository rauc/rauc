#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <context.h>
#include <utils.h>
#include "signature.h"
#include "common.h"

static void signature_sign(void)
{
	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = NULL;
	GError *error = NULL;
	g_assert_nonnull(content);

	// Test valid signing
	sig = cms_sign(content,
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_nonnull(sig);
	g_assert_null(error);

	g_bytes_unref(sig);

	// Test signing fail with invalid key
	sig = cms_sign(content,
			r_context()->certpath,
			"test/random.dat",
			NULL,
			&error);
	g_assert_null(sig);
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_clear_error(&error);

	// Test signing fail with invalid cert
	sig = cms_sign(content,
			"test/random.dat",
			r_context()->keypath,
			NULL,
			&error);
	g_assert_null(sig);
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_clear_error(&error);

	g_bytes_unref(content);
}

static void signature_sign_file(void)
{
	GBytes *sig = NULL;
	GError *error = NULL;

	// Test valid file
	sig = cms_sign_file("test/openssl-ca/manifest",
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_nonnull(sig);
	g_assert_null(error);

	g_bytes_unref(sig);
	g_clear_error(&error);


	// Test non-existing file
	sig = cms_sign_file("path/to/nonexisting/file",
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_null(sig);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);

	g_bytes_unref(sig);
	g_clear_error(&error);

	// Test invalid certificate (use key instead)
	sig = cms_sign_file("test/openssl-ca/manifest",
			r_context()->keypath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_null(sig);
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_bytes_unref(sig);
	g_clear_error(&error);
}

static void signature_verify(void)
{
	GError *error = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;

	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	GBytes *isig = read_file("test/random.dat", NULL);
	g_assert_nonnull(content);
	g_assert_nonnull(sig);
	g_assert_nonnull(isig);

	g_assert_true(cms_verify(content, sig, &cms, &store, &error));
	g_assert_no_error(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);

	// Test against invalid signature
	g_assert_false(cms_verify(content, isig, &cms, &store, &error));
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_null(cms);
	g_assert_null(store);

	g_bytes_unref(content);
	g_bytes_unref(sig);
	g_bytes_unref(isig);
}

static void signature_verify_file(void)
{
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	GError *error = NULL;

	GBytes *sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);

	g_assert_nonnull(sig);

	// Test valid manifest
	g_assert_true(cms_verify_file("test/openssl-ca/manifest", sig, 0, &cms, &store, &error));
	g_assert_null(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);

	// Test valid manifest with invalid size limit
	g_assert_false(cms_verify_file("test/openssl-ca/manifest", sig, 42, &cms, &store, &error));
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(cms);
	g_assert_null(store);

	g_clear_error(&error);

	// Test non-existing file
	g_assert_false(cms_verify_file("path/to/nonexisting/file", sig, 0, &cms, &store, &error));
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_assert_null(cms);
	g_assert_null(store);

	g_clear_error(&error);

	g_bytes_unref(sig);
}

static void signature_loopback(void)
{
	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = NULL;
	g_assert_nonnull(content);
	sig = cms_sign(content,
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			NULL);
	g_assert_nonnull(sig);
	g_assert_true(cms_verify(content, sig, NULL, NULL, NULL));
	((char *)g_bytes_get_data(content, NULL))[0] = 0x00;
	g_assert_false(cms_verify(content, sig, NULL, NULL, NULL));
	g_bytes_unref(content);
	g_bytes_unref(sig);
}

static void signature_get_cert_chain(void)
{
	GError *error = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	STACK_OF(X509) *verified_chain = NULL;

	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(content);
	g_assert_nonnull(sig);

	/* We verify against the dev-ca keychain */
	r_context_conf()->keyringpath = g_strdup("test/openssl-ca/dev-ca.pem");

	g_assert_true(cms_verify(content, sig, &cms, &store, &error));
	g_assert_no_error(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(cms, store, &verified_chain, &error));
	g_assert_no_error(error);
	g_assert_nonnull(verified_chain);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_error(&error);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(verified_chain), ==, 3);

	sk_X509_pop_free(verified_chain, X509_free);
}

static void signature_selfsigned(void)
{
	GBytes *sig = NULL;
	GError *error = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	STACK_OF(X509) *verified_chain = NULL;

	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	g_assert_nonnull(content);

	/* We sign with root CA key and cert */
	r_context_conf()->certpath = g_strdup("test/openssl-ca/root/ca.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/root/private/ca.key.pem");
	/* We also verify against the root CA */
	r_context_conf()->keyringpath = g_strdup("test/openssl-ca/root/ca.cert.pem");

	sig = cms_sign(content,
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_nonnull(sig);
	g_assert_no_error(error);

	g_clear_error(&error);

	g_assert_true(cms_verify(content, sig, &cms, &store, &error));
	g_assert_no_error(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	g_clear_error(&error);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(cms, store, &verified_chain, &error));
	g_assert_no_error(error);
	g_assert_nonnull(verified_chain);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_error(&error);

	/* Chain length for self-signed must be 1 */
	g_assert_cmpint(sk_X509_num(verified_chain), ==, 1);

	sk_X509_pop_free(verified_chain, X509_free);
}

static void signature_intermediate(void)
{
	GBytes *sig = NULL;
	GError *error = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	STACK_OF(X509) *verified_chain = NULL;
	GPtrArray *interfiles = NULL;

	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	g_assert_nonnull(content);

	/* We sign with the release key */
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context_conf()->keyringpath = NULL;

	sig = cms_sign(content,
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_nonnull(sig);
	g_assert_no_error(error);

	/* We verify against the provisioning CA */
	r_context_conf()->keyringpath = g_strdup("test/openssl-ca/provisioning-ca.pem");
	/* Without explicit intermediate certificate, this must fail */
	g_assert_false(cms_verify(content, sig, &cms, &store, &error));
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(cms);
	g_assert_null(store);

	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_pointer(&store, X509_STORE_free);
	g_clear_error(&error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	sig = cms_sign(content,
			r_context()->certpath,
			r_context()->keypath,
			(gchar**) g_ptr_array_free(interfiles, FALSE),
			NULL);
	g_assert_nonnull(sig);

	/* With intermediate certificate, this must succeed */
	g_assert_true(cms_verify(content, sig, &cms, &store, &error));
	g_assert_no_error(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(cms, store, &verified_chain, &error));
	g_assert_no_error(error);
	g_assert_nonnull(verified_chain);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_error(&error);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(verified_chain), ==, 3);

	sk_X509_pop_free(verified_chain, X509_free);
}

static void signature_intermediate_file(void)
{
	GBytes *sig = NULL;
	GError *error = NULL;
	CMS_ContentInfo *cms = NULL;
	X509_STORE *store = NULL;
	STACK_OF(X509) *verified_chain = NULL;
	GPtrArray *interfiles = NULL;

	/* We sign with the release key */
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context_conf()->keyringpath = NULL;

	sig = cms_sign_file("test/openssl-ca/manifest",
			r_context()->certpath,
			r_context()->keypath,
			NULL,
			&error);
	g_assert_nonnull(sig);
	g_assert_no_error(error);

	/* We verify against the provisioning CA */
	r_context_conf()->keyringpath = g_strdup("test/openssl-ca/provisioning-ca.pem");
	/* Without explicit intermediate certificate, this must fail */
	g_assert_false(cms_verify_file("test/openssl-ca/manifest", sig, 0, &cms, &store, &error));
	g_assert_error(error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(cms);
	g_assert_null(store);

	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_pointer(&store, X509_STORE_free);
	g_clear_error(&error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	sig = cms_sign_file("test/openssl-ca/manifest",
			r_context()->certpath,
			r_context()->keypath,
			(gchar**) g_ptr_array_free(interfiles, FALSE),
			NULL);
	g_assert_nonnull(sig);

	/* With intermediate certificate, this must succeed */
	g_assert_true(cms_verify_file("test/openssl-ca/manifest", sig, 0, &cms, &store, &error));
	g_assert_no_error(error);
	g_assert_nonnull(cms);
	g_assert_nonnull(store);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(cms, store, &verified_chain, &error));
	g_assert_no_error(error);
	g_assert_nonnull(verified_chain);

	g_clear_pointer(&store, X509_STORE_free);
	g_clear_pointer(&cms, CMS_ContentInfo_free);
	g_clear_error(&error);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(verified_chain), ==, 3);

	sk_X509_pop_free(verified_chain, X509_free);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->keyringpath = g_strdup("test/openssl-ca/dev-ca.pem");
	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context();

	g_assert(test_prepare_dummy_file("test/", "random.dat",
			256 * 1024, "/dev/urandom") == 0);

	g_assert(test_prepare_dummy_file("test/", "empty.dat",
			0, "/dev/zero") == 0);

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/signature/sign", signature_sign);
	g_test_add_func("/signature/sign_file", signature_sign_file);
	g_test_add_func("/signature/verify", signature_verify);
	g_test_add_func("/signature/verify_file", signature_verify_file);
	g_test_add_func("/signature/loopback", signature_loopback);
	g_test_add_func("/signature/get_cert_chain", signature_get_cert_chain);
	g_test_add_func("/signature/selfsigned", signature_selfsigned);
	g_test_add_func("/signature/intermediate", signature_intermediate);
	g_test_add_func("/signature/intermediate_file", signature_intermediate_file);

	return g_test_run();
}

