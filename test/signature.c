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
		       &error);
	g_assert_nonnull(sig);
	g_assert_null(error);

	g_bytes_unref(sig);

	// Test signing fail with invalid key
	sig = cms_sign(content,
		       r_context()->certpath,
		       "test/random.dat",
		       &error);
	g_assert_null(sig);
	g_assert_nonnull(error);

	g_clear_error(&error);

	// Test signing fail with invalid cert
	sig = cms_sign(content,
		       "test/random.dat",
		       r_context()->keypath,
		       &error);
	g_assert_null(sig);
	g_assert_nonnull(error);

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
			    &error);
	g_assert_nonnull(sig);
	g_assert_null(error);

	g_bytes_unref(sig);
	g_clear_error(&error);


	// Test non-existing file
	sig = cms_sign_file("path/to/nonexisting/file",
			    r_context()->certpath,
			    r_context()->keypath,
			    &error);
	g_assert_null(sig);
	g_assert_nonnull(error);

	g_bytes_unref(sig);
	g_clear_error(&error);

	// Test invalid certificate
	sig = cms_sign_file("test/openssl-ca/manifest",
			    NULL,
			    r_context()->keypath,
			    &error);
	g_assert_null(sig);
	g_assert_nonnull(error);

	g_bytes_unref(sig);
	g_clear_error(&error);
}

static void signature_verify(void)
{
	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(content);
	g_assert_nonnull(sig);
	g_assert_true(cms_verify(content, sig, NULL, NULL, NULL));
	g_bytes_unref(content);
	g_bytes_unref(sig);
}

static void signature_verify_file(void)
{
	GError *error = NULL;
	GBytes *sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	GBytes *isig = read_file("test/random.dat", NULL);

	g_assert_nonnull(sig);
	g_assert_nonnull(isig);

	// Test valid manifest
	g_assert_true(cms_verify_file("test/openssl-ca/manifest", sig, 0, NULL, NULL, &error));
	g_assert_null(error);

	// Test non-existing file
	g_assert_false(cms_verify_file("path/to/nonexisting/file", sig, 0, NULL, NULL, &error));
	g_assert_nonnull(error);

	g_clear_error(&error);

	// Test valid manifest against invalid signature
	g_assert_false(cms_verify_file("test/openssl-ca/manifest", isig, 0, NULL, NULL, &error));
	g_assert_nonnull(error);

	g_clear_error(&error);

	g_bytes_unref(sig);
	g_bytes_unref(isig);
}

static void signature_loopback(void)
{
	GBytes *content = read_file("test/openssl-ca/manifest", NULL);
	GBytes *sig = NULL;
	g_assert_nonnull(content);
	sig = cms_sign(content,
		       r_context()->certpath,
		       r_context()->keypath,
		       NULL);
	g_assert_nonnull(sig);
	g_assert_true(cms_verify(content, sig, NULL, NULL, NULL));
	((char *)g_bytes_get_data(content, NULL))[0] = 0x00;
	g_assert_false(cms_verify(content, sig, NULL, NULL, NULL));
	g_bytes_unref(content);
	g_bytes_unref(sig);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->configpath = g_strdup("test/test.conf");
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

	return g_test_run();
}
