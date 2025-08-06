#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <openssl/x509.h>

#include <context.h>
#include <utils.h>
#include "signature.h"
#include "common.h"

typedef struct {
	GBytes *content;
	GBytes *sig;
	GError *error;
	CMS_ContentInfo *cms;
	X509_STORE *store;
	STACK_OF(X509) *verified_chain;
} SignatureFixture;

static void signature_set_up(SignatureFixture *fixture,
		gconstpointer user_data)
{
	r_context_conf();

	fixture->content = read_file("test/openssl-ca/manifest", NULL);
	g_assert_nonnull(fixture->content);
	fixture->sig = NULL;
	fixture->error = NULL;
	fixture->cms = NULL;

	fixture->store = X509_STORE_new();
	g_assert_nonnull(fixture->store);
	g_assert_true(X509_STORE_load_locations(fixture->store, "test/openssl-ca/dev-ca.pem", NULL));

	fixture->verified_chain = NULL;
}

static void signature_tear_down(SignatureFixture *fixture,
		gconstpointer user_data)
{
	g_bytes_unref(fixture->content);
	g_bytes_unref(fixture->sig);
	g_clear_error(&fixture->error);
	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_clear_pointer(&fixture->store, X509_STORE_free);

	if (fixture->verified_chain)
		sk_X509_pop_free(fixture->verified_chain, X509_free);

	r_context_clean();
}

static void signature_sign_detached(SignatureFixture *fixture,
		gconstpointer user_data)
{
	const gchar *certpath = "test/openssl-ca/rel/release-1.cert.pem";
	const gchar *keypath = "test/openssl-ca/rel/private/release-1.pem";
	gboolean detached = FALSE;

	// Test valid signing
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			certpath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_null(fixture->error);

	g_assert_true(cms_is_detached(fixture->sig, &detached, &fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_true(detached);

	g_bytes_unref(fixture->sig);

	// Test signing fails with invalid key
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			certpath,
			"test/random.dat",
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_clear_error(&fixture->error);

	// Test signing fails with invalid cert
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/random.dat",
			keypath,
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);
}

static void signature_sign_inline(SignatureFixture *fixture,
		gconstpointer user_data)
{
	const gchar *certpath = "test/openssl-ca/rel/release-1.cert.pem";
	const gchar *keypath = "test/openssl-ca/rel/private/release-1.pem";
	gboolean detached = TRUE;

	// Test valid signing
	fixture->sig = cms_sign(fixture->content,
			FALSE,
			certpath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_null(fixture->error);

	g_assert_true(cms_is_detached(fixture->sig, &detached, &fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_false(detached);

	g_bytes_unref(fixture->sig);

	// Test signing fails with invalid key
	fixture->sig = cms_sign(fixture->content,
			FALSE,
			certpath,
			"test/random.dat",
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_clear_error(&fixture->error);

	// Test signing fails with invalid cert
	fixture->sig = cms_sign(fixture->content,
			FALSE,
			"test/random.dat",
			keypath,
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);
}

static void signature_sign_file(SignatureFixture *fixture,
		gconstpointer user_data)
{
	const gchar *certpath = "test/openssl-ca/rel/release-1.cert.pem";
	const gchar *keypath = "test/openssl-ca/rel/private/release-1.pem";

	// Test valid file
	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			certpath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_null(fixture->error);

	g_bytes_unref(fixture->sig);
	g_clear_error(&fixture->error);

	// Test non-existing file
	fixture->sig = cms_sign_file("path/to/nonexisting/file",
			certpath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, G_FILE_ERROR, G_FILE_ERROR_NOENT);

	g_bytes_unref(fixture->sig);
	g_clear_error(&fixture->error);

	// Test invalid certificate (use key instead)
	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			keypath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);
}

static void signature_verify_common_names_valid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);
	r_context()->config->keyring_allowed_signer_cns = g_strsplit("Test Org Release-1;Test Org NonExisting", ";", 0);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);

	g_clear_pointer(&r_context()->config->keyring_allowed_signer_cns, g_strfreev);
}

static void signature_verify_common_names_invalid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);
	r_context()->config->keyring_allowed_signer_cns = g_strsplit("Test This one does not exist;This one also doesn't", ";", 0);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_SIGNER_CN_FORBIDDEN);
	g_assert_false(res);

	g_clear_pointer(&r_context()->config->keyring_allowed_signer_cns, g_strfreev);
}

static void signature_verify_common_names_2nd_value(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	r_context()->config->keyring_allowed_signer_cns = g_strsplit("Test This one does not exist;Test Org Release-1", ";", 0);
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);

	g_clear_pointer(&r_context()->config->keyring_allowed_signer_cns, g_strfreev);
}

static void signature_verify_valid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean detached = FALSE;
	gboolean res;

	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	g_assert_true(cms_is_detached(fixture->sig, &detached, &fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_true(detached);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_verify_invalid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean detached = TRUE;

	fixture->sig = read_file("test/random.dat", NULL);
	g_assert_nonnull(fixture->sig);

	// Test against invalid signature
	g_assert_false(cms_is_detached(fixture->sig, &detached, &fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_true(detached); /* should not be touched in the error case */

	g_clear_error(&fixture->error);

	g_assert_false(cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_null(fixture->cms);
}

static void signature_verify_file(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gint fd;
	gboolean res;
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	// Test valid manifest
	fd = g_open("test/openssl-ca/manifest", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >=, 0);
	res = cms_verify_fd(fd,
			fixture->sig,
			0,
			fixture->store,
			&fixture->cms,
			&fixture->error);
	g_close(fd, NULL);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);

	// Test valid manifest with invalid size limit
	fd = g_open("test/openssl-ca/manifest", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >=, 0);
	res = cms_verify_fd(fd,
			fixture->sig,
			42,
			fixture->store,
			&fixture->cms,
			&fixture->error);
	g_close(fd, NULL);
	g_assert_false(res);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_error(&fixture->error);
}

static void signature_loopback_detached(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;

	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			NULL,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);

	((char *)g_bytes_get_data(fixture->content, NULL))[0] = 0x00;
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			NULL,
			NULL,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_false(res);
}

static void signature_loopback_inline(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	GBytes *manifest = NULL;

	fixture->sig = cms_sign(fixture->content,
			FALSE,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	res = cms_verify_bytes(NULL,
			fixture->sig,
			fixture->store,
			NULL,
			&manifest,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(manifest);
	g_assert_true(g_bytes_equal(fixture->content, manifest));

	g_clear_pointer(&manifest, g_bytes_unref);

	((char *)g_bytes_get_data(fixture->sig, NULL))[0x10] = 0x00;
	res = cms_verify_bytes(NULL,
			fixture->sig,
			fixture->store,
			NULL,
			&manifest,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_false(res);
	g_assert_null(manifest);
}

static void signature_get_cert_chain(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	res = cms_get_cert_chain(fixture->cms,
			fixture->store,
			&fixture->verified_chain,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_selfsigned(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) root_store = X509_STORE_new();
	g_assert_nonnull(root_store);
	g_assert_true(X509_STORE_load_locations(root_store, "test/openssl-ca/root/ca.cert.pem", NULL));

	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/root/ca.cert.pem",
			"test/openssl-ca/root/private/ca.key.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	g_clear_error(&fixture->error);

	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			root_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	g_clear_error(&fixture->error);

	/* Verify obtaining cert chain works */
	res = cms_get_cert_chain(fixture->cms,
			root_store,
			&fixture->verified_chain,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length for self-signed must be 1 */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 1);
}

static void signature_intermediate(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(GPtrArray) interfiles = NULL;
	g_autoptr(X509_STORE) prov_store = X509_STORE_new();
	g_assert_nonnull(prov_store);
	/* We verify against the provisioning CA */
	g_assert_true(X509_STORE_load_locations(prov_store, "test/openssl-ca/provisioning-ca.pem", NULL));

	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	/* Without explicit intermediate certificate, this must fail */
	g_assert_false(cms_verify_bytes(fixture->content,
			fixture->sig,
			prov_store,
			&fixture->cms,
			NULL,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_clear_pointer(&fixture->sig, g_bytes_unref);
	g_clear_error(&fixture->error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_set_free_func(interfiles, g_free);
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			(gchar**) interfiles->pdata,
			NULL);
	g_assert_nonnull(fixture->sig);

	/* With intermediate certificate, this must succeed */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			prov_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	res = cms_get_cert_chain(fixture->cms,
			prov_store,
			&fixture->verified_chain,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_intermediate_file(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gint fd;
	gboolean res;
	g_autoptr(GPtrArray) interfiles = NULL;
	g_autoptr(X509_STORE) prov_store = X509_STORE_new();
	g_assert_nonnull(prov_store);
	g_assert_true(X509_STORE_load_locations(prov_store, "test/openssl-ca/provisioning-ca.pem", NULL));

	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	/* Without explicit intermediate certificate, this must fail */
	fd = g_open("test/openssl-ca/manifest", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >=, 0);
	res = cms_verify_fd(fd,
			fixture->sig,
			0,
			prov_store,
			&fixture->cms,
			&fixture->error);
	g_close(fd, NULL);
	g_assert_false(res);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_clear_pointer(&fixture->sig, g_bytes_unref);
	g_clear_error(&fixture->error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_set_free_func(interfiles, g_free);
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			(gchar**) interfiles->pdata,
			NULL);
	g_assert_nonnull(fixture->sig);

	/* With intermediate certificate, this must succeed */
	fd = g_open("test/openssl-ca/manifest", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >=, 0);
	res = cms_verify_fd(fd,
			fixture->sig,
			0,
			fixture->store,
			&fixture->cms,
			&fixture->error);
	g_close(fd, NULL);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	res = cms_get_cert_chain(fixture->cms,
			fixture->store,
			&fixture->verified_chain,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_partial(SignatureFixture *fixture, gconstpointer user_data)
{
	gboolean res;

	g_autoptr(X509_STORE) dev_partial_store = setup_x509_store("test/openssl-ca/dev-partial-ca.pem", NULL, NULL);
	g_autoptr(X509_STORE) rel_partial_store = setup_x509_store("test/openssl-ca/rel-partial-ca.pem", NULL, NULL);
	/* Allow a partial chain. */
	r_context()->config->keyring_allow_partial_chain = TRUE;
	g_autoptr(X509_STORE) rel_partial_allowed_store = setup_x509_store("test/openssl-ca/rel-partial-ca.pem", NULL, NULL);
	r_context()->config->keyring_allow_partial_chain = FALSE;

	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	/* With only the dev ca in the store, this must fail. */
	g_assert_false(cms_verify_bytes(fixture->content,
			fixture->sig,
			dev_partial_store,
			&fixture->cms,
			NULL,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);
	g_clear_error(&fixture->error);

	/* Without allowing a partial chain, this must fail. */
	g_assert_false(cms_verify_bytes(fixture->content,
			fixture->sig,
			rel_partial_store,
			&fixture->cms,
			NULL,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);
	g_clear_error(&fixture->error);

	/* With allowing a partial chain, this must succeed. */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			rel_partial_allowed_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	res = cms_get_cert_chain(fixture->cms,
			rel_partial_allowed_store,
			&fixture->verified_chain,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 2 (release-1 -> rel) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 2);
}

static void signature_cmsverify_path(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) a_store = X509_STORE_new();
	g_assert_nonnull(a_store);
	g_assert_true(X509_STORE_load_locations(a_store, "test/openssl-ca/dir/a.cert.pem", NULL));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);

	g_clear_error(&fixture->error);

	/* Verify against "A" cert */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			a_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_dir_combined(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) ab_dir_store = X509_STORE_new();
	g_assert_nonnull(ab_dir_store);
	g_assert_true(X509_STORE_load_locations(ab_dir_store, NULL, "test/openssl-ca/dir/hash/ab"));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in combined directory (A+B) */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			ab_dir_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_dir_single_fail(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) a_store = X509_STORE_new();
	g_autoptr(X509_STORE) ab_dir_store = X509_STORE_new();
	g_assert_nonnull(a_store);
	g_assert_nonnull(ab_dir_store);
	g_assert_true(X509_STORE_load_locations(a_store, "test/openssl-ca/dir/a.cert.pem", NULL));
	g_assert_true(X509_STORE_load_locations(ab_dir_store, NULL, "test/openssl-ca/dir/hash/ab"));

	/* Sign with "B" key and cert */
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dir/b.cert.pem",
			"test/openssl-ca/dir/private/b.key.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in combined directory (A+B) */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			ab_dir_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);

	/* Verify failure against certs stored in "A" only directory */
	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_assert_false(cms_verify_bytes(fixture->content,
			fixture->sig,
			a_store,
			&fixture->cms,
			NULL,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
}

static void signature_cmsverify_pathdir_dir(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) a_dir_b_store = X509_STORE_new();
	g_assert_nonnull(a_dir_b_store);
	g_assert_true(X509_STORE_load_locations(a_dir_b_store, "test/openssl-ca/dir/b.cert.pem", "test/openssl-ca/dir/hash/a"));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in directory(A) + path(B) */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			a_dir_b_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_pathdir_path(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;
	g_autoptr(X509_STORE) a_dir_b_store = X509_STORE_new();
	g_assert_nonnull(a_dir_b_store);
	g_assert_true(X509_STORE_load_locations(a_dir_b_store, "test/openssl-ca/dir/b.cert.pem", "test/openssl-ca/dir/hash/a"));

	/* Sign with "B" key and cert */
	fixture->sig = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dir/b.cert.pem",
			"test/openssl-ca/dir/private/b.key.pem",
			NULL,
			&fixture->error);

	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->sig);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in directory(A) + path(B) */
	res = cms_verify_bytes(fixture->content,
			fixture->sig,
			a_dir_b_store,
			&fixture->cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_append_detached(SignatureFixture *fixture, gconstpointer user_data)
{
	gboolean res;

	g_autoptr(GBytes) sig1 = cms_sign(fixture->content,
			TRUE,
			"test/openssl-ca/dev/autobuilder-1.cert.pem",
			"test/openssl-ca/dev/private/autobuilder-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig1);

	g_autoptr(GBytes) sig2 = cms_append_signature(sig1,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig2);

	/* dev-ca allows release CA -> OK */
	g_autoptr(CMS_ContentInfo) cms = NULL;
	res = cms_verify_bytes(fixture->content,
			sig2,
			fixture->store,
			&cms,
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);

	STACK_OF(CMS_SignerInfo) *sinfos = CMS_get0_SignerInfos(cms);
	g_assert_cmpint(sk_CMS_SignerInfo_num(sinfos), ==, 2);

	/* modified CMS must fail verification */
	((char *)g_bytes_get_data(sig2, NULL))[0x10] = 0x00;
	res = cms_verify_bytes(fixture->content,
			sig2,
			fixture->store,
			NULL,
			NULL,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_false(res);
}

static void signature_append_inline(SignatureFixture *fixture, gconstpointer user_data)
{
	gboolean res;
	GBytes *manifest = NULL;

	g_autoptr(GBytes) sig1 = cms_sign(fixture->content,
			FALSE,
			"test/openssl-ca/dev/autobuilder-1.cert.pem",
			"test/openssl-ca/dev/private/autobuilder-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig1);

	g_autoptr(GBytes) sig2 = cms_append_signature(sig1,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig2);

	/* dev-ca allows release CA -> OK */
	g_autoptr(CMS_ContentInfo) cms = NULL;
	res = cms_verify_bytes(NULL,
			sig2,
			fixture->store,
			&cms,
			&manifest,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(manifest);
	g_assert_true(g_bytes_equal(fixture->content, manifest));

	STACK_OF(CMS_SignerInfo) *sinfos = CMS_get0_SignerInfos(cms);
	g_assert_cmpint(sk_CMS_SignerInfo_num(sinfos), ==, 2);

	g_clear_pointer(&manifest, g_bytes_unref);

	/* modified CMS must fail verification */
	((char *)g_bytes_get_data(sig2, NULL))[0x10] = 0x00;
	res = cms_verify_bytes(NULL,
			sig2,
			fixture->store,
			NULL,
			&manifest,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_false(res);
	g_assert_null(manifest);
}

/* assert that the cert has the expected common name */
static G_GNUC_UNUSED void assert_X509_subject_cn(const X509 *cert, const gchar *expected)
{
	g_assert_nonnull(cert);

	X509_NAME *name = X509_get_subject_name(cert);
	g_assert_nonnull(name);

	int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	g_assert_cmpint(index, >=, 0);

	const X509_NAME_ENTRY *cn = X509_NAME_get_entry(name, index);
	g_assert_nonnull(cn);

	const unsigned char* cn_value = ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(cn));
	g_assert_nonnull(cn_value);

	/* the should be no more common names */
	index = X509_NAME_get_index_by_NID(name, NID_commonName, index);
	g_assert_cmpint(index, ==, -1);

	g_assert_cmpstr(expected, ==, (gchar*)cn_value);
}

static void signature_append_partial(SignatureFixture *fixture, gconstpointer user_data)
{
	gboolean res;
	GBytes *manifest_null = NULL;

	/* we want to allow dev and rel CAs separately, so allow partial chains */
	r_context()->config->keyring_allow_partial_chain = TRUE;
	g_autoptr(X509_STORE) dev_partial_allowed_store = setup_x509_store("test/openssl-ca/dev-partial-ca.pem", NULL, NULL);
	g_autoptr(X509_STORE) rel_partial_allowed_store = setup_x509_store("test/openssl-ca/rel-partial-ca.pem", NULL, NULL);
	r_context()->config->keyring_allow_partial_chain = FALSE;

	g_autoptr(GBytes) sig1 = cms_sign(fixture->content,
			FALSE,
			"test/openssl-ca/dev/autobuilder-1.cert.pem",
			"test/openssl-ca/dev/private/autobuilder-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig1);

	g_autoptr(GBytes) sig2 = cms_append_signature(sig1,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_nonnull(sig2);

	/* full dev CA -> both autobuilder and release sigs are OK */
	g_autoptr(CMS_ContentInfo) cms1 = NULL;
	g_autoptr(GBytes) manifest1 = NULL;
	res = cms_verify_bytes(NULL,
			sig2,
			fixture->store,
			&cms1,
			&manifest1,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);

	STACK_OF(CMS_SignerInfo) *sinfos1 = CMS_get0_SignerInfos(cms1);
	g_assert_cmpint(sk_CMS_SignerInfo_num(sinfos1), ==, 2);

	/* partial dev CA -> release is not valid, overall verification fails */
	res = cms_verify_bytes(NULL,
			sig2,
			dev_partial_allowed_store,
			NULL,
			&manifest_null,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_false(res);
	g_assert_null(manifest_null);
	g_clear_error(&fixture->error);

	/* partial release CA -> autobuilder is not valid, overall verification fails */
	res = cms_verify_bytes(NULL,
			sig2,
			rel_partial_allowed_store,
			NULL,
			&manifest_null,
			&fixture->error);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_false(res);
	g_assert_null(manifest_null);
	g_clear_error(&fixture->error);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_assert(test_prepare_dummy_file("test/", "random.dat",
			256 * 1024, "/dev/urandom") == 0);

	g_assert(test_prepare_dummy_file("test/", "empty.dat",
			0, "/dev/zero") == 0);

	g_test_init(&argc, &argv, NULL);

	g_test_add("/signature/sign_detached", SignatureFixture, NULL, signature_set_up, signature_sign_detached, signature_tear_down);
	g_test_add("/signature/sign_inline", SignatureFixture, NULL, signature_set_up, signature_sign_inline, signature_tear_down);
	g_test_add("/signature/sign_file", SignatureFixture, NULL, signature_set_up, signature_sign_file, signature_tear_down);
	g_test_add("/signature/verify_valid", SignatureFixture, NULL, signature_set_up, signature_verify_valid, signature_tear_down);
	g_test_add("/signature/verify_invalid", SignatureFixture, NULL, signature_set_up, signature_verify_invalid, signature_tear_down);
	g_test_add("/signature/verify_file", SignatureFixture, NULL, signature_set_up, signature_verify_file, signature_tear_down);
	g_test_add("/signature/loopback_detached", SignatureFixture, NULL, signature_set_up, signature_loopback_detached, signature_tear_down);
	g_test_add("/signature/loopback_inline", SignatureFixture, NULL, signature_set_up, signature_loopback_inline, signature_tear_down);
	g_test_add("/signature/get_cert_chain", SignatureFixture, NULL, signature_set_up, signature_get_cert_chain, signature_tear_down);
	g_test_add("/signature/selfsigned", SignatureFixture, NULL, signature_set_up, signature_selfsigned, signature_tear_down);
	g_test_add("/signature/intermediate", SignatureFixture, NULL, signature_set_up, signature_intermediate, signature_tear_down);
	g_test_add("/signature/common_names_valid", SignatureFixture, NULL, signature_set_up, signature_verify_common_names_valid, signature_tear_down);
	g_test_add("/signature/common_names_invalid", SignatureFixture, NULL, signature_set_up, signature_verify_common_names_invalid, signature_tear_down);
	g_test_add("/signature/common_names_2nd_value", SignatureFixture, NULL, signature_set_up, signature_verify_common_names_2nd_value, signature_tear_down);
	g_test_add("/signature/intermediate_file", SignatureFixture, NULL, signature_set_up, signature_intermediate_file, signature_tear_down);
	g_test_add("/signature/partial", SignatureFixture, NULL, signature_set_up, signature_partial, signature_tear_down);
	g_test_add("/signature/cmsverify_path", SignatureFixture, NULL, signature_set_up, signature_cmsverify_path, signature_tear_down);
	g_test_add("/signature/cmsverify_dir_combined", SignatureFixture, NULL, signature_set_up, signature_cmsverify_dir_combined, signature_tear_down);
	g_test_add("/signature/cmsverify_dir_single_fail", SignatureFixture, NULL, signature_set_up, signature_cmsverify_dir_single_fail, signature_tear_down);
	g_test_add("/signature/cmsverify_pathdir_dir", SignatureFixture, NULL, signature_set_up, signature_cmsverify_pathdir_dir, signature_tear_down);
	g_test_add("/signature/cmsverify_pathdir_path", SignatureFixture, NULL, signature_set_up, signature_cmsverify_pathdir_path, signature_tear_down);
	g_test_add("/signature/append_detached", SignatureFixture, NULL, signature_set_up, signature_append_detached, signature_tear_down);
	g_test_add("/signature/append_inline", SignatureFixture, NULL, signature_set_up, signature_append_inline, signature_tear_down);
	g_test_add("/signature/append_partial", SignatureFixture, NULL, signature_set_up, signature_append_partial, signature_tear_down);

	return g_test_run();
}
