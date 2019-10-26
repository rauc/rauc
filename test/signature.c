#include <stdio.h>
#include <locale.h>
#include <glib.h>

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

static void signature_sign(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gchar *certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	gchar *keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");

	// Test valid signing
	fixture->sig = cms_sign(fixture->content,
			certpath,
			keypath,
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_null(fixture->error);

	g_bytes_unref(fixture->sig);

	// Test signing fails with invalid key
	fixture->sig = cms_sign(fixture->content,
			certpath,
			"test/random.dat",
			NULL,
			&fixture->error);
	g_assert_null(fixture->sig);
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE_ERROR);

	g_clear_error(&fixture->error);

	// Test signing fails with invalid cert
	fixture->sig = cms_sign(fixture->content,
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
	gchar *certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	gchar *keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");

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

static void signature_verify_valid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	gboolean res;

	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	res = cms_verify(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			&fixture->error);
	g_assert_no_error(fixture->error);
	g_assert_true(res);
	g_assert_nonnull(fixture->cms);
}

static void signature_verify_invalid(SignatureFixture *fixture,
		gconstpointer user_data)
{
	fixture->sig = read_file("test/random.dat", NULL);
	g_assert_nonnull(fixture->sig);

	// Test against invalid signature
	g_assert_false(cms_verify(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_PARSE);
	g_assert_null(fixture->cms);
}

static void signature_verify_file(SignatureFixture *fixture,
		gconstpointer user_data)
{
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	// Test valid manifest
	g_assert_true(cms_verify_file("test/openssl-ca/manifest",
			fixture->sig,
			0,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_null(fixture->error);
	g_assert_nonnull(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);

	// Test valid manifest with invalid size limit
	g_assert_false(cms_verify_file("test/openssl-ca/manifest",
			fixture->sig,
			42,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_error(&fixture->error);

	// Test non-existing file
	g_assert_false(cms_verify_file("path/to/nonexisting/file",
			fixture->sig,
			0,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_assert_null(fixture->cms);
}

static void signature_loopback(SignatureFixture *fixture,
		gconstpointer user_data)
{
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			NULL);
	g_assert_nonnull(fixture->sig);
	g_assert_true(cms_verify(fixture->content, fixture->sig, fixture->store, NULL, NULL));
	((char *)g_bytes_get_data(fixture->content, NULL))[0] = 0x00;
	g_assert_false(cms_verify(fixture->content, fixture->sig, fixture->store, NULL, NULL));
}

static void signature_get_cert_chain(SignatureFixture *fixture,
		gconstpointer user_data)
{
	fixture->sig = read_file("test/openssl-ca/manifest-r1.sig", NULL);
	g_assert_nonnull(fixture->sig);

	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(fixture->cms,
			fixture->store,
			&fixture->verified_chain,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_selfsigned(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *root_store = X509_STORE_new();
	g_assert_nonnull(root_store);
	g_assert_true(X509_STORE_load_locations(root_store, "test/openssl-ca/root/ca.cert.pem", NULL));

	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/root/ca.cert.pem",
			"test/openssl-ca/root/private/ca.key.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);

	g_clear_error(&fixture->error);

	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			root_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);

	g_clear_error(&fixture->error);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(fixture->cms,
			root_store,
			&fixture->verified_chain,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length for self-signed must be 1 */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 1);
}

static void signature_intermediate(SignatureFixture *fixture,
		gconstpointer user_data)
{
	GPtrArray *interfiles = NULL;
	X509_STORE *prov_store = X509_STORE_new();
	g_assert_nonnull(prov_store);
	/* We verify against the provisioning CA */
	g_assert_true(X509_STORE_load_locations(prov_store, "test/openssl-ca/provisioning-ca.pem", NULL));

	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);

	/* Without explicit intermediate certificate, this must fail */
	g_assert_false(cms_verify(fixture->content,
			fixture->sig,
			prov_store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_clear_error(&fixture->error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			(gchar**) g_ptr_array_free(interfiles, FALSE),
			NULL);
	g_assert_nonnull(fixture->sig);

	/* With intermediate certificate, this must succeed */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			prov_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(fixture->cms,
			prov_store,
			&fixture->verified_chain,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_intermediate_file(SignatureFixture *fixture,
		gconstpointer user_data)
{
	GPtrArray *interfiles = NULL;
	X509_STORE *prov_store = X509_STORE_new();
	g_assert_nonnull(prov_store);
	g_assert_true(X509_STORE_load_locations(prov_store, "test/openssl-ca/provisioning-ca.pem", NULL));

	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);

	/* Without explicit intermediate certificate, this must fail */
	g_assert_false(cms_verify_file("test/openssl-ca/manifest",
			fixture->sig,
			0,
			prov_store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
	g_assert_null(fixture->cms);

	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_clear_error(&fixture->error);

	/* Include the missing link in the signature */
	interfiles = g_ptr_array_new();
	g_ptr_array_add(interfiles, g_strdup("test/openssl-ca/rel/ca.cert.pem"));
	g_ptr_array_add(interfiles, NULL);

	fixture->sig = cms_sign_file("test/openssl-ca/manifest",
			"test/openssl-ca/rel/release-1.cert.pem",
			"test/openssl-ca/rel/private/release-1.pem",
			(gchar**) g_ptr_array_free(interfiles, FALSE),
			NULL);
	g_assert_nonnull(fixture->sig);

	/* With intermediate certificate, this must succeed */
	g_assert_true(cms_verify_file("test/openssl-ca/manifest",
			fixture->sig,
			0,
			fixture->store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);

	/* Verify obtaining cert chain works */
	g_assert_true(cms_get_cert_chain(fixture->cms,
			fixture->store,
			&fixture->verified_chain,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->verified_chain);

	/* Chain length must be 3 (release-1 -> rel -> root) */
	g_assert_cmpint(sk_X509_num(fixture->verified_chain), ==, 3);
}

static void signature_cmsverify_path(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *a_store = X509_STORE_new();
	g_assert_nonnull(a_store);
	g_assert_true(X509_STORE_load_locations(a_store, "test/openssl-ca/dir/a.cert.pem", NULL));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);

	g_clear_error(&fixture->error);

	/* Verify against "A" cert */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			a_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_dir_combined(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *ab_dir_store = X509_STORE_new();
	g_assert_nonnull(ab_dir_store);
	g_assert_true(X509_STORE_load_locations(ab_dir_store, NULL, "test/openssl-ca/dir/hash/ab"));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in combined directory (A+B) */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			ab_dir_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_dir_single_fail(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *a_store = X509_STORE_new();
	X509_STORE *ab_dir_store = X509_STORE_new();
	g_assert_nonnull(a_store);
	g_assert_nonnull(ab_dir_store);
	g_assert_true(X509_STORE_load_locations(a_store, "test/openssl-ca/dir/a.cert.pem", NULL));
	g_assert_true(X509_STORE_load_locations(ab_dir_store, NULL, "test/openssl-ca/dir/hash/ab"));


	/* Sign with "B" key and cert */
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/dir/b.cert.pem",
			"test/openssl-ca/dir/private/b.key.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in combined directory (A+B) */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			ab_dir_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);

	/* Verify failure against certs stored in "A" only directory */
	g_clear_pointer(&fixture->cms, CMS_ContentInfo_free);
	g_assert_false(cms_verify(fixture->content,
			fixture->sig,
			a_store,
			&fixture->cms,
			&fixture->error));
	g_assert_error(fixture->error, R_SIGNATURE_ERROR, R_SIGNATURE_ERROR_INVALID);
}

static void signature_cmsverify_pathdir_dir(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *a_dir_b_store = X509_STORE_new();
	g_assert_nonnull(a_dir_b_store);
	g_assert_true(X509_STORE_load_locations(a_dir_b_store, "test/openssl-ca/dir/b.cert.pem", "test/openssl-ca/dir/hash/a"));

	/* Sign with "A" key and cert */
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/dir/a.cert.pem",
			"test/openssl-ca/dir/private/a.key.pem",
			NULL,
			&fixture->error);
	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in directory(A) + path(B) */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			a_dir_b_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);
}

static void signature_cmsverify_pathdir_path(SignatureFixture *fixture,
		gconstpointer user_data)
{
	X509_STORE *a_dir_b_store = X509_STORE_new();
	g_assert_nonnull(a_dir_b_store);
	g_assert_true(X509_STORE_load_locations(a_dir_b_store, "test/openssl-ca/dir/b.cert.pem", "test/openssl-ca/dir/hash/a"));

	/* Sign with "B" key and cert */
	fixture->sig = cms_sign(fixture->content,
			"test/openssl-ca/dir/b.cert.pem",
			"test/openssl-ca/dir/private/b.key.pem",
			NULL,
			&fixture->error);

	g_assert_nonnull(fixture->sig);
	g_assert_no_error(fixture->error);
	g_clear_error(&fixture->error);

	/* Verify against certs stored in directory(A) + path(B) */
	g_assert_true(cms_verify(fixture->content,
			fixture->sig,
			a_dir_b_store,
			&fixture->cms,
			&fixture->error));
	g_assert_no_error(fixture->error);
	g_assert_nonnull(fixture->cms);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");
	r_context_conf();

	g_assert(test_prepare_dummy_file("test/", "random.dat",
			256 * 1024, "/dev/urandom") == 0);

	g_assert(test_prepare_dummy_file("test/", "empty.dat",
			0, "/dev/zero") == 0);

	g_test_init(&argc, &argv, NULL);

	g_test_add("/signature/sign", SignatureFixture, NULL, signature_set_up, signature_sign, signature_tear_down);
	g_test_add("/signature/sign_file", SignatureFixture, NULL, signature_set_up, signature_sign_file, signature_tear_down);
	g_test_add("/signature/verify_valid", SignatureFixture, NULL, signature_set_up, signature_verify_valid, signature_tear_down);
	g_test_add("/signature/verify_invalid", SignatureFixture, NULL, signature_set_up, signature_verify_invalid, signature_tear_down);
	g_test_add("/signature/verify_file", SignatureFixture, NULL, signature_set_up, signature_verify_file, signature_tear_down);
	g_test_add("/signature/loopback", SignatureFixture, NULL, signature_set_up, signature_loopback, signature_tear_down);
	g_test_add("/signature/get_cert_chain", SignatureFixture, NULL, signature_set_up, signature_get_cert_chain, signature_tear_down);
	g_test_add("/signature/selfsigned", SignatureFixture, NULL, signature_set_up, signature_selfsigned, signature_tear_down);
	g_test_add("/signature/intermediate", SignatureFixture, NULL, signature_set_up, signature_intermediate, signature_tear_down);
	g_test_add("/signature/intermediate_file", SignatureFixture, NULL, signature_set_up, signature_intermediate_file, signature_tear_down);
	g_test_add("/signature/cmsverify_path", SignatureFixture, NULL, signature_set_up, signature_cmsverify_path, signature_tear_down);
	g_test_add("/signature/cmsverify_dir_combined", SignatureFixture, NULL, signature_set_up, signature_cmsverify_dir_combined, signature_tear_down);
	g_test_add("/signature/cmsverify_dir_single_fail", SignatureFixture, NULL, signature_set_up, signature_cmsverify_dir_single_fail, signature_tear_down);
	g_test_add("/signature/cmsverify_pathdir_dir", SignatureFixture, NULL, signature_set_up, signature_cmsverify_pathdir_dir, signature_tear_down);
	g_test_add("/signature/cmsverify_pathdir_path", SignatureFixture, NULL, signature_set_up, signature_cmsverify_pathdir_path, signature_tear_down);

	return g_test_run();
}

