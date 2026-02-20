#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <manifest.h>
#include <signature.h>
#include <utils.h>
#include <nbd.h>

#include "common.h"

typedef struct {
	gchar *tmpdir;
} NBDFixture;

typedef struct {
	const gchar *bundle_url;
	RaucBundleAccessArgs access_args;

	gboolean needs_backend;

	GQuark err_domain;
	gint err_code;
} NBDData;

static gboolean have_http_server(void)
{
	if (!g_getenv("RAUC_TEST_HTTP_SERVER")) {
		g_test_message("no HTTP server for testing found (define RAUC_TEST_HTTP_SERVER)");
		g_test_skip("RAUC_TEST_HTTP_SERVER undefined");
		return FALSE;
	}

	return TRUE;
}

static void nbd_fixture_set_up(NBDFixture *fixture, gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_test_message("tmpdir: %s\n", fixture->tmpdir);
}

static void nbd_fixture_tear_down(NBDFixture *fixture, gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);

	g_test_assert_expected_messages();
}

static void test_direct_read(NBDFixture *fixture, gconstpointer user_data)
{
	NBDData *data = (NBDData *)user_data;
	g_autoptr(RaucNBDServer) nbd_srv = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;
	guint32 magic = 0;

	if (!have_http_server())
		return;

	nbd_srv = r_nbd_new_server();
	nbd_srv->url = g_strdup(data->bundle_url);
	nbd_srv->tls_cert = g_strdup(data->access_args.tls_cert);
	nbd_srv->tls_key = g_strdup(data->access_args.tls_key);
	nbd_srv->tls_ca = g_strdup(data->access_args.tls_ca);
	nbd_srv->tls_no_verify = data->access_args.tls_no_verify;
	nbd_srv->headers = g_strdupv(data->access_args.http_headers);

	res = r_nbd_start_server(nbd_srv, &ierror);
	if (!data->err_domain) {
		g_assert_no_error(ierror);
		g_assert_true(res);
	} else {
		g_assert_error(ierror, data->err_domain, data->err_code);
		g_assert_false(res);
		return;
	}

	res = r_nbd_read(nbd_srv->sock, (guint8 *)&magic, sizeof(magic), 0, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_cmphex(magic, ==, GUINT32_TO_LE(0x73717368));
}

static void test_check_invalid_bundle(NBDFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	res = check_bundle("http://127.0.0.1/test/invalid-sig-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT);
	g_assert_false(res);
	g_assert_null(bundle);
}

static void test_check_not_found(NBDFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	res = check_bundle("http://127.0.0.1/test/missing-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_NBD_ERROR, R_NBD_ERROR_NOT_FOUND);
	g_assert_false(res);
	g_assert_null(bundle);
}

static void test_plain_bundle(NBDFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	res = check_bundle("http://127.0.0.1/test/good-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_FORMAT);
	g_assert_false(res);
	g_assert_null(bundle);
}

static void test_verity_bundle(NBDFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	res = check_bundle("http://127.0.0.1/test/good-verity-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
}

static void test_extract(NBDFixture *fixture, gconstpointer user_data)
{
	g_autofree gchar *outputdir = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	outputdir = g_build_filename(fixture->tmpdir, "output", NULL);
	g_assert_nonnull(outputdir);

	res = check_bundle("http://127.0.0.1/test/good-verity-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);

	res = extract_bundle(bundle, outputdir, &ierror);
	g_assert_error(ierror, R_BUNDLE_ERROR, R_BUNDLE_ERROR_UNSAFE);
	g_assert_false(res);
}

static void test_cache_etag(NBDFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	if (!have_http_server())
		return;

	res = check_bundle("http://127.0.0.1/test/good-verity-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(bundle);
	g_assert_nonnull(bundle->nbd_srv->etag);
	g_autofree gchar *etag = g_strdup(bundle->nbd_srv->etag);
	g_clear_pointer(&bundle, free_bundle);

	g_auto(RaucBundleAccessArgs) access_args = {0};
	access_args.http_info_headers = g_ptr_array_new_with_free_func(g_free);
	g_ptr_array_add(access_args.http_info_headers, g_strdup_printf("If-None-Match: %s", etag));
	res = check_bundle("http://127.0.0.1/test/good-verity-bundle.raucb", &bundle, CHECK_BUNDLE_DEFAULT, &access_args, &ierror);
	g_assert_error(ierror, R_NBD_ERROR, R_NBD_ERROR_NOT_MODIFIED);
	g_assert_false(res);
	g_assert_null(bundle);
}

static void test_nbd_mount(NBDFixture *fixture, gconstpointer user_data)
{
	NBDData *data = (NBDData *)user_data;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;

	/* mount needs to run as root */
	if (!test_running_as_root())
		return;

	if (!have_http_server())
		return;

	if (data->needs_backend) {
		if (!g_getenv("RAUC_TEST_HTTP_BACKEND")) {
			g_test_message("no aiohttp backend for testing found (define RAUC_TEST_HTTP_BACKEND)");
			g_test_skip("RAUC_TEST_HTTP_BACKEND undefined");
			return;
		}
	}

	res = check_bundle(data->bundle_url, &bundle, CHECK_BUNDLE_DEFAULT, &data->access_args, &ierror);
	if (!data->err_domain) {
		g_assert_no_error(ierror);
		g_assert_true(res);
		g_assert_nonnull(bundle);
	} else {
		g_assert_error(ierror, data->err_domain, data->err_code);
		g_assert_false(res);
		g_assert_null(bundle);
		return;
	}

	res = mount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	res = umount_bundle(bundle, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
}

int main(int argc, char *argv[])
{
	g_autoptr(GPtrArray) ptrs = g_ptr_array_new_with_free_func(g_free);
	const char *http_headers[2] = {NULL, NULL};
	NBDData *nbd_data;
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();

	g_test_init(&argc, &argv, NULL);

	/* low level connect and read */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/test/good-verity-bundle.raucb",
	}));
	g_test_add("/nbd/direct_read/good",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);

	/* 204 handling */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/code/204",
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_NO_CONTENT,
	}));
	g_test_add("/nbd/direct_read/204",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);

	/* 304 handling */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/code/304",
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_NOT_MODIFIED,
	}));
	g_test_add("/nbd/direct_read/304",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);

	/* 404 handling */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/error/404",
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_NOT_FOUND,
	}));
	g_test_add("/nbd/direct_read/404",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);

	/* basic auth */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/basic/test/good-verity-bundle.raucb",
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_UNAUTHORIZED,
	}));
	g_test_add("/nbd/basic-auth/fail",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://rauc:rauctest@127.0.0.1/basic/test/good-verity-bundle.raucb",
	}));
	g_test_add("/nbd/basic-auth/good-1",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);
	http_headers[0] = "Authorization: Basic cmF1YzpyYXVjdGVzdA==";
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/basic/test/good-verity-bundle.raucb",
		.access_args = {
			.http_headers = dup_test_data(ptrs, http_headers),
		},
	}));
	g_test_add("/nbd/basic-auth/good-2",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_direct_read,
			nbd_fixture_tear_down);

	/* basic bundle handling */
	g_test_add("/nbd/check_invalid_bundle",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_check_invalid_bundle,
			nbd_fixture_tear_down);

	g_test_add("/nbd/check_not_found",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_check_not_found,
			nbd_fixture_tear_down);

	g_test_add("/nbd/plain_bundle",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_plain_bundle,
			nbd_fixture_tear_down);

	g_test_add("/nbd/verity_bundle",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_verity_bundle,
			nbd_fixture_tear_down);

	g_test_add("/nbd/check_extract",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_extract,
			nbd_fixture_tear_down);

	/* bundle caching */
	g_test_add("/nbd/cache/etag",
			NBDFixture, NULL,
			nbd_fixture_set_up, test_cache_etag,
			nbd_fixture_tear_down);

	/* mount via HTTP */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/test/good-verity-bundle.raucb",
	}));
	g_test_add("/nbd/mount/http",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* mount via HTTPS */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.1/test/good-verity-bundle.raucb",
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_CONFIGURATION, /* missing CA cert */
	}));
	g_test_add("/nbd/mount/https-bad-ca",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.1/test/good-verity-bundle.raucb",
		.access_args = {
			.tls_no_verify = TRUE,
		},
	}));
	g_test_add("/nbd/mount/https-no-verify",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.1/test/good-verity-bundle.raucb",
		.access_args = {
			.tls_ca = dup_test_printf(ptrs, "test/openssl-ca/web-ca.pem"),
		},
	}));
	g_test_add("/nbd/mount/https",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* mount via HTTPS with HTTP/2 */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.2/test/good-verity-bundle.raucb",
		.access_args = {
			.tls_ca = dup_test_printf(ptrs, "test/openssl-ca/web-ca.pem"),
		},
	}));
	g_test_add("/nbd/mount/http2",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* mount via HTTPS with client certificates checking */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.3/test/good-verity-bundle.raucb",
		.access_args = {
			.tls_cert = dup_test_printf(ptrs, "test/openssl-ca/web/client-1.cert.pem"),
			.tls_key = dup_test_printf(ptrs, "test/openssl-ca/web/private/client-1.pem"),
			.tls_ca = dup_test_printf(ptrs, "test/openssl-ca/web-ca.pem"),
		},
	}));
	g_test_add("/nbd/mount/client-cert/good",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* 404 via HTTPS & client cert */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.3/error/404",
		.access_args = {
			.tls_cert = dup_test_printf(ptrs, "test/openssl-ca/web/client-1.cert.pem"),
			.tls_key = dup_test_printf(ptrs, "test/openssl-ca/web/private/client-1.pem"),
			.tls_ca = dup_test_printf(ptrs, "test/openssl-ca/web-ca.pem"),
		},
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_NOT_FOUND,
	}));
	g_test_add("/nbd/mount/client-cert/404",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* HTTPS with missing client cert */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "https://127.0.0.3/test/good-verity-bundle.raucb",
		.access_args = {
			.tls_ca = dup_test_printf(ptrs, "test/openssl-ca/web-ca.pem"),
		},
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_CONFIGURATION, /* missing client cert */
	}));
	g_test_add("/nbd/mount/client-cert/unauth",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* HTTP with sporadic errors */
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/backend/sporadic.raucb",
		.needs_backend = TRUE,
	}));
	g_test_add("/nbd/mount/http-sporadic-errors",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	/* HTTP with cookie/token auth*/
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/backend/token.raucb",
		.needs_backend = TRUE,
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_UNAUTHORIZED,
	}));
	g_test_add("/nbd/token/missing",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);
	http_headers[0] = "Cookie: token=wrong";
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/backend/token.raucb",
		.access_args = {
			.http_headers = dup_test_data(ptrs, http_headers),
		},
		.needs_backend = TRUE,
		.err_domain = R_NBD_ERROR,
		.err_code = R_NBD_ERROR_UNAUTHORIZED,
	}));
	g_test_add("/nbd/token/wrong",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);
	http_headers[0] = "Cookie: token=secret";
	nbd_data = dup_test_data(ptrs, (&(NBDData) {
		.bundle_url = "http://127.0.0.1/backend/token.raucb",
		.needs_backend = TRUE,
		.access_args = {
			.http_headers = dup_test_data(ptrs, http_headers),
		},
	}));
	g_test_add("/nbd/token/good",
			NBDFixture, nbd_data,
			nbd_fixture_set_up, test_nbd_mount,
			nbd_fixture_tear_down);

	return g_test_run();
}
