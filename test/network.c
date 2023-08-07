#include <locale.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>
#include <utils.h>
#include "network.h"

typedef struct {
	gchar *tmpdir;
} NetworkFixture;

static void network_fixture_set_up(NetworkFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("network tmpdir: %s\n", fixture->tmpdir);
}

static void network_fixture_tear_down(NetworkFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void test_download_file(NetworkFixture *fixture,
		gconstpointer user_data)
{
	g_autofree const gchar *target = NULL;
	GError *ierror = NULL;
	gboolean res;

	target = g_build_filename(fixture->tmpdir, "target", NULL);

	/* basic download (no size limit) */
	res = download_file(target, "https://rauc.io/", 0, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_cmpint(g_unlink(target), ==, 0);

	/* download with large limit */
	res = download_file(target, "https://rauc.io/", 1048576, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_cmpint(g_unlink(target), ==, 0);

	/* abort download for too large files */
	res = download_file(target, "https://rauc.io/", 1024, &ierror);
	g_assert_error(ierror, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_assert_false(res);
	g_clear_error(&ierror);
	g_assert_cmpint(g_unlink(target), ==, 0);

	/* invalid host name */
	res = download_file(target, "https://error.rauc.io/", 1024, &ierror);
	g_assert_error(ierror, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_assert_false(res);
	g_clear_error(&ierror);
	g_assert_cmpint(g_unlink(target), ==, 0);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/network/download_file", NetworkFixture, NULL,
			network_fixture_set_up, test_download_file,
			network_fixture_tear_down);

	return g_test_run();
}
