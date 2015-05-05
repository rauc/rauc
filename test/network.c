#include <locale.h>
#include <glib.h>

#include <context.h>
#include "network.h"

typedef struct {
	gchar *tmpdir;
} NetworkFixture;

static void network_fixture_set_up(NetworkFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp(NULL, NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_print("network tmpdir: %s\n", fixture->tmpdir);
}

static void network_fixture_tear_down(NetworkFixture *fixture,
		gconstpointer user_data)
{
	// FIXME remove tmpdir
	g_free(fixture->tmpdir);
}

static void test_download_file(NetworkFixture *fixture,
			       gconstpointer user_data)
{
	const gchar *target, *tmpname;

	target = g_build_filename(fixture->tmpdir, "target", NULL);
	tmpname = ".tmp.0123456789ABCDEF";
	
	g_assert_true(download_file(target, tmpname, "http://example.com/", 0));
}

static void test_download_mem(void)
{
	GBytes *data = NULL;

	/* basic download (no size limit) */
	g_assert_true(download_mem(&data, "http://example.com/", 0));
	g_assert_nonnull(data);
	g_clear_pointer(&data, g_bytes_unref);

	/* download with large limit */
	g_assert_true(download_mem(&data, "http://example.com/", 1048576));
	g_assert_nonnull(data);
	g_clear_pointer(&data, g_bytes_unref);

	/* abort download for too large files */
	g_assert_false(download_mem(&data, "http://example.com/", 1024));
	g_assert_null(data);
	g_clear_pointer(&data, g_bytes_unref);

	/* download with https */
	g_assert_true(download_mem(&data, "https://example.com/", 1048576));
	g_assert_nonnull(data);
	g_clear_pointer(&data, g_bytes_unref);

	/* invalid host name */
	g_assert_false(download_mem(&data, "http://error.example.com/", 1024));
	g_assert_null(data);
	g_clear_pointer(&data, g_bytes_unref);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/network/download_mem", test_download_mem);

	g_test_add("/network/download_file", NetworkFixture, NULL,
		   network_fixture_set_up, test_download_file,
		   network_fixture_tear_down);

	return g_test_run();
}
