#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

static void whitespace_removed_test(void)
{
	gchar *str;

	str = g_strdup("foo");
	g_assert_false(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("\r\n\t  foo  \t\r\n");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);
}

static void get_sectorsize_test(void)
{
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	guint size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_sectorsize(fd);
	g_assert_cmpint(size, ==, 512);

	if (fd >= 0)
		g_close(fd, NULL);
}

static void get_device_size_test(void)
{
	GError *error = NULL;
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	goffset size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_device_size(fd, &error);
	g_assert_no_error(error);
	g_assert_cmpint(size, ==, 64<<20); /* 64MiB */

	if (fd >= 0)
		g_close(fd, NULL);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/utils/whitespace_removed", whitespace_removed_test);
	g_test_add_func("/utils/get_sectorsize", get_sectorsize_test);
	g_test_add_func("/utils/get_device_size", get_device_size_test);

	return g_test_run();
}
