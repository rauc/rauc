#include <locale.h>
#include <glib.h>

#include "utils.h"

static void resolve_device_test(void)
{
	gchar *rdev;

	g_assert_null(r_resolve_device(NULL));

	rdev = r_resolve_device("PARTLABEL=mylabel");
	g_assert_cmpstr(rdev, ==, "/dev/disk/by-partlabel/mylabel");
	g_free(rdev);

	rdev = r_resolve_device("PARTUUID=4f8bb419-01");
	g_assert_cmpstr(rdev, ==, "/dev/disk/by-partuuid/4f8bb419-01");
	g_free(rdev);

	rdev = r_resolve_device("UUID=9e8b0c3e-e20f-4119-b419-ec20a132aa94");
	g_assert_cmpstr(rdev, ==,
			"/dev/disk/by-uuid/9e8b0c3e-e20f-4119-b419-ec20a132aa94");
	g_free(rdev);
}

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

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/utils/resolve_device", resolve_device_test);
	g_test_add_func("/utils/whitespace_removed", whitespace_removed_test);

	return g_test_run();
}
