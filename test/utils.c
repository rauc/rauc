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

static void ubi_name_to_sysfs_path_test(void)
{
	gchar *spath;

	g_assert_null(r_ubi_name_to_sysfs_path(NULL));

	/* too short */
	g_assert_null(r_ubi_name_to_sysfs_path("ubi"));

	/* simply wrong */
	g_assert_null(r_ubi_name_to_sysfs_path("/dev/sda7"));

	/* "ubi" followed by no separator and no digit */
	g_assert_null(r_ubi_name_to_sysfs_path("ubiY"));

	/* "ubiY" */
	spath = r_ubi_name_to_sysfs_path("ubi3");
	g_assert_cmpstr(spath, ==, "/sys/class/ubi/ubi0/ubi0_3");
	g_free(spath);

	/* "ubiX_Y" */
	spath = r_ubi_name_to_sysfs_path("ubi1_2");
	g_assert_cmpstr(spath, ==, "/sys/class/ubi/ubi1/ubi1_2");
	g_free(spath);

	/* "ubiX_" followed by non numeric garbage */
	g_assert_null(r_ubi_name_to_sysfs_path("ubi0_Y"));

	/* Missing more bad cases and NAME resolving, the latter would
	 * need either a reproducible test setup or mocking. */
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
	g_test_add_func("/utils/ubi_name_to_sysfs_path", ubi_name_to_sysfs_path_test);
	g_test_add_func("/utils/whitespace_removed", whitespace_removed_test);

	return g_test_run();
}
