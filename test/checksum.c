#include <stdio.h>
#include <locale.h>

#include "checksum.h"

#define TEST_DIGEST_FAIL "fa1lbad73aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"
#define TEST_DIGEST_GOOD "c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"

static void checksum_test1(void)
{
	RaucChecksum checksum = {};
	GError *error = NULL;

	g_assert_true(compute_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_no_error(error);
	g_assert_cmpstr(checksum.digest, ==, TEST_DIGEST_GOOD);
	g_assert(checksum.size == 32768);

	g_clear_pointer(&checksum.digest, g_free);
	checksum.size = 0;
	g_assert_false(compute_checksum(&checksum, "tesinstall-content/rootfs.img", &error));
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_clear_error(&error);
	g_assert_null(checksum.digest);
	g_assert(checksum.size == 0);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/checksum/test1", checksum_test1);

	return g_test_run();
}
