#include <stdio.h>
#include <locale.h>

#include "checksum.h"

#define TEST_DIGEST_FAIL "fa1lbad73aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"
#define TEST_DIGEST_GOOD "c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"

static void checksum_test1(void)
{
	RaucChecksum checksum = {};
	GError *error = NULL;

	checksum.type = 0;
	checksum.digest = NULL;
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_FAILED);
	g_clear_error(&error);

	checksum.type = G_CHECKSUM_SHA256;
	checksum.digest = g_strdup(TEST_DIGEST_FAIL);
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_SIZE_MISMATCH);
	g_clear_error(&error);

	checksum.size = 32768;
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_DIGEST_MISMATCH);
	g_clear_error(&error);

	checksum.size = 0;
	checksum.digest = g_strdup(TEST_DIGEST_GOOD);
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_SIZE_MISMATCH);
	g_clear_error(&error);

	checksum.size = 32768;
	g_assert_true(verify_checksum(&checksum, "test/install-content/appfs.img", &error));
	g_assert_no_error(error);

	g_assert_false(verify_checksum(&checksum, "tesinstall-content/rootfs.img", &error));
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_clear_error(&error);

	g_assert_false(verify_checksum(&checksum, "test/_MISSING_", &error));
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_clear_error(&error);

	g_clear_pointer(&checksum.digest, g_free);
	checksum.size = 0;
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

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/checksum/test1", checksum_test1);

	return g_test_run();
}
