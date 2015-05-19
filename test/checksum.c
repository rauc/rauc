#include <stdio.h>
#include <locale.h>

#include "checksum.h"

#define TEST_DIGEST "c35020473aed1b4642cd726cad727b63fff2824ad68cedd7ffb73c7cbd890479"

static void checksum_test1(void)
{
	RaucChecksum checksum;

	checksum.type = 0;
	checksum.digest = NULL;
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", NULL));

	checksum.type = G_CHECKSUM_SHA256;
	g_assert_false(verify_checksum(&checksum, "test/install-content/appfs.img", NULL));

	checksum.digest = g_strdup(TEST_DIGEST);
	g_assert_true(verify_checksum(&checksum, "test/install-content/appfs.img", NULL));
	g_assert_false(verify_checksum(&checksum, "tesinstall-content/rootfs.img", NULL));
	g_assert_false(verify_checksum(&checksum, "test/_MISSING_", NULL));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/checksum/test1", checksum_test1);

	return g_test_run();
}
