#include <stdio.h>
#include <locale.h>

#include "checksum.h"

#define MANIFEST_DIGEST "fa285b828f53eabb4cb9003d28943ca33ea2234edcd93ac22b61659ffa41555a"

static void checksum_test1(void)
{
	RaucChecksum checksum;

	checksum.type = G_CHECKSUM_SHA256;
	checksum.digest = g_strdup(MANIFEST_DIGEST);

	g_assert_true(verify_checksum(&checksum, "test/manifest.raucm"));
	g_assert_false(verify_checksum(&checksum, "test/rootfs.raucs"));
	g_assert_false(verify_checksum(&checksum, "test/_MISSING_"));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/checksum/test1", checksum_test1);

	return g_test_run();
}
