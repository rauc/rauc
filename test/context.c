#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>

static void test_bootslot_rauc_slot(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/dummy rauc.slot=A rootwait";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "A");

	r_context_clean();
}

static void test_bootslot_root(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/dummy rootwait";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/dummy");

	r_context_clean();
}

static void test_bootslot_external_boot(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/dummy rauc.external rootwait";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "_external_");

	r_context_clean();
}

static void test_bootslot_nfs_boot(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/nfs";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "_external_");

	r_context_clean();
}

static void test_bootslot_partlabel(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=PARTLABEL=root_partition";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/disk/by-partlabel/root_partition");

	r_context_clean();
}

static void test_bootslot_partuuid(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=PARTUUID=12345678-01";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/disk/by-partuuid/12345678-01");

	r_context_clean();
}

static void test_bootslot_uuid(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet root=UUID=123e4567-e89b-12d3-a456-426614174000";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/disk/by-uuid/123e4567-e89b-12d3-a456-426614174000");

	r_context_clean();
}

static void test_bootslot_no_bootslot(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_null(r_context()->bootslot);

	r_context_clean();
}

static void test_bootslot_raspberrypi_bootloader(void)
{
	if (g_access("/sys/firmware/devicetree/base/chosen/bootloader", R_OK) != 0) {
		g_test_skip("Test requires file /sys/firmware/devicetree/base/chosen/bootloader to be readable");
		return;
	}

	r_context_conf()->configpath = g_strdup("test/test-raspberrypi.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "2");

	r_context_clean();
}

static void test_bootslot_raspberrypi_bootloader_no_bootslot(void)
{
	if (g_access("/sys/firmware/devicetree/base/chosen/bootloader", F_OK) == 0) {
		g_test_skip("Test requires file /sys/firmware/devicetree/base/chosen/bootloader to be inexistent");
		return;
	}

	r_context_conf()->configpath = g_strdup("test/test-raspberrypi.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	r_context_conf()->mock.proc_cmdline = "quiet";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_null(r_context()->bootslot);

	r_context_clean();
}

static void test_bootslot_custom_bootloader(void)
{
	r_context_conf()->configpath = g_strdup("test/test-custom.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	g_assert_true(g_setenv("CUSTOM_STATE_PATH", "test/custom-state-current", TRUE));
	r_context_conf()->mock.proc_cmdline = "quiet";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "A");

	r_context_clean();
}

static void test_bootslot_custom_bootloader_no_bootslot(void)
{
	r_context_conf()->configpath = g_strdup("test/test-custom.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	g_assert_true(g_setenv("CUSTOM_STATE_PATH", "/dev/null", TRUE));
	r_context_conf()->mock.proc_cmdline = "quiet";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_null(r_context()->bootslot);

	r_context_clean();
}

/* Tests that the infos provided by the configured system-info handler make it
 * into RAUC's system information.
 */
static void test_context_system_info(void)
{
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	/* Test if special keys are retrieved */
	g_assert_cmpstr(r_context()->system_serial, ==, "1234");
	g_assert_cmpstr(r_context()->config->system_variant, ==, "test-variant-x");
	g_assert_cmpstr(r_context()->system_version, ==, "1.0.0");

	/* Test if configured keys appear in system_info hash table */
	g_assert_nonnull(r_context()->system_info);
	g_assert_true(g_hash_table_contains(r_context()->system_info, "RAUC_SYSTEM_SERIAL"));
	g_assert_true(g_hash_table_contains(r_context()->system_info, "RAUC_SYSTEM_VARIANT"));
	g_assert_true(g_hash_table_contains(r_context()->system_info, "RAUC_SYSTEM_VERSION"));
	g_assert_true(g_hash_table_contains(r_context()->system_info, "RAUC_CUSTOM_VARIABLE"));
	g_assert_false(g_hash_table_contains(r_context()->system_info, "RAUC_TEST_VAR"));

	r_context_clean();
}

/* Tests that the static variant from the system.conf is not cleared by an
 * empty system-info handler.
 */
static void test_context_system_info_dummy(void)
{
	r_context_conf()->configpath = g_strdup("test/test-dummy-handler.conf");
	r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_REQUIRED;
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->system_serial, ==, NULL);
	g_assert_true(r_context()->config->system_variant_type == R_CONFIG_SYS_VARIANT_NAME);
	g_assert_cmpstr(r_context()->config->system_variant, ==, "Default Variant");

	g_assert_nonnull(r_context()->system_info);
	g_assert_cmpuint(g_hash_table_size(r_context()->system_info), ==, 0);

	r_context_clean();
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/context/bootslot/rauc-slot", test_bootslot_rauc_slot);

	g_test_add_func("/context/bootslot/root", test_bootslot_root);

	g_test_add_func("/context/bootslot/external_boot", test_bootslot_external_boot);

	g_test_add_func("/context/bootslot/nfs_boot", test_bootslot_nfs_boot);

	g_test_add_func("/context/bootslot/partlabel", test_bootslot_partlabel);

	g_test_add_func("/context/bootslot/partuuid", test_bootslot_partuuid);

	g_test_add_func("/context/bootslot/uuid", test_bootslot_uuid);

	g_test_add_func("/context/bootslot/no-bootslot", test_bootslot_no_bootslot);

	g_test_add_func("/context/bootslot/raspberrypi-bootslot", test_bootslot_raspberrypi_bootloader);

	g_test_add_func("/context/bootslot/raspberrypi-bootslot_no_bootslot", test_bootslot_raspberrypi_bootloader_no_bootslot);

	g_test_add_func("/context/bootslot/custom-bootslot", test_bootslot_custom_bootloader);

	g_test_add_func("/context/bootslot/custom-bootslot_no_bootslot", test_bootslot_custom_bootloader_no_bootslot);

	g_test_add_func("/context/system-info", test_context_system_info);

	g_test_add_func("/context/system-info-dummy", test_context_system_info_dummy);

	return g_test_run();
}
