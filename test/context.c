#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <context.h>

#include "common.h"

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

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/nfs");

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


int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/context/bootslot/rauc-slot", test_bootslot_rauc_slot);

	g_test_add_func("/context/bootslot/root", test_bootslot_root);

	g_test_add_func("/context/bootslot/external_boot", test_bootslot_external_boot);

	g_test_add_func("/context/bootslot/nfs_boot", test_bootslot_nfs_boot);

	g_test_add_func("/context/bootslot/no-bootslot", test_bootslot_no_bootslot);

	return g_test_run();
}
