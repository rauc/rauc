#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <context.h>

#include "common.h"

static void external_boot(void)
{
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/dummy rauc.external rootwait";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "_external_");

	r_context_conf()->mock.proc_cmdline = NULL;
	g_clear_pointer(&r_context_conf()->bootslot, g_free);
}

static void nfs_boot(void)
{
	r_context_conf()->mock.proc_cmdline = "quiet root=/dev/nfs";
	g_clear_pointer(&r_context_conf()->bootslot, g_free);

	g_assert_cmpstr(r_context()->bootslot, ==, "/dev/nfs");

	r_context_conf()->mock.proc_cmdline = NULL;
	g_clear_pointer(&r_context_conf()->bootslot, g_free);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/context/external_boot", external_boot);

	g_test_add_func("/context/nfs_boot", nfs_boot);

	return g_test_run();
}
