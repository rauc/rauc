#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <bootchooser.h>
#include <context.h>
#include <utils.h>

#include "common.h"

typedef struct {
	gchar *tmpdir;
} BootchooserFixture;

static void bootchooser_fixture_set_up(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-bootchooser-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
}

static void custom_bootchooser_fixture_set_up(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	bootchooser_fixture_set_up(fixture, user_data);

	g_assert_true(test_copy_file("test/bin/custom-bootloader-script", NULL,
			fixture->tmpdir, "custom-bootloader-script"));
}

static void bootchooser_fixture_tear_down(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void bootchooser_barebox(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL, *rootfs1 = NULL, *primary = NULL;
	gboolean good;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.recovery.0]\n\
device=/dev/recovery-0\n\
type=raw\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=system1\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "barebox.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);
	rootfs1 = find_config_slot_by_name(r_context()->config, "rootfs.1");
	g_assert_nonnull(rootfs1);

	/* check rootfs.0 and rootfs.1 are considered good */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_true(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, NULL));
	g_assert_true(good);
	/* check rootfs.0 is considered as primary */
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary == rootfs0);
	g_assert(primary != rootfs1);

	/* check rootfs.0 is considered bad (remaining_attempts = 0) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_false(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, NULL));
	g_assert_true(good);
	/* check rootfs.1 is considered as primary */
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	/* check rootfs.0 is considered bad (priority = 0) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_false(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, NULL));
	g_assert_true(good);
	/* check rootfs.1 is considered as primary */
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	/* check rootfs.0 is marked good (has remaining attempts reset 1->3) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=1\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(r_boot_set_state(rootfs0, TRUE, NULL));

	/* check rootfs.0 is marked bad (prio and attempts 0) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(r_boot_set_state(rootfs0, FALSE, NULL));

	/* check rootfs.1 is marked primary (prio set to 20, others to 10) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=10\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=20\n\
", TRUE));
	g_assert_true(r_boot_set_primary(rootfs1, NULL));

	/* check rootfs.1 is marked primary while current remains disabled (prio set to 20, others to 10) */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=0\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=20\n\
", TRUE));
	g_assert_true(r_boot_set_primary(rootfs1, NULL));
}

static void bootchooser_barebox_asymmetric(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	RaucSlot *recovery = NULL, *rootfs0 = NULL, *primary = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.recovery.0]\n\
device=/dev/recovery-0\n\
type=raw\n\
bootname=recovery\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "barebox_asymmetric.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	recovery = find_config_slot_by_name(r_context()->config, "recovery.0");
	g_assert_nonnull(recovery);
	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);

	/* check rootfs.0 is marked bad (prio and attempts 0) for asymmetric update scenarios */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.recovery.remaining_attempts=3\n\
bootstate.recovery.priority=20\n\
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.recovery.remaining_attempts=3\n\
bootstate.recovery.priority=20\n\
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=0\n\
", TRUE));
	res = r_boot_set_state(rootfs0, FALSE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	/* check rootfs.0 is marked primary for asymmetric update scenarios */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.recovery.remaining_attempts=3\n\
bootstate.recovery.priority=20\n\
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=0\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.recovery.remaining_attempts=3\n\
bootstate.recovery.priority=10\n\
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
", TRUE));
	res = r_boot_set_primary(rootfs0, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == recovery);
}

static void bootchooser_barebox_conf_attempts(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	GError *error = NULL;
	gboolean res;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
boot-attempts=5\n\
boot-attempts-primary=10\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=system1\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "barebox.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);

	/* check rootfs.0 is marked good with configured default attempts */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=5\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	res = r_boot_set_state(rootfs0, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	/* check rootfs.0 is marked primary with configured primary attempts */
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=10\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE));
	res = r_boot_set_primary(rootfs0, &error);
	g_assert_no_error(error);
	g_assert_true(res);
}

static void bootchooser_barebox_fallback_lock_counter(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
prevent-late-fallback=lock-counter\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=system1\n";

	gchar *pathname = write_tmp_file(fixture->tmpdir, "barebox.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;

	// Test if lock counter is enabled
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE",
			"bootstate.system0.remaining_attempts=3\n"
			"bootstate.system0.priority=20\n"
			"bootstate.system1.remaining_attempts=3\n"
			"bootstate.system1.priority=10\n"
			"bootstate.attempts_locked=1\n",
			TRUE));

	r_context();
	g_assert_nonnull(r_context()->config);
	g_assert_cmpint(r_context()->config->prevent_late_fallback, ==, R_CONFIG_FALLBACK_LOCK_COUNTER);

	gboolean lock_counter = FALSE;
	g_assert_true(r_boot_get_counters_lock(&lock_counter, NULL));
	g_assert_true(lock_counter);

	// Disable lock counter
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE",
			"bootstate.system0.remaining_attempts=3\n"
			"bootstate.system0.priority=20\n"
			"bootstate.system1.remaining_attempts=3\n"
			"bootstate.system1.priority=10\n"
			"bootstate.attempts_locked=1\n",
			TRUE));
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_POST",
			"bootstate.system0.remaining_attempts=3\n"
			"bootstate.system0.priority=20\n"
			"bootstate.system1.remaining_attempts=3\n"
			"bootstate.system1.priority=10\n"
			"bootstate.attempts_locked=0\n",
			TRUE));

	g_assert_true(r_boot_set_counters_lock(FALSE, NULL));

	// Verify lock counter is disabled
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE",
			"bootstate.system0.remaining_attempts=3\n"
			"bootstate.system0.priority=20\n"
			"bootstate.system1.remaining_attempts=3\n"
			"bootstate.system1.priority=10\n"
			"bootstate.attempts_locked=0\n",
			TRUE));

	lock_counter = FALSE;
	g_assert_true(r_boot_get_counters_lock(&lock_counter, NULL));
	g_assert_false(lock_counter);
}

static void bootchooser_barebox_fallback_lock_counter_var_missing(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
prevent-late-fallback=lock-counter\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=system1\n";

	gchar *pathname = write_tmp_file(fixture->tmpdir, "barebox.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;

	// Test if lock counter is enabled
	g_assert_true(g_setenv("BAREBOX_STATE_VARS_PRE",
			"bootstate.system0.remaining_attempts=3\n"
			"bootstate.system0.priority=20\n"
			"bootstate.system1.remaining_attempts=3\n"
			"bootstate.system1.priority=10\n",
			TRUE));

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "No data directory or status file set, falling back to per-slot status.\nConsider setting \'data-directory=<path>\' or \'statusfile=<path>/per-slot\' explicitly.");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Using per-slot statusfile. System status information not supported!");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, "Using system config file *");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Failed to read barebox lock counter: Failed to parse value: *");
	r_context();
	g_assert_nonnull(r_context()->config);
	g_assert_cmpint(r_context()->config->prevent_late_fallback, ==, R_CONFIG_FALLBACK_LOCK_COUNTER);

	GError *error = NULL;
	g_assert_false(r_boot_set_counters_lock(TRUE, &error));
	g_error_free(error);
}

/* Write content to state storage for grub-editenv RAUC mock tool.
 * Content should be similar to:
 * "\
 * A_TRY=1\n\
 * B_TRY=0\n\
 * A_OK=1\n\
 * B_OK=0\n\
 * ORDER=A B\n\
 * "
 */
static void test_grub_initialize_state(const gchar *vars)
{
	g_assert_true(g_file_set_contents(r_context()->config->grubenv_path, vars, -1, NULL));
}

/**
 * Returns TRUE if mock tools state content equals desired content,
 * FALSE otherwise
 */
static gboolean test_grub_post_state(const gchar *compare)
{
	g_autofree gchar *contents = NULL;

	g_assert_true(g_file_get_contents(r_context()->config->grubenv_path, &contents, NULL, NULL));

	if (g_strcmp0(contents, compare) != 0) {
		g_print("Error: '%s' and '%s' differ\n", contents, compare);
		return FALSE;
	}

	return TRUE;
}

static void bootchooser_grub(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	RaucSlot *rootfs1 = NULL;
	RaucSlot *primary = NULL;
	gboolean good;
	GError *error = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=grub\n\
grubenv=grubenv.test\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/rescue-0\n\
type=raw\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "grub.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);
	rootfs1 = find_config_slot_by_name(r_context()->config, "rootfs.1");
	g_assert_nonnull(rootfs1);

	/* check rootfs.0 and rootfs.1 are considered bad (as not marked good or boot attempt failed) */
	test_grub_initialize_state("\
A_TRY=1\n\
B_TRY=0\n\
A_OK=1\n\
B_OK=0\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_get_state(rootfs0, &good, &error));
	g_assert_false(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, &error));
	g_assert_false(good);

	/* check rootfs.0 and rootfs.1 are not considered good (A_TRY and B_OK not set) */
	test_grub_initialize_state("\
B_TRY=0\n\
A_OK=1\n\
ORDER=A B\n\
");
	g_assert_false(r_boot_get_state(rootfs0, &good, &error));
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);
	g_assert_false(r_boot_get_state(rootfs1, &good, &error));
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);

	/* check rootfs.1 is considered primary (as rootfs.0 has A_TRY=1) */
	test_grub_initialize_state("\
A_TRY=1\n\
B_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=A B\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	/* check none is considered primary (as rootfs.0 has A_OK=0 and rootfs.1 is not in ORDER) */
	test_grub_initialize_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=A\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_null(primary);
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);

	/* check none is considered primary (B_TRY is not set, rootfs.0 is not in ORDER) */
	test_grub_initialize_state("\
A_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=B\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_null(primary);
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);

	/* check none is considered primary (B_OK is not set, rootfs.0 is not in ORDER) */
	test_grub_initialize_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=0\n\
ORDER=B\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_null(primary);
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);

	/* check rootfs.0 + rootfs.1 are considered good */
	test_grub_initialize_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=1\n\
B_OK=1\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_get_state(rootfs0, &good, &error));
	g_assert_true(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, &error));
	g_assert_true(good);

	/* check rootfs.0 is marked bad (A_OK set to 0) */
	test_grub_initialize_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=1\n\
B_OK=1\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_set_state(rootfs0, FALSE, &error));
	g_assert_true(test_grub_post_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=A B\n\
"));
	/* check rootfs.0 is considered bad */
	g_assert_true(r_boot_get_state(rootfs0, &good, &error));
	g_assert_false(good);

	/* check rootfs.0 is marked good (A_OK set to 0) */
	test_grub_initialize_state("\
A_TRY=1\n\
B_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_set_state(rootfs0, TRUE, &error));
	g_assert_true(test_grub_post_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=1\n\
B_OK=1\n\
ORDER=A B\n\
"));
	/* check rootfs.0 is considered good */
	g_assert_true(r_boot_get_state(rootfs0, &good, &error));
	g_assert_true(good);

	/* check rootfs.1 is marked primary (B_TRY=0, B_OK=1, B first in ORDER) */
	test_grub_initialize_state("\
A_TRY=0\n\
B_TRY=1\n\
A_OK=1\n\
B_OK=0\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_set_primary(rootfs1, NULL));
	g_assert_true(test_grub_post_state("\
A_TRY=0\n\
B_TRY=0\n\
A_OK=1\n\
B_OK=1\n\
ORDER=B A\n\
"));
	/* check rootfs.1 is considered good */
	g_assert_true(r_boot_get_state(rootfs1, &good, &error));
	g_assert_true(good);
	/* check rootfs.1 is considered primary */
	primary = r_boot_get_primary(&error);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	/* check rootfs.1 is marked primary and rootfs.0 is disabled */
	test_grub_initialize_state("\
A_TRY=1\n\
B_TRY=1\n\
A_OK=0\n\
B_OK=0\n\
ORDER=A B\n\
");
	g_assert_true(r_boot_set_primary(rootfs1, NULL));
	g_assert_true(test_grub_post_state("\
A_TRY=1\n\
B_TRY=0\n\
A_OK=0\n\
B_OK=1\n\
ORDER=B A\n\
"));
}

/* Write content to state storage for uboot fw_setenv / fw_printenv RAUC mock
 * tools. Content should be similar to:
 * "\
 * BOOT_ORDER=A B\n\
 * BOOT_A_LEFT=3\n\
 * BOOT_B_LEFT=3\n\
 * "
 */
static void test_uboot_initialize_state(const BootchooserFixture *fixture, const gchar *vars)
{
	g_autofree gchar *state_path = g_build_filename(fixture->tmpdir, "uboot-test-state", NULL);
	g_assert_true(g_setenv("UBOOT_STATE_PATH", state_path, TRUE));
	g_assert_true(g_file_set_contents(state_path, vars, -1, NULL));
}

/* Write desired target content of variables set by RAUC's fw_setenv /
 * fw_printenv mock tools for asserting correct behavior.
 * Content should identical to format described for
 * test_uboot_initialize_state().
 *
 * Returns TRUE if mock tools state content equals desired content,
 * FALSE otherwise
 */
static gboolean test_uboot_post_state(const BootchooserFixture *fixture, const gchar *compare)
{
	g_autofree gchar *state_path = g_build_filename(fixture->tmpdir, "uboot-test-state", NULL);
	g_autofree gchar *contents = NULL;

	g_assert_true(g_file_get_contents(state_path, &contents, NULL, NULL));

	if (g_strcmp0(contents, compare) != 0) {
		g_print("Error: '%s' and '%s' differ\n", contents, compare);
		return FALSE;
	}

	return TRUE;
}

static void bootchooser_uboot(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	RaucSlot *rootfs1 = NULL;
	RaucSlot *primary = NULL;
	gboolean good;
	GError *error = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=R\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "uboot.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);
	rootfs1 = find_config_slot_by_name(r_context()->config, "rootfs.1");
	g_assert_nonnull(rootfs1);

	/* check rootfs.0 and rootfs.1 are considered bad (as not in BOOT_ORDER / no attempts left) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=0\n\
");
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_false(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, NULL));
	g_assert_false(good);

	/* check rootfs.1 is considered primary (as rootfs.0 has BOOT_A_LEFT set to 0) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=0\n\
BOOT_B_LEFT=3\n\
");
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	/* check none is considered primary (as rootfs.0 has BOOT_A_LEFT set to 0 and rootfs.1 is not in BOOT_ORDER) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A\n\
BOOT_A_LEFT=0\n\
BOOT_B_LEFT=3\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_null(primary);
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);

	/* check rootfs.0 + rootfs.1 are considered good */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=3\n\
");
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_true(good);
	g_assert_true(r_boot_get_state(rootfs1, &good, NULL));
	g_assert_true(good);

	/* check boot lock counter which is currently only implemented for barebox.
	 * So test if it fails as expected */
	gboolean lock_counter;
	g_assert_false(r_boot_set_counters_lock(TRUE, NULL));
	g_assert_false(r_boot_get_counters_lock(&lock_counter, NULL));

	/* check rootfs.0 is marked bad (BOOT_A_LEFT set to 0) */
	g_assert_true(r_boot_set_state(rootfs0, FALSE, NULL));
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=B\n\
BOOT_A_LEFT=0\n\
BOOT_B_LEFT=3\n\
"));
	/* check rootfs.0 is considered bad*/
	g_assert_true(r_boot_get_state(rootfs0, &good, NULL));
	g_assert_false(good);

	/* check rootfs.0 is marked good again (BOOT_A_LEFT reset to 3) */
	g_assert_true(r_boot_set_state(rootfs0, TRUE, NULL));
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=3\n\
"));

	/* check rootfs.1 is marked primary (first in BOOT_ORDER, BOOT_B_LEFT reset to 3) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=1\n\
");
	g_assert_true(r_boot_set_primary(rootfs1, NULL));
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=B A\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=3\n\
"));

	/* check rootfs.1 is marked primary while rootfs.0 remains disabled (BOOT_A_LEFT remains 0)  */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=0\n\
BOOT_B_LEFT=0\n\
");
	g_assert_true(r_boot_set_primary(rootfs1, NULL));
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=B A\n\
BOOT_A_LEFT=0\n\
BOOT_B_LEFT=3\n\
"));
}

static void bootchooser_uboot_asymmetric(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	RaucSlot *rescue = NULL;
	RaucSlot *primary = NULL;
	gboolean res;
	GError *ierror = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/rescue-0\n\
type=raw\n\
bootname=R\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=A\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "uboot_asymmetric.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rescue = find_config_slot_by_name(r_context()->config, "rescue.0");
	g_assert_nonnull(rescue);
	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);

	/* check rootfs.0 is marked bad (not in BOOT_ORDER, BOOT_R_LEFT = 0) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=R A\n\
BOOT_R_LEFT=3\n\
BOOT_A_LEFT=3\n\
");
	res = r_boot_set_state(rootfs0, FALSE, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=R\n\
BOOT_R_LEFT=3\n\
BOOT_A_LEFT=0\n\
"));

	/* check rootfs.0 is marked primary (first in BOOT_ORDER) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=R A\n\
BOOT_R_LEFT=3\n\
BOOT_A_LEFT=1\n\
");
	res = r_boot_set_primary(rootfs0, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=A R\n\
BOOT_R_LEFT=3\n\
BOOT_A_LEFT=3\n\
"));

	/* check rootfs.0 is considered primary (as rootfs.0 has BOOT_A_LEFT set to 0) */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A R\n\
BOOT_R_LEFT=3\n\
BOOT_A_LEFT=3\n\
");
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary != rescue);
	g_assert(primary == rootfs0);
}

static void bootchooser_uboot_conf_attempts(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	GError *error = NULL;
	gboolean res;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
boot-attempts=5\n\
boot-attempts-primary=10\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "uboot.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(rootfs0);

	/* check rootfs.0 is marked good with configured default attempts */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=3\n\
");
	res = r_boot_set_state(rootfs0, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=5\n\
BOOT_B_LEFT=3\n\
"));

	/* check rootfs.0 is marked primary with configured primary attempts */
	test_uboot_initialize_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=3\n\
BOOT_B_LEFT=3\n\
");
	res = r_boot_set_primary(rootfs0, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	/* remember: U-Boot uses hex numbers without a prefix */
	g_assert_true(test_uboot_post_state(fixture, "\
BOOT_ORDER=A B\n\
BOOT_A_LEFT=a\n\
BOOT_B_LEFT=3\n\
"));
}

static void bootchooser_efi(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *slot;
	gboolean good;
	RaucSlot *primary = NULL;
	gchar *bootname;
	GError *error = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=efi\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=recover\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=system1\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "efi.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	slot = find_config_slot_by_name(r_context()->config, "rootfs.0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_get_state(slot, &good, NULL));
	g_assert_true(good);
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);

	g_assert_true(r_boot_set_state(slot, FALSE, NULL));
	g_assert_true(r_boot_set_state(slot, TRUE, NULL));

	slot = find_config_slot_by_name(r_context()->config, "rootfs.1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot, NULL));

	bootname = r_boot_get_current_bootname(r_context()->config, "", &error);
	g_assert_nonnull(bootname);
}

/* Write content to state storage for custom-backend RAUC mock
 * tools. Content should be similar to:
 * "\
 * PRIMARY=A\n\
 * STATE_A=good\n\
 * STATE_B=good\n\
 * "
 */
static void test_custom_initialize_state(const BootchooserFixture *fixture, const gchar *vars)
{
	g_autofree gchar *state_path = g_build_filename(fixture->tmpdir, "custom-test-state", NULL);
	g_assert_true(g_setenv("CUSTOM_STATE_PATH", state_path, TRUE));
	g_assert_true(g_file_set_contents(state_path, vars, -1, NULL));
}

/* Content written should identical to format described for
 * test_custom_initialize_state().
 *
 * Returns TRUE if mock tools state content equals desired content,
 * FALSE otherwise
 */
static gboolean test_custom_post_state(const BootchooserFixture *fixture, const gchar *compare)
{
	g_autofree gchar *state_path = g_build_filename(fixture->tmpdir, "custom-test-state", NULL);
	g_autofree gchar *contents = NULL;

	g_assert_true(g_file_get_contents(state_path, &contents, NULL, NULL));

	if (g_strcmp0(contents, compare) != 0) {
		g_print("Error: '%s' and '%s' differ\n", contents, compare);
		return FALSE;
	}

	return TRUE;
}

static void bootchooser_custom(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *rootfs0 = NULL;
	RaucSlot *rootfs1 = NULL;
	RaucSlot *primary = NULL;
	gboolean good;
	GError *error = NULL;
	gboolean res;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=custom\n\
mountprefix=/mnt/myrauc/\n\
\n\
[handlers]\n\
bootloader-custom-backend=custom-bootloader-script\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=R\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/rootfs-0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/rootfs-1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "custom.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	rootfs0 = find_config_slot_by_device(r_context()->config, "/dev/rootfs-0");
	g_assert_nonnull(rootfs0);
	rootfs1 = find_config_slot_by_device(r_context()->config, "/dev/rootfs-1");
	g_assert_nonnull(rootfs1);

	/* check A and B can be set to bad */
	test_custom_initialize_state(fixture, "\
PRIMARY=A\n\
STATE_A=good\n\
STATE_B=good\n\
");
	res = r_boot_get_state(rootfs0, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_true(good);
	res = r_boot_get_state(rootfs1, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_true(good);

	res = r_boot_set_state(rootfs0, FALSE, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	res = r_boot_get_state(rootfs0, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_false(good);
	res = r_boot_set_state(rootfs1, FALSE, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	res = r_boot_get_state(rootfs1, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_false(good);
	g_assert_true(test_custom_post_state(fixture, "\
PRIMARY=A\n\
STATE_A=bad\n\
STATE_B=bad\n\
"));

	/* check A and B can be set to good */
	test_custom_initialize_state(fixture, "\
PRIMARY=A\n\
STATE_A=bad\n\
STATE_B=bad\n\
");
	res = r_boot_get_state(rootfs0, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_false(good);
	res = r_boot_get_state(rootfs1, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_false(good);
	res = r_boot_set_state(rootfs0, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	res = r_boot_get_state(rootfs0, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_true(good);
	res = r_boot_set_state(rootfs1, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	res = r_boot_get_state(rootfs1, &good, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_true(good);
	g_assert_true(test_custom_post_state(fixture, "\
PRIMARY=A\n\
STATE_A=good\n\
STATE_B=good\n\
"));

	/* check B can be set to primary */
	test_custom_initialize_state(fixture, "\
PRIMARY=A\n\
STATE_A=good\n\
STATE_B=good\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_no_error(error);
	g_assert_nonnull(primary);
	g_assert(primary == rootfs0);
	g_assert(primary != rootfs1);

	res = r_boot_set_primary(rootfs1, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	primary = r_boot_get_primary(&error);
	g_assert_no_error(error);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);
	g_assert_true(test_custom_post_state(fixture, "\
PRIMARY=B\n\
STATE_A=good\n\
STATE_B=good\n\
"));

	/* check A can be set to primary */
	test_custom_initialize_state(fixture, "\
PRIMARY=B\n\
STATE_A=good\n\
STATE_B=good\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_no_error(error);
	g_assert_nonnull(primary);
	g_assert(primary != rootfs0);
	g_assert(primary == rootfs1);

	res = r_boot_set_primary(rootfs0, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	primary = r_boot_get_primary(&error);
	g_assert_no_error(error);
	g_assert_nonnull(primary);
	g_assert(primary == rootfs0);
	g_assert(primary != rootfs1);
	g_assert_true(test_custom_post_state(fixture, "\
PRIMARY=A\n\
STATE_A=good\n\
STATE_B=good\n\
"));

	/* check none is considered primary if both are bad */
	test_custom_initialize_state(fixture, "\
PRIMARY=A\n\
STATE_A=bad\n\
STATE_B=bad\n\
");
	primary = r_boot_get_primary(&error);
	g_assert_null(primary);
	g_assert_error(error, R_BOOTCHOOSER_ERROR, R_BOOTCHOOSER_ERROR_PARSE_FAILED);
	g_clear_error(&error);
}

int main(int argc, char *argv[])
{
	gchar *path;
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	path = g_strdup_printf("%s:%s", "test/bin", g_getenv("PATH"));
	g_assert_true(g_setenv("PATH", path, TRUE));
	g_free(path);

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bootchooser/barebox", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/barebox-asymmetric", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox_asymmetric,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/barebox-conf-attempts", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox_conf_attempts,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/barebox-conf-fallback-lock-counter", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox_fallback_lock_counter,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/barebox-conf-fallback-lock-counter-var-missing", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox_fallback_lock_counter_var_missing,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/grub", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_grub,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/uboot", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_uboot,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/uboot-conf-attempts", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_uboot_conf_attempts,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/uboot-asymmetric", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_uboot_asymmetric,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/efi", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_efi,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchooser/custom", BootchooserFixture, NULL,
			custom_bootchooser_fixture_set_up, bootchooser_custom,
			bootchooser_fixture_tear_down);

	return g_test_run();
}
