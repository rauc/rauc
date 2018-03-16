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

static void bootchooser_fixture_tear_down(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void bootchooser_barebox(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *slot = NULL, *primary = NULL;
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
bootname=recovery\n\
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

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-0");
	g_assert_nonnull(slot);

	/* check rootfs is considered good */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_assert_true(r_boot_get_state(slot, &good, NULL));
	g_assert_true(good);

	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);
	g_assert(primary == slot);

	/* check rootfs is considered bad (remaining_attempts = 0) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_assert_true(r_boot_get_state(slot, &good, NULL));
	g_assert_false(good);

	/* check rootfs is considered bad (priority = 0) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_assert_true(r_boot_get_state(slot, &good, NULL));
	g_assert_false(good);

	/* check rootfs-0 is marked good (has remaining attempts reset 1->3) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=1\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_assert_true(r_boot_set_state(slot, TRUE, NULL));

	/* check rootfs-0 is marked bad (prio and attempts 0) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=0\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_assert_true(r_boot_set_state(slot, FALSE, NULL));

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-1");
	g_assert_nonnull(slot);

	/* check rootfs-1 is marked primary (prio set to 20, others to 10) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=20\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=10\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=20\n\
", TRUE);
	g_assert_true(r_boot_set_primary(slot, NULL));

	/* check rootfs-1 is marked primary while current remains disabled (prio set to 20, others to 10) */
	g_setenv("BAREBOX_STATE_VARS_PRE", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=0\n\
bootstate.system1.priority=10\n\
", TRUE);
	g_setenv("BAREBOX_STATE_VARS_POST", " \
bootstate.system0.remaining_attempts=3\n\
bootstate.system0.priority=0\n\
bootstate.system1.remaining_attempts=3\n\
bootstate.system1.priority=20\n\
", TRUE);
	g_assert_true(r_boot_set_primary(slot, NULL));
}

static void bootchooser_grub(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *slot;

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

	gchar* pathname = write_tmp_file(fixture->tmpdir, "grub.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context();

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_state(slot, TRUE, NULL));
	g_assert_true(r_boot_set_state(slot, FALSE, NULL));

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot, NULL));
}

static void bootchooser_uboot(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *slot;

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

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_state(slot, TRUE, NULL));
	g_assert_true(r_boot_set_state(slot, FALSE, NULL));

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot, NULL));
}

static void bootchooser_efi(BootchooserFixture *fixture,
		gconstpointer user_data)
{
	RaucSlot *slot;
	gboolean good;
	RaucSlot *primary = NULL;

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

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_get_state(slot, &good, NULL));
	g_assert_true(good);
	primary = r_boot_get_primary(NULL);
	g_assert_nonnull(primary);

	g_assert_true(r_boot_set_state(slot, FALSE, NULL));
	g_assert_true(r_boot_set_state(slot, TRUE, NULL));

	slot = find_config_slot_by_device(r_context()->config, "/dev/rootfs-1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot, NULL));
}


int main(int argc, char *argv[])
{
	gchar *path;
	setlocale(LC_ALL, "C");

	path = g_strdup_printf("%s:%s", "test/bin", g_getenv("PATH"));
	g_setenv("PATH", path, TRUE);
	g_free(path);

	g_test_init(&argc, &argv, NULL);

	g_test_add("/bootchoser/barebox", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_barebox,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchoser/grub", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_grub,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchoser/uboot", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_uboot,
			bootchooser_fixture_tear_down);

	g_test_add("/bootchoser/efi", BootchooserFixture, NULL,
			bootchooser_fixture_set_up, bootchooser_efi,
			bootchooser_fixture_tear_down);

	return g_test_run();
}
