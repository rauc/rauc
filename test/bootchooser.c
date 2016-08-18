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
	RaucSlot *slot;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[slot.rescue.0]\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/sda0\n\
type=ext4\n\
bootname=system0\n\
\n\
[slot.rootfs.1]\n\
device=/dev/sda1\n\
type=ext4\n\
bootname=system1\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "barebox.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context_prepare();

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_state(slot, TRUE));
	g_assert_true(r_boot_set_state(slot, FALSE));

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot));
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
device=/dev/mtd4\n\
type=raw\n\
bootname=R\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
device=/dev/sda0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/sda1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "grub.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context_prepare();

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_state(slot, TRUE));
	g_assert_true(r_boot_set_state(slot, FALSE));

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot));
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
device=/dev/sda0\n\
type=ext4\n\
bootname=A\n\
\n\
[slot.rootfs.1]\n\
device=/dev/sda1\n\
type=ext4\n\
bootname=B\n";

	gchar* pathname = write_tmp_file(fixture->tmpdir, "uboot.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_clear_pointer(&r_context_conf()->configpath, g_free);
	r_context_conf()->configpath = pathname;
	r_context_prepare();

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda0");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_state(slot, TRUE));
	g_assert_true(r_boot_set_state(slot, FALSE));

	slot = find_config_slot_by_device(r_context()->config, "/dev/sda1");
	g_assert_nonnull(slot);

	g_assert_true(r_boot_set_primary(slot));
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

	return g_test_run ();
}
