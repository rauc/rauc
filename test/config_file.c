#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <config_file.h>
#include <context.h>

#include "common.h"
#include "utils.h"

typedef struct {
	gchar *tmpdir;
} ConfigFileFixture;

static void config_file_fixture_set_up(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-conf_file-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->handlerextra = g_strdup("--dummy1 --dummy2");
	r_context();
}

static void config_file_fixture_tear_down(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
	r_context_clean();
}

/* Test: Parse entire config file and check if derived slot / file structures
 * are initialized correctly */
static void config_file_full_config(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	GError *ierror = NULL;
	gboolean res;
	GList *slotlist;
	g_autoptr(RaucConfig) config = NULL;
	RaucSlot *slot;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
min-bundle-version=2024.05-downgrade+barrier\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
statusfile=/mnt/persistent-rw-fs/system.raucs\n\
max-bundle-download-size=42\n\
max-bundle-signature-size=32\n\
bundle-formats=verity\n\
\n\
[keyring]\n\
path=/etc/rauc/keyring/\n\
\n\
[casync]\n\
storepath=/var/lib/default.castr/\n\
tmppath=/tmp/\n\
install-args=--verbose\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/rescue-0\n\
type=raw\n\
bootname=factory0\n\
readonly=true\n\
\n\
[slot.rootfs.0]\n\
description=Root filesystem partition 0\n\
device=/dev/rootfs-0\n\
type=ext4\n\
extra-mkfs-opts=\n\
bootname=system0\n\
readonly=false\n\
force-install-same=false\n\
\n\
[slot.rootfs.1]\n\
description=Root filesystem partition 1\n\
device=/dev/rootfs-1\n\
type=ext4\n\
extra-mkfs-opts= \n\
bootname=system1\n\
readonly=false\n\
ignore-checksum=false\n\
\n\
[slot.appfs.0]\n\
description=Application filesystem partition 0\n\
device=/dev/appfs-0\n\
type=ext4\n\
parent=rootfs.0\n\
install-same=false\n\
\n\
[slot.appfs.1]\n\
description=Application filesystem partition 1\n\
device=/dev/appfs-1\n\
type=ext4\n\
extra-mkfs-opts=-L mylabel -i 8192\n\
parent=rootfs.1\n\
install-same=false\n\
[artifacts.containers]\n\
path=/var/artifacts/containers\n\
type=trees\n\
";

	g_autofree gchar* pathname = write_tmp_file(fixture->tmpdir, "full_config.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmpstr(config->system_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(config->system_min_bundle_version, ==, "2024.05-downgrade+barrier");
	g_assert_cmpstr(config->system_bootloader, ==, "barebox");
	g_assert_cmpstr(config->mount_prefix, ==, "/mnt/myrauc/");
	g_assert_true(config->activate_installed);
	g_assert_cmpstr(config->statusfile_path, ==, "/mnt/persistent-rw-fs/system.raucs");
	g_assert_cmpint(config->max_bundle_download_size, ==, 42);
	g_assert_cmphex(config->bundle_formats_mask, ==, 0x2);
	g_assert_cmpstr(config->store_path, ==, "/var/lib/default.castr/");
	g_assert_cmpstr(config->tmp_path, ==, "/tmp/");
	g_assert_cmpstr(config->casync_install_args, ==, "--verbose");
	g_assert_false(config->use_desync);

	g_assert_nonnull(config->slots);
	slotlist = g_hash_table_get_keys(config->slots);

	slot = g_hash_table_lookup(config->slots, "rescue.0");
	g_assert_cmpstr(slot->name, ==, "rescue.0");
	g_assert_cmpstr(slot->description, ==, "Rescue partition");
	g_assert_cmpstr(slot->device, ==, "/dev/rescue-0");
	g_assert_cmpstr(slot->bootname, ==, "factory0");
	g_assert_cmpstr(slot->type, ==, "raw");
	g_assert_true(slot->readonly);
	g_assert_true(slot->install_same);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_name(config, "rescue.0") == slot);

	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_cmpstr(slot->name, ==, "rootfs.0");
	g_assert_cmpstr(slot->description, ==, "Root filesystem partition 0");
	g_assert_cmpstr(slot->device, ==, "/dev/rootfs-0");
	g_assert_cmpstr(slot->bootname, ==, "system0");
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_null(slot->extra_mkfs_opts);
	g_assert_false(slot->readonly);
	g_assert_false(slot->install_same);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_name(config, "rootfs.0") == slot);

	slot = g_hash_table_lookup(config->slots, "rootfs.1");
	g_assert_cmpstr(slot->name, ==, "rootfs.1");
	g_assert_cmpstr(slot->description, ==, "Root filesystem partition 1");
	g_assert_cmpstr(slot->device, ==, "/dev/rootfs-1");
	g_assert_cmpstr(slot->bootname, ==, "system1");
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_null(slot->extra_mkfs_opts);
	g_assert_false(slot->readonly);
	g_assert_false(slot->install_same);
	g_assert_null(slot->parent);
	g_assert(find_config_slot_by_name(config, "rootfs.1") == slot);

	slot = g_hash_table_lookup(config->slots, "appfs.0");
	g_assert_cmpstr(slot->name, ==, "appfs.0");
	g_assert_cmpstr(slot->description, ==, "Application filesystem partition 0");
	g_assert_cmpstr(slot->device, ==, "/dev/appfs-0");
	g_assert_null(slot->bootname);
	g_assert_cmpstr(slot->type, ==, "ext4");
	g_assert_null(slot->extra_mkfs_opts);
	g_assert_false(slot->readonly);
	g_assert_false(slot->install_same);
	g_assert_nonnull(slot->parent);
	g_assert(find_config_slot_by_name(config, "appfs.0") == slot);

	slot = g_hash_table_lookup(config->slots, "appfs.1");
	g_assert_cmpstr(slot->name, ==, "appfs.1");
	g_assert_cmpstr(slot->description, ==, "Application filesystem partition 1");
	g_assert_cmpstr(slot->device, ==, "/dev/appfs-1");
	g_assert_null(slot->bootname);
	g_assert_cmpstr(slot->type, ==, "ext4");

	g_assert_nonnull(slot->extra_mkfs_opts);
	g_assert_cmpstr(slot->extra_mkfs_opts[0], ==, "-L");
	g_assert_cmpstr(slot->extra_mkfs_opts[1], ==, "mylabel");
	g_assert_cmpstr(slot->extra_mkfs_opts[2], ==, "-i");
	g_assert_cmpstr(slot->extra_mkfs_opts[3], ==, "8192");
	g_assert_null(slot->extra_mkfs_opts[4]);

	g_assert_false(slot->readonly);
	g_assert_false(slot->install_same);
	g_assert_nonnull(slot->parent);
	g_assert(find_config_slot_by_name(config, "appfs.1") == slot);

	g_assert_cmpuint(g_list_length(slotlist), ==, 5);

	g_list_free(slotlist);

	g_assert(find_config_slot_by_device(config, "/dev/xxx0") == NULL);
}

static void config_file_invalid_items(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *unknown_group_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[unknown]\n\
foo=bar\n\
";
	pathname = write_tmp_file(fixture->tmpdir, "unknown_group.conf", unknown_group_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_assert_cmpstr(ierror->message, ==, "Invalid group '[unknown]'");
	g_clear_error(&ierror);

	g_clear_pointer(&pathname, g_free);
	g_clear_pointer(&config, free_config);

	const gchar *unknown_key_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
foo=bar\n\
";
	pathname = write_tmp_file(fixture->tmpdir, "unknown_key.conf", unknown_key_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_assert_cmpstr(ierror->message, ==, "Invalid key 'foo' in group '[system]'");
	g_clear_error(&ierror);

	g_clear_pointer(&pathname, g_free);
	g_clear_pointer(&config, free_config);

	const gchar *unsupported_verify_partial_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
[keyring]\n\
allow-single-signature=true\n\
";
	pathname = write_tmp_file(fixture->tmpdir, "unsupported_verify_partial.conf", unsupported_verify_partial_cfg_file, NULL);
	g_assert_nonnull(pathname);

	if (ENABLE_OPENSSL_VERIFY_PARTIAL) {
		g_assert_true(load_config(pathname, &config, &ierror));
		g_assert_no_error(ierror);
		g_assert_true(config->keyring_allow_single_signature);
	} else {
		g_assert_false(load_config(pathname, &config, &ierror));
		g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
		g_assert_cmpstr(ierror->message, ==, "Keyring section option 'allow-single-signature' is not supported because OpenSSL does not define CMS_VERIFY_PARTIAL");
		g_clear_error(&ierror);
	}
}

static void config_file_bootloaders(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *boot_inval_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=superloader2000\n\
mountprefix=/mnt/myrauc/\n";
	const gchar *boot_missing_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
mountprefix=/mnt/myrauc/\n";

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", boot_inval_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Unsupported bootloader 'superloader2000' selected in system config");
	g_clear_error(&ierror);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", boot_missing_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "No bootloader selected in system config");
	g_clear_error(&ierror);
}

static void config_file_boot_attempts(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *valid_boot_attempts_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
boot-attempts=5\n\
boot-attempts-primary=10\n\
mountprefix=/mnt/myrauc/\n";
	const gchar *invalid_boot_attempts_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
boot-attempts=urks\n\
boot-attempts-primary=10\n\
mountprefix=/mnt/myrauc/\n";
	const gchar *boot_attempts_invalid_bootloader_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=grub\n\
boot-attempts=5\n\
boot-attempts-primary=10\n\
mountprefix=/mnt/myrauc/\n";
	const gchar *negative_boot_attempts_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=uboot\n\
boot-attempts=5\n\
boot-attempts-primary=-10\n\
mountprefix=/mnt/myrauc/\n";

	pathname = write_tmp_file(fixture->tmpdir, "valid_bootloader.conf", valid_boot_attempts_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_true(load_config(pathname, &config, &ierror));
	g_assert_no_error(ierror);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", invalid_boot_attempts_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_clear_error(&ierror);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", boot_attempts_invalid_bootloader_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Configuring boot attempts is valid for uboot or barebox only (not for grub)");
	g_clear_error(&ierror);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", negative_boot_attempts_cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_cmpstr(ierror->message, ==, "Value for \"boot-attempts-primary\" must not be negative");
	g_clear_error(&ierror);
}

static void config_file_slots_invalid_type(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *invalid_slot_type = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
type=oups\n\
\t";

	pathname = write_tmp_file(fixture->tmpdir, "system.conf", invalid_slot_type, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_SLOT_TYPE);
	g_assert_cmpstr(ierror->message, ==, "Unsupported slot type 'oups' for slot rootfs.0 selected in system config");
	g_clear_error(&ierror);
}

static void config_file_invalid_parent(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *nonexisting_parent = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.child.0]\n\
device=/dev/null\n\
parent=invalid\n\
\t";

	pathname = write_tmp_file(fixture->tmpdir, "nonexisting_bootloader.conf", nonexisting_parent, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_PARENT);
	g_assert_cmpstr(ierror->message, ==, "Parent slot 'invalid' not found!");
	g_clear_error(&ierror);
}

static void config_file_parent_has_parent(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	RaucSlot *parentslot;
	RaucSlot *childslot;
	RaucSlot *grandchildslot;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
\n\
[slot.child.0]\n\
device=/dev/null\n\
parent=rootfs.0\n\
\n\
[slot.grandchild.0]\n\
device=/dev/null\n\
parent=child.0\n";

	pathname = write_tmp_file(fixture->tmpdir, "parent_has_parent.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_true(load_config(pathname, &config, NULL));
	g_assert_nonnull(config);

	parentslot = g_hash_table_lookup(config->slots, "rootfs.0");
	childslot = g_hash_table_lookup(config->slots, "child.0");
	g_assert(childslot->parent == parentslot);
	grandchildslot = g_hash_table_lookup(config->slots, "grandchild.0");
	g_assert(grandchildslot->parent == parentslot);
}

static void config_file_parent_loop(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
parent=child.0\n\
\n\
[slot.child.0]\n\
device=/dev/null\n\
parent=rootfs.0\n";

	pathname = write_tmp_file(fixture->tmpdir, "parent_loop.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_PARENT_LOOP);
	g_clear_error(&ierror);
}

static void config_file_bootname_set_on_child(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.parent.0]\n\
device=/dev/null\n\
bootname=slot0\n\
\n\
[slot.child.0]\n\
device=/dev/null\n\
parent=parent.0\n\
bootname=slotchild0\n";

	pathname = write_tmp_file(fixture->tmpdir, "bootname_set_on_child.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_CHILD_HAS_BOOTNAME);
	g_assert_cmpstr(ierror->message, ==, "Child slot 'child.0' has bootname set");
	g_clear_error(&ierror);
}

static void config_file_duplicate_bootname(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
bootname=theslot\n\
\n\
[slot.rootfs.1]\n\
device=/dev/null\n\
bootname=theslot\n";

	pathname = write_tmp_file(fixture->tmpdir, "duplicate_bootname.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_DUPLICATE_BOOTNAME);
	g_assert_cmpstr(ierror->message, ==, "Bootname 'theslot' is set on more than one slot");
	g_clear_error(&ierror);
}

static void config_file_duplicate_slotclass(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
bootname=theslot\n\
\n\
[artifacts.rootfs]\n\
path=/var/artifacts/containers\n\
type=trees\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "duplicate_bootname.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_DUPLICATE_CLASS);
	g_assert_cmpstr(ierror->message, ==, "Existing slot class 'rootfs' cannot be used as artifact repo name!");
	g_clear_error(&ierror);
}

static void config_file_typo(ConfigFileFixture *fixture, const gchar *cfg_file)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	pathname = write_tmp_file(fixture->tmpdir, "typo.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_null(config);
	g_clear_error(&ierror);
}

static void config_file_typo_in_boolean_readonly_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
readonly=typo\n");
}

static void config_file_typo_in_boolean_allow_mounted_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
allow-mounted=typo\n");
}

static void config_file_typo_in_boolean_install_same_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
install-same=typo\n");
}

static void config_file_typo_in_boolean_force_install_same_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
force-install-same=typo\n");
}

static void config_file_typo_in_boolean_ignore_checksum_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/mtd4\n\
type=raw\n\
bootname=factory0\n\
ignore-checksum=typo\n");
}

static void config_file_typo_in_boolean_resize_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
\n\
[slot.rescue.0]\n\
description=Rescue partition\n\
device=/dev/null\n\
type=ext4\n\
resize=typo\n");
}

static void config_file_typo_in_boolean_activate_installed_key(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
activate-installed=typo\n");
}

static void config_file_bootname_tab(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
bootname=the\tslot\n";

	pathname = write_tmp_file(fixture->tmpdir, "bootname_tab.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_assert_cmpstr(ierror->message, ==, "Invalid bootname for slot rootfs.0: The value 'the\tslot' can not contain tab or whitespace characters");
	g_clear_error(&ierror);
}

static void config_file_boot_emmc_with_bootpart(ConfigFileFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *contents = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/mmcblk0boot0\n\
type=boot-emmc\n";

	pathname = write_tmp_file(fixture->tmpdir, "boot-emmc-bootpart.conf", contents, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_DEVICE);
	g_assert_cmpstr(ierror->message, ==, "slot.rootfs.0: 'device' must refer to the eMMC base device, not the boot partition");
	g_clear_error(&ierror);
}

static void config_file_no_max_bundle_download_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n";

	pathname = write_tmp_file(fixture->tmpdir, "no_max_bundle_download_size.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmpuint(config->max_bundle_download_size, ==, DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE);
}

static void config_file_zero_max_bundle_download_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
max-bundle-download-size=0\n";

	pathname = write_tmp_file(fixture->tmpdir, "zero_max_bundle_download_size.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_MAX_BUNDLE_DOWNLOAD_SIZE);
	g_assert_null(config);

	g_clear_error(&ierror);
}

static void config_file_typo_in_uint64_max_bundle_download_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
max-bundle-download-size=no-uint64\n");
}

static void config_file_zero_max_bundle_signature_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
max-bundle-signature-size=0\n";

	pathname = write_tmp_file(fixture->tmpdir, "zero_max_bundle_signature_size.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_MAX_BUNDLE_SIGNATURE_SIZE);
	g_assert_null(config);

	g_clear_error(&ierror);
}

static void config_file_typo_in_uint64_max_bundle_signature_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	config_file_typo(fixture, "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
max-bundle-signature-size=no-uint64\n");
}

static void config_file_activate_installed_set_to_true(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
activate-installed=true\n";

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_true(config->activate_installed);
}

static void config_file_activate_installed_set_to_false(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
activate-installed=false\n";

	pathname = write_tmp_file(fixture->tmpdir, "invalid_bootloader.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_false(config->activate_installed);
}

static void config_file_system_variant(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file_no_variant = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/";

	const gchar *cfg_file_name_variant = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
variant-name=variant-name";

	const gchar *cfg_file_dtb_variant = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
variant-dtb=true";

	const gchar *cfg_file_file_variant = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
variant-file=/path/to/file";

	const gchar *cfg_file_conflicting_variants = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
variant-dtb=true\n\
variant-name=xxx";

	pathname = write_tmp_file(fixture->tmpdir, "no_variant.conf", cfg_file_no_variant, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_free(pathname);
	g_assert_null(ierror);
	g_assert_nonnull(config);
	g_assert_null(config->system_variant);

	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "name_variant.conf", cfg_file_name_variant, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_free(pathname);
	g_assert_null(ierror);
	g_assert_nonnull(config);
	g_assert(config->system_variant_type == R_CONFIG_SYS_VARIANT_NAME);
	g_assert_cmpstr(config->system_variant, ==, "variant-name");

	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "dtb_variant.conf", cfg_file_dtb_variant, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_free(pathname);
	g_assert_null(ierror);
	g_assert_nonnull(config);
	g_assert(config->system_variant_type == R_CONFIG_SYS_VARIANT_DTB);
	g_assert_null(config->system_variant);

	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "file_variant.conf", cfg_file_file_variant, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_free(pathname);
	g_assert_null(ierror);
	g_assert_nonnull(config);
	g_assert(config->system_variant_type == R_CONFIG_SYS_VARIANT_FILE);
	g_assert_cmpstr(config->system_variant, ==, "/path/to/file");

	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "conflict_variant.conf", cfg_file_conflicting_variants, NULL);
	g_assert_nonnull(pathname);

	g_assert_false(load_config(pathname, &config, &ierror));
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_FORMAT);
	g_assert_null(config);
}

static void config_file_no_extra_mount_opts(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;
	RaucSlot *slot = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
activate-installed=false\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n";

	pathname = write_tmp_file(fixture->tmpdir, "extra_mount.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);

	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_nonnull(slot);
	g_assert_cmpstr(slot->extra_mount_opts, ==, NULL);
}

static void config_file_extra_mount_opts(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;
	RaucSlot *slot = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n\
activate-installed=false\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
extra-mount-opts=ro,noatime\n";

	pathname = write_tmp_file(fixture->tmpdir, "extra_mount.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);

	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_nonnull(slot);
	g_assert_cmpstr(slot->extra_mount_opts, ==, "ro,noatime");
}

static void config_file_extra_mkfs_opts(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;
	RaucSlot *slot = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[slot.rootfs.0]\n\
device=/dev/null\n\
type=ext4\n\
extra-mkfs-opts=-L \"my label\" -i 8192\n";

	pathname = write_tmp_file(fixture->tmpdir, "extra_mkfs.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);

	slot = g_hash_table_lookup(config->slots, "rootfs.0");
	g_assert_nonnull(slot);
	g_assert_nonnull(slot->extra_mkfs_opts);
	g_assert_cmpstr(slot->extra_mkfs_opts[0], ==, "-L");
	g_assert_cmpstr(slot->extra_mkfs_opts[1], ==, "my label");
	g_assert_cmpstr(slot->extra_mkfs_opts[2], ==, "-i");
	g_assert_cmpstr(slot->extra_mkfs_opts[3], ==, "8192");
	g_assert_null(slot->extra_mkfs_opts[4]);
}

static void config_file_statusfile_missing(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
mountprefix=/mnt/myrauc/\n";

	pathname = write_tmp_file(fixture->tmpdir, "valid_bootloader.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_nonnull(config->statusfile_path);
	g_assert_cmpstr(config->statusfile_path, ==, "per-slot");
}

static void config_file_keyring_checks(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autofree gchar* pathname = NULL;

	const gchar *simple_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
[keyring]\n\
path=/dev/null\n";
	const gchar *checking_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
[keyring]\n\
path=/dev/null\n\
allow-partial-chain=true\n\
check-crl=true\n\
check-purpose=codesign\n\
allowed-signer-cns=SomeAllowedCN;OtherAllowedCN\n";

	pathname = write_tmp_file(fixture->tmpdir, "simple.conf", simple_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_false(config->keyring_allow_partial_chain);
	g_assert_false(config->keyring_check_crl);
	g_assert_cmpstr(config->keyring_check_purpose, ==, NULL);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "checking.conf", checking_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_true(config->keyring_allow_partial_chain);
	g_assert_true(config->keyring_check_crl);
	g_assert_cmpstr(config->keyring_check_purpose, ==, "codesign-rauc");
	g_assert_cmpint(g_strv_length(config->keyring_allowed_signer_cns), ==, 2);
	g_assert_cmpstr(config->keyring_allowed_signer_cns[0], ==, "SomeAllowedCN");
	g_assert_cmpstr(config->keyring_allowed_signer_cns[1], ==, "OtherAllowedCN");
}

static void config_file_bundle_formats(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res = FALSE;
	g_autofree gchar* pathname = NULL;

	const gchar *default_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n";
	const gchar *set_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
bundle-formats=plain\n";
	const gchar *modify_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
bundle-formats=-plain\n";
	const gchar *none_cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
bundle-formats=-plain -verity -crypt\n";

	pathname = write_tmp_file(fixture->tmpdir, "default.conf", default_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmphex(config->bundle_formats_mask, ==, 0x7);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "set.conf", set_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmphex(config->bundle_formats_mask, ==, 0x1);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "modify.conf", modify_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmphex(config->bundle_formats_mask, ==, 0x6);

	g_free(pathname);
	g_clear_pointer(&config, free_config);

	pathname = write_tmp_file(fixture->tmpdir, "none.conf", none_cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_FORMAT);
	g_assert_cmpstr(ierror->message, ==, "Invalid bundle format configuration '-plain -verity -crypt', no remaining formats");
	g_assert_false(res);
	g_assert_null(config);
	g_clear_error(&ierror);
}

static void config_file_test_parse_bundle_formats(void)
{
	guint mask;
	gboolean res;
	g_autoptr(GError) ierror = NULL;

	mask = 0x0;
	res = parse_bundle_formats(&mask, "plain  verity", &ierror);
	g_assert_no_error(ierror);
	g_assert_cmphex(mask, ==, 0x3);
	g_assert_true(res);

	mask = 0x2;
	res = parse_bundle_formats(&mask, "+plain -verity", &ierror);
	g_assert_no_error(ierror);
	g_assert_cmphex(mask, ==, 0x1);
	g_assert_true(res);

	mask = 0x3;
	res = parse_bundle_formats(&mask, "-verity", &ierror);
	g_assert_no_error(ierror);
	g_assert_cmphex(mask, ==, 0x1);
	g_assert_true(res);

	mask = 0x3;
	res = parse_bundle_formats(&mask, "-verity +verity", &ierror);
	g_assert_no_error(ierror);
	g_assert_cmphex(mask, ==, 0x3);
	g_assert_true(res);

	mask = 0x3;
	res = parse_bundle_formats(&mask, "-verity plain", &ierror);
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_FORMAT);
	g_assert_cmpstr(ierror->message, ==, "Invalid bundle format configuration '-verity plain', cannot combine fixed value with modification (+/-)");
	g_assert_cmphex(mask, ==, 0x3);
	g_assert_false(res);
	g_clear_error(&ierror);

	mask = 0x3;
	res = parse_bundle_formats(&mask, "", &ierror);
	g_assert_no_error(ierror);
	g_assert_cmphex(mask, ==, 0x3);
	g_assert_true(res);

	mask = 0x3;
	res = parse_bundle_formats(&mask, "-verity -plain", &ierror);
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_FORMAT);
	g_assert_cmpstr(ierror->message, ==, "Invalid bundle format configuration '-verity -plain', no remaining formats");
	g_assert_cmphex(mask, ==, 0x3);
	g_assert_false(res);
	g_clear_error(&ierror);
}

static void config_file_use_desync_set_to_true(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[casync]\n\
storepath=/var/lib/default.castr/\n\
tmppath=/tmp/\n\
install-args=--seed /my/path/additional_seed.caibx\n\
use-desync=true";

	pathname = write_tmp_file(fixture->tmpdir, "simple_desync.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmpstr(config->store_path, ==, "/var/lib/default.castr/");
	g_assert_cmpstr(config->tmp_path, ==, "/tmp/");
	g_assert_cmpstr(config->casync_install_args, ==, "--seed /my/path/additional_seed.caibx");
	g_assert_true(config->use_desync);
}

static void config_file_send_headers(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[streaming]\n\
send-headers=boot-id;uptime";

	pathname = write_tmp_file(fixture->tmpdir, "send_headers.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
	g_assert_cmpint(g_strv_length(config->enabled_headers), ==, 2);
}

static void config_file_send_headers_invalid_item(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[streaming]\n\
send-headers=transaction-id;invalid-key";

	pathname = write_tmp_file(fixture->tmpdir, "send_headers.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_assert_false(res);
	g_assert_null(config);
}

/* A logger must at least have a 'filename' set.
 * Test that an empty logger causes a failure */
static void config_file_logger_empty(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "emtpy_logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
	g_assert_false(res);
	g_assert_null(config);
}

/* Test specifying a relative log filename but no data-dir. */
static void config_file_logger_relative_no_datadir(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
filename=test.log\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);
	g_assert_null(config);
}

/* Test specifying a minimal valid logger */
static void config_file_logger_minimal(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
data-directory=anydir\n\
\n\
[log.testlogger]\n\
filename=test.log\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
}

/* Test specifying a full option logger */
static void config_file_logger_full(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
filename=/tmp/test.log\n\
events=boot;install\n\
format=readable\n\
max-size=1M\n\
max-files=8\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);
}

/* Test providing an invalid event type */
static void config_file_logger_invalid_event(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
filename=/tmp/test.log\n\
events=invalid\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);
	g_assert_null(config);
}

/* Test combining 'all' event with another valid event.
 * This must fail since 'all' already includes all events. */
static void config_file_logger_invalid_event_combo(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
filename=/tmp/test.log\n\
events=all;boot\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);
	g_assert_null(config);
}

/* Test with invalid (negative) max-files set. */
static void config_file_logger_invalid_max_size(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
bootloader=barebox\n\
\n\
[log.testlogger]\n\
filename=test.log\n\
max-files=-1\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "emtpy_logger.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);
	g_assert_null(config);
}

/* Test specifying a valid min-bundle-version */
static void config_file_min_bundle_version_good(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
min-bundle-version=2024.05.15-pre+4a5428\n\
bootloader=barebox\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "min_bundle_version.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(config);

	g_assert_cmpstr(config->system_min_bundle_version, ==, "2024.05.15-pre+4a5428");
}

/* Test providing an invalid min-bundle-version */
static void config_file_min_bundle_version_bad(ConfigFileFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) ierror = NULL;
	gboolean res;
	g_autofree gchar* pathname = NULL;

	const gchar *cfg_file = "\
[system]\n\
compatible=FooCorp Super BarBazzer\n\
min-bundle-version=v1.foo.2-baa\n\
bootloader=barebox\n\
";

	pathname = write_tmp_file(fixture->tmpdir, "min_bundle_version.conf", cfg_file, NULL);
	g_assert_nonnull(pathname);

	res = load_config(pathname, &config, &ierror);
	g_assert_error(ierror, R_CONFIG_ERROR, R_CONFIG_ERROR_INVALID_FORMAT);
	g_assert_false(res);
	g_assert_null(config);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/config-file/full-config", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_full_config,
			config_file_fixture_tear_down);
	g_test_add("/config-file/invalid-items", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_invalid_items,
			config_file_fixture_tear_down);
	g_test_add("/config-file/bootloaders", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_bootloaders,
			config_file_fixture_tear_down);
	g_test_add("/config-file/boot_attempts", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_boot_attempts,
			config_file_fixture_tear_down);
	g_test_add("/config-file/slots/invalid_type", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_slots_invalid_type,
			config_file_fixture_tear_down);
	g_test_add("/config-file/invalid-parent", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_invalid_parent,
			config_file_fixture_tear_down);
	g_test_add("/config-file/parent-has-parent", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_parent_has_parent,
			config_file_fixture_tear_down);
	g_test_add("/config-file/parent-loop", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_parent_loop,
			config_file_fixture_tear_down);
	g_test_add("/config-file/bootname-set-on-child", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_bootname_set_on_child,
			config_file_fixture_tear_down);
	g_test_add("/config-file/duplicate-bootname", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_duplicate_bootname,
			config_file_fixture_tear_down);
	g_test_add("/config-file/duplicate-slotclass", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_duplicate_slotclass,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-allow-mounted-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_allow_mounted_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-readonly-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_readonly_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-install-same-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_install_same_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-force-install-same-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_force_install_same_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-ignore-checksum-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_ignore_checksum_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-resize-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_resize_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-boolean-activate-installed-key", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_boolean_activate_installed_key,
			config_file_fixture_tear_down);
	g_test_add("/config-file/bootname-tab", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_bootname_tab,
			config_file_fixture_tear_down);
	g_test_add("/config-file/boot-emmc-with-bootpart", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_boot_emmc_with_bootpart,
			config_file_fixture_tear_down);
	g_test_add("/config-file/no-max-bundle-download-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_no_max_bundle_download_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/zero-max-bundle-download-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_zero_max_bundle_download_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-uint64-max-bundle-download-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_uint64_max_bundle_download_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/zero-max-bundle-signature-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_zero_max_bundle_signature_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/typo-in-uint64-max-bundle-signature-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_typo_in_uint64_max_bundle_signature_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/activate-installed-key-set-to-true", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_activate_installed_set_to_true,
			config_file_fixture_tear_down);
	g_test_add("/config-file/activate-installed-key-set-to-false", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_activate_installed_set_to_false,
			config_file_fixture_tear_down);
	g_test_add("/config-file/system-variant", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_system_variant,
			config_file_fixture_tear_down);
	g_test_add("/config-file/no-extra-mount-opts", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_no_extra_mount_opts,
			config_file_fixture_tear_down);
	g_test_add("/config-file/extra-mount-opts", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_extra_mount_opts,
			config_file_fixture_tear_down);
	g_test_add("/config-file/extra-mkfs-opts", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_extra_mkfs_opts,
			config_file_fixture_tear_down);
	g_test_add("/config-file/statusfile-missing", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_statusfile_missing,
			config_file_fixture_tear_down);
	g_test_add("/config-file/keyring-checks", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_keyring_checks,
			config_file_fixture_tear_down);
	g_test_add("/config-file/bundle-formats", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_bundle_formats,
			config_file_fixture_tear_down);
	g_test_add_func("/config-file/parse-bundle-formats", config_file_test_parse_bundle_formats);
	g_test_add("/config-file/use-desync", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_use_desync_set_to_true,
			config_file_fixture_tear_down);
	g_test_add("/config-file/send-headers", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_send_headers,
			config_file_fixture_tear_down);
	g_test_add("/config-file/send-headers-invalid-value", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_send_headers_invalid_item,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/empty", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_empty,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/relativ-no-datadir", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_relative_no_datadir,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/minimal", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_minimal,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/full", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_full,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/invalid-event", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_invalid_event,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/invalid-event-combo", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_invalid_event_combo,
			config_file_fixture_tear_down);
	g_test_add("/config-file/logger/invalid-max-size", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_logger_invalid_max_size,
			config_file_fixture_tear_down);
	g_test_add("/config-file/min-bundle-version/good", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_min_bundle_version_good,
			config_file_fixture_tear_down);
	g_test_add("/config-file/min-bundle-version/bad", ConfigFileFixture, NULL,
			config_file_fixture_set_up, config_file_min_bundle_version_bad,
			config_file_fixture_tear_down);
	return g_test_run();
}
