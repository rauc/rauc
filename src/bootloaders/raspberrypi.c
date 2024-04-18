#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>

#include "bootchooser.h"
#include "context.h"
#include "raspberrypi.h"
#include "utils.h"

#define RASPBERRYPI_VCMAILBOX "vcmailbox"

static int r_rename(const gchar *oldfilename, const char *newfilename)
{
	int res;

	/* Try to exchange files... */
	res = renameat2(AT_FDCWD, oldfilename, AT_FDCWD, newfilename, RENAME_EXCHANGE);
	if (res == 0) {
		/* ... and remove old file. */
		if (g_remove(oldfilename) == -1) {
			int err = errno;
			g_warning("Failed to remove file %s: %s", oldfilename, g_strerror(err));
		}

		return 0;
	}

	/* ... or, try to replace file if filesystem does not support exchange. */
	if (res == -1 && errno == EINVAL)
		res = renameat2(AT_FDCWD, oldfilename, AT_FDCWD, newfilename, 0);

	return res;
}

static RaucSlot *raspberrypi_find_config_slot_by_bootloader_partition(RaucConfig *config, gint partition)
{
	g_autofree gchar *name = g_strdup_printf("%u", partition);
	return find_config_slot_by_bootname(config, name);
}

static RaucSlot *raspberrypi_find_config_slot_by_reboot_flag(RaucConfig *config, gboolean tryboot)
{
	g_autoptr(GKeyFile) key_file = NULL;
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *data = NULL;
	const gchar *group_name = tryboot ? "tryboot" : "all";
	const gchar *boot_partition;
	const gchar *filename;
	gsize length;

	filename = r_context()->config->raspberrypi_autoboottxt_path;
	if (!g_file_get_contents(filename, &data, &length, &ierror)) {
		g_warning("Failed to read %s: %s", filename, ierror->message);
		return NULL;
	}

	key_file = g_key_file_new();
	if (!g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, &ierror)) {
		g_warning("Failed to load %s: %s", filename, ierror->message);
		return NULL;
	}

        boot_partition = g_key_file_get_string(key_file, group_name, "boot_partition", &ierror);
        if (!boot_partition || (boot_partition[0] == '\0')) {
		g_warning("Failed to get 'boot_partition' in '%s': %s", group_name, ierror->message);
                return NULL;
        }

	return find_config_slot_by_bootname(config, boot_partition);
}

static gboolean raspberrypi_bootloader_get(const gchar *property, guint *value, GError **error)
{
	g_auto(filedesc) fd = -1;
	g_autofree gchar *filename = NULL;
	guint32 val;

	g_return_val_if_fail(property, FALSE);
	g_return_val_if_fail(value, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	filename = g_build_filename("/sys/firmware/devicetree/base/chosen/bootloader", property, NULL);
	fd = g_open(filename, O_RDONLY);
	if (fd < 0) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Failed to open file: %s", filename);
		return FALSE;
	}

	if (read(fd, &val, sizeof(val)) != sizeof(val)) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Failed to read integer from file: %s", filename);
		return FALSE;
	}

	*value = g_htonl(val);

	return TRUE;
}

static gboolean raspberrypi_bootloader_get_partition(guint *partition, GError **error)
{
	return raspberrypi_bootloader_get("partition", partition, error);
}

static gboolean raspberrypi_bootloader_get_tryboot(gboolean *tryboot, GError **error)
{
	guint value;

	if (!raspberrypi_bootloader_get("tryboot", &value, error))
		return FALSE;

	*tryboot = value ? TRUE : FALSE;

	return TRUE;
}

static gboolean raspberrypi_get_reboot_flag(gboolean *enabled, GError **error)
{
	g_autoptr(GBytes) stdout_bytes = NULL;
	g_autoptr(GSubprocess) sub = NULL;
	g_autofree gchar *stdout_str = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(enabled, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/*
	 * The tag Get Reboot Flags is undocumented.
	 * https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
	 *
	 * However, it is defined by the raspberrypi-linux firmware driver:
	 * https://github.com/raspberrypi/linux/commit/e2726f05782135e15537575e95faea46c40a88a2
	 */
	sub = r_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror, RASPBERRYPI_VCMAILBOX,
			"0x00030064", "4", "0", "0", NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " RASPBERRYPI_VCMAILBOX ": ");
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " RASPBERRYPI_VCMAILBOX ": ");
		return FALSE;
	}

	/*
	 * Parse output.
	 *
	 * If the reboot flag is unset:
	 *
	 * 	$ vcmailbox 0x00030064 4 0 0
	 * 	0x0000001c 0x80000000 0x00030064 0x00000004 0x80000004 0x00000000 0x00000000
	 *
	 * If the reboot flag is set:
	 *
	 * 	$ vcmailbox 0x00030064 4 0 0
	 * 	0x0000001c 0x80000000 0x00030064 0x00000004 0x80000004 0x00000001 0x00000000
	 */
	stdout_str = r_bytes_unref_to_string(&stdout_bytes);
	if (stdout_str) {
		g_auto(GStrv) words = g_strsplit(stdout_str, " ", -1);
		if (g_strv_length(words) > 5) {
			guint32 value = (guint32)g_ascii_strtoull(words[5], NULL, 0);
			*enabled = value == 0 ? FALSE : TRUE;
			return TRUE;
		}
	}

	g_set_error(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"Failed to parse " RASPBERRYPI_VCMAILBOX ": %s", stdout_str);
	return FALSE;
}

static gboolean raspberrypi_set_reboot_flag(gboolean enable, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/*
	 * The tag Set Reboot Flags is undocumented.
	 * https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
	 *
	 * However, it is used by the raspberrypi-linux firmware driver:
	 * https://github.com/raspberrypi/linux/commit/777a6a08bcf8f5f0a0086358dc66d
	 */
	sub = r_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, RASPBERRYPI_VCMAILBOX,
			"0x00038064", "4", "0", enable ? "1" : "0", NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " RASPBERRYPI_VCMAILBOX ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " RASPBERRYPI_VCMAILBOX ": ");
		return FALSE;
	}

	return TRUE;
}

static RaucSlot *raspberrypi_get_booted(GError **error)
{
	RaucSlot *booted;
	GError *ierror = NULL;
	guint partition;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!raspberrypi_bootloader_get_partition(&partition, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader partition property: ");
		return NULL;
	}

	booted = raspberrypi_find_config_slot_by_bootloader_partition(r_context()->config, partition);
	if (!booted) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"No slot found with partition %i", partition);
		return NULL;
	}

	return booted;
}

/* Write the autoboot.txt using the other bootname as the boot_partition in the
 * [all] section, and the primary bootname as the boot_partition in the
 * [tryboot] section. */
static gboolean raspberrypi_set_other_persistent(RaucSlot *primary, RaucSlot *other, GError **error)
{
	g_auto(filedesc) fd = -1;
	g_autofree gchar *data = NULL;
	g_autofree gchar *filename_tmp = NULL;
	gchar *filename;
	gsize size;

	g_return_val_if_fail(primary != other, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	filename = r_context()->config->raspberrypi_autoboottxt_path;
	filename_tmp = g_strdup_printf("%s.tmp", filename);

	fd = g_open(filename_tmp, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open file %s: %s", filename_tmp, g_strerror(err));
		return FALSE;
	}

	data = g_strdup_printf("[all]\ntryboot_a_b=1\nboot_partition=%s\n[tryboot]\nboot_partition=%s\n",
			other->bootname, primary->bootname);
	size = strlen(data);
	if (write(fd, data, size) != (gssize)size) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to write file %s: %s", filename_tmp, g_strerror(err));
		return FALSE;
	}

	if (fsync(fd) == -1) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to sync file %s: %s", filename_tmp, g_strerror(err));
		return FALSE;
	}

	if (r_rename(filename_tmp, filename) == -1) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to rename %s to %s: %s", filename_tmp, filename, g_strerror(err));
		return FALSE;
	}

	return TRUE;
}

static RaucSlot *raspberrypi_get_primary_and_reboot_flag(gboolean *reboot, GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;

	g_return_val_if_fail(reboot, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!raspberrypi_get_reboot_flag(reboot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get reboot flag: ");
		return NULL;
	}

	primary = raspberrypi_find_config_slot_by_reboot_flag(r_context()->config, *reboot);
	if (!primary) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"No slot found");
		return NULL;
	}

	return primary;
}

/* Get booted bootname */
gchar *r_raspberrypi_get_bootname(RaucConfig *config, GError **error)
{
	GError *ierror = NULL;
	guint partition;

	if (!raspberrypi_bootloader_get_partition(&partition, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader partition property: ");
		return NULL;
	}

	return g_strdup_printf("%u", partition);
}

/* Get slot marked as primary one, i.e. the slot with boot_partition set in the
 * section [all] in the file autoboot.txt if the reboot flag is unset, or the
 * slot with boot_partition set in the section [tryboot] in the file
 * autoboot.txt if the reboot flag is set. */
RaucSlot *r_raspberrypi_get_primary(GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;
	gboolean reboot;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	primary = raspberrypi_get_primary_and_reboot_flag(&reboot, &ierror);
	if (!primary) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get primary slot and reboot flag: ");
		return NULL;
	}

	if (reboot)
		g_debug("Detected reboot flag");

	return primary;
}

/* Set slot as primary boot slot, i.e. either persistently in the static file
 * autoboot.txt if it is the booted slot or temporarily via the tryboot reboot
 * flag otherwise. */
gboolean r_raspberrypi_set_primary(RaucSlot *slot, GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;
	gboolean reboot;

	primary = raspberrypi_get_primary_and_reboot_flag(&reboot, &ierror);
	if (!primary) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get primary slot and reboot flag: ");
		return FALSE;
	}

	/* The slot is already the primary slot, do nothing. */
	if (slot == primary)
		return TRUE;

	/* The slot is already already the primary slot in autoboot.txt (the
	 * reboot flag is set), clear the reboot flag. */
	if (reboot) {
		if (!raspberrypi_set_reboot_flag(FALSE, error)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to set reboot flag: ");
			return FALSE;
		}

		g_debug("Reboot flag cleared");
		return TRUE;
	}

	/* The slot is not yet the primary slot in autoboot.txt (the reboot
	 * flag is unset), set the reboot flag. */
	if (!raspberrypi_set_reboot_flag(TRUE, error)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to set reboot flag: ");
		return FALSE;
	}


	g_debug("Reboot flag set");
	return TRUE;
}

/* We assume bootstate to be good if the slot is the booted slot. */
gboolean r_raspberrypi_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	RaucSlot *booted;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	booted = raspberrypi_get_booted(&ierror);
	if (!booted) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get booted slot: ");
		return FALSE;
	}

	*good = (booted == slot) ? TRUE : FALSE;

	return TRUE;
}

/* We assume to set bootstate persistently in autoboot.txt if the slot is good
 * and it is not the primary slot, and if booted using tryboot. */
gboolean r_raspberrypi_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;
	gboolean reboot;
	gboolean tryboot;

	primary = raspberrypi_get_primary_and_reboot_flag(&reboot, &ierror);
	if (!primary) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get primary slot and reboot flag: ");
		return FALSE;
	}

	/* The slot is bad, do nothing */
	if (!good)
		return TRUE;

	if (!raspberrypi_bootloader_get_tryboot(&tryboot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader tryboot property: ");
	}

	/* The tryboot is unset, do nothing */
	if (!tryboot)
		return TRUE;

	g_debug("Detected tryboot boot");

	/* The reboot flag is set, do nothing */
	if (reboot) {
		g_debug("Detected reboot flag");
		return TRUE;
	}

	/* The slot is not yet the primary slot, update autoboot.txt */
	if (slot != primary) {
		if (!raspberrypi_set_other_persistent(primary, slot, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to set other persistent: ");
			return FALSE;
		}
		g_debug("File autoboot.txt updated");
	}

	return TRUE;
}
