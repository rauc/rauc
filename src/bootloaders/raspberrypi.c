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

static RaucSlot *raspberrypi_find_config_slot_by_boot_partition(RaucConfig *config, gint partition)
{
	g_autofree gchar *name = g_strdup_printf("%u", partition);
	return find_config_slot_by_bootname(config, name);
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

static gboolean raspberrypi_tryboot_set(gboolean enable, GError **error)
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
 * section [all] in the file autoboot.txt */
RaucSlot *r_raspberrypi_get_primary(GError **error)
{
	g_autoptr(GList) slots = NULL;
	RaucSlot *booted;
	GError *ierror = NULL;
	gboolean tryboot;
	guint partition;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!raspberrypi_bootloader_get_partition(&partition, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader partition property: ");
		return NULL;
	}

	if (!raspberrypi_bootloader_get_tryboot(&tryboot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader tryboot property: ");
		return NULL;
	}

	booted = raspberrypi_find_config_slot_by_boot_partition(r_context()->config, partition);
	if (!booted) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"No slot found with partition %i", partition);
		return NULL;
	}

	if (!tryboot)
		return booted;

	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		if (s == booted)
			continue;
		if (!s->bootname)
			continue;

		return s;
	}

	g_set_error_literal(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"No slot found");
	return NULL;
}

/* Set the oneshot reboot flag to cause the firmware to run tryboot at next
 * reboot.
 *
 * The firmware uses the boot_partition defined in the [tryboot] section and it
 * loads the alternate configuration file tryboot.txt instead of config.txt at
 * next boot. */
static gboolean raspberrypi_set_other_temporary(GError **error)
{
	GError *ierror = NULL;

	if (!raspberrypi_tryboot_set(TRUE, error)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to set reboot flag: ");
		return FALSE;
	}

	return TRUE;
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

/* Set slot as primary boot slot, i.e. either persistently in the static file
 * autoboot.txt if it is the boot'ed slot or temporarily via the tryboot reboot
 * flag otherwise. */
gboolean r_raspberrypi_set_primary(RaucSlot *slot, GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;
	gboolean tryboot;

	primary = r_raspberrypi_get_primary(&ierror);
	if (!primary) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get primary: ");
		return FALSE;
	}

	if (slot == primary)
		return TRUE;

	if (!raspberrypi_bootloader_get_tryboot(&tryboot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader tryboot property: ");
		return FALSE;
	}

	if (!tryboot) {
		if (!raspberrypi_set_other_temporary(&ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to set other temporary: ");
			return FALSE;
		}

		return TRUE;
	}

	if (!raspberrypi_set_other_persistent(primary, slot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to set other persistent: ");
		return FALSE;
	}

	return TRUE;
}

/* We assume bootstate to be good if the slot is the booted slot or if the slot
 * is not the booted slot and the reboot flag is set; we assume bootstate to be
 * bad otherwise */
gboolean r_raspberrypi_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	RaucSlot *booted;
	GError *ierror = NULL;
	gboolean tryboot;
	guint partition;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!raspberrypi_bootloader_get_partition(&partition, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader partition property: ");
		return FALSE;
	}

	if (!raspberrypi_bootloader_get_tryboot(&tryboot, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get bootloader tryboot property: ");
		return FALSE;
	}

	booted = raspberrypi_find_config_slot_by_boot_partition(r_context()->config, partition);
	if (!booted) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"No slot found with partition %i", partition);
		return FALSE;
	}

	*good = (booted == slot || tryboot) ? TRUE : FALSE;

	return TRUE;
}

/* Set slot status values */
gboolean r_raspberrypi_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	RaucSlot *primary;
	GError *ierror = NULL;

	primary = r_raspberrypi_get_primary(&ierror);
	if (!primary) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get primary: ");
		return FALSE;
	}

	if ((slot != primary && good) || (slot == primary && !good)) {
		if (!raspberrypi_set_other_persistent(primary, slot, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed to set other persistent: ");
			return FALSE;
		}
	}

	return TRUE;
}
