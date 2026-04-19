#include "systemd-boot.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define BOOTCTL_NAME "bootctl"

/* Run "bootctl status --no-pager" and return the id of the default boot entry.
 *
 * @default_id: (out) allocated string with the entry id (must be NULL on entry)
 * @error: (out) error
 */
static gboolean systemdboot_get_default_entry(gchar **default_id, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(default_id && *default_id == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE,
			&ierror,
			BOOTCTL_NAME, "status", "--no-pager", NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BOOTCTL_NAME ": ");
		return FALSE;
	}

	g_autoptr(GBytes) sub_stdout_buf = NULL;
	if (!g_subprocess_communicate(sub, NULL, NULL, &sub_stdout_buf, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BOOTCTL_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				BOOTCTL_NAME " did not exit normally");
		return FALSE;
	}

	gint ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				BOOTCTL_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	/* Parse output for the default entry id. We look for a line containing
	 * "id: <entry>" within the "Default Boot Loader Entry:" section. */
	const gchar *sub_stdout = g_bytes_get_data(sub_stdout_buf, NULL);
	if (sub_stdout) {
		g_auto(GStrv) lines = g_strsplit(sub_stdout, "\n", -1);
		gboolean in_default_section = FALSE;
		for (gchar **line = lines; *line; line++) {
			if (g_str_has_prefix(*line, "Default Boot Loader Entry:")) {
				in_default_section = TRUE;
				continue;
			}
			/* A new non-indented section ends the default entry block */
			if (in_default_section && (*line)[0] != ' ' && (*line)[0] != '\t' && (*line)[0] != '\0') {
				in_default_section = FALSE;
			}
			if (in_default_section) {
				const gchar *id_prefix = "id: ";
				gchar *id_pos = strstr(*line, id_prefix);
				if (id_pos) {
					g_autofree gchar *id = g_strdup(id_pos + strlen(id_prefix));
					g_strchomp(id);

					/* A '+' in the entry id means Automatic Boot Assessment
					 * (https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/) is active.
					 * RAUC's systemd-boot backend is incompatible with boot
					 * counting: the dynamic filename suffix breaks bootname
					 * matching and slot detection.  Refuse to proceed and ask
					 * the user to disable boot assessment. */
					if (strchr(id, '+')) {
						g_set_error(
								error,
								R_BOOTCHOOSER_ERROR,
								R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
								"Automatic Boot Assessment is active (entry id '%s' "
								"contains a boot-counting suffix). "
								"Disable boot assessment (remove '+N' suffixes from "
								"entry filenames) before using the systemd-boot "
								"bootchooser backend.", id);
						return FALSE;
					}

					*default_id = g_steal_pointer(&id);
					return TRUE;
				}
			}
		}
	}

	g_set_error_literal(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"Could not determine default boot entry from " BOOTCTL_NAME " output");
	return FALSE;
}

/* systemd-boot does not track a per-entry good/bad state.
 * Boot Assessment (https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/) is
 * explicitly unsupported by this backend (get_primary() will refuse to
 * proceed if a boot-counting suffix is detected), so every configured entry
 * is unconditionally considered good. */
gboolean r_systemdboot_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Function must not be called for slots without a bootname! */
	g_assert_nonnull(slot->bootname);

	g_debug("systemd-boot: slot %s (%s) state assumed good", slot->name, slot->bootname);
	*good = TRUE;

	return TRUE;
}

/* Mark a slot as good by confirming it as the default boot entry.
 * Marking a slot as bad is not supported; systemd-boot has no failed-entry
 * concept when Automatic Boot Assessment is disabled. */
gboolean r_systemdboot_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!good) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
				"systemd-boot does not support marking a slot as bad");
		return FALSE;
	}

	/* Confirm this slot is the ongoing default */
	return r_systemdboot_set_primary(slot, error);
}

RaucSlot *r_systemdboot_get_primary(GError **error)
{
	g_autofree gchar *default_id = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!systemdboot_get_default_entry(&default_id, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_debug("systemd-boot: default boot entry id: %s", default_id);

	/* Find the slot whose bootname matches the default entry id */
	GHashTableIter iter;
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	RaucSlot *slot;
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &slot)) {
		if (!slot->bootname)
			continue;
		if (g_strcmp0(slot->bootname, default_id) == 0)
			return slot;
	}

	g_set_error(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"No configured slot matches default boot entry '%s'", default_id);
	return NULL;
}

gboolean r_systemdboot_set_primary(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_message("systemd-boot: setting slot %s (%s) as default boot entry",
			slot->name, slot->bootname);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			BOOTCTL_NAME, "set-default", slot->bootname, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BOOTCTL_NAME ": ");
		return FALSE;
	}
	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BOOTCTL_NAME ": ");
		return FALSE;
	}

	return TRUE;
}
