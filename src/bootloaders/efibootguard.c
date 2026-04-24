#include "efibootguard.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define BG_PRINTENV_NAME "bg_printenv"
#define BG_SETENV_NAME   "bg_setenv"

/* Fetch a variable from efibootguard environment for a slot.
 *
 * @slot: bootname of the slot
 * @key: variable to fetch
 * @value: (out) string value (allocated, must be NULL on entry)
 * @error: (out) error
 */
static gboolean efibootguard_env_get(const gchar *slot, const gchar *key, GString **value, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GPtrArray) sub_args = g_ptr_array_new_full(5, g_free);
	g_ptr_array_add(sub_args, g_strdup(BG_PRINTENV_NAME));
	g_ptr_array_add(sub_args, g_strdup("--raw"));
	g_ptr_array_add(sub_args, g_strdup("-p"));
	g_ptr_array_add(sub_args, g_strdup(slot));
	g_ptr_array_add(sub_args, NULL);

	g_autoptr(GSubprocess) sub = r_subprocess_newv(
			sub_args,
			G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE,
			&ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BG_PRINTENV_NAME ": ");
		return FALSE;
	}

	g_autoptr(GBytes) sub_stdout_buf = NULL;
	if (!g_subprocess_communicate(sub, NULL, NULL, &sub_stdout_buf, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BG_PRINTENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				BG_PRINTENV_NAME " did not exit normally");
		return FALSE;
	}

	gint ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				BG_PRINTENV_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	const gchar *sub_stdout = g_bytes_get_data(sub_stdout_buf, NULL);
	if (sub_stdout) {
		g_autofree gchar *key_prefix = g_strdup_printf("%s=", key);
		g_auto(GStrv) variables = g_strsplit(sub_stdout, "\n", -1);
		for (gchar **variable = variables; *variable; variable++) {
			if (g_str_has_prefix(*variable, key_prefix)) {
				gsize offset = strlen(key_prefix);
				gsize size = strlen(*variable);
				*value = g_string_new_len(*variable + offset, size - offset);
				g_strchomp((*value)->str);
				return TRUE;
			}
		}
	}

	g_set_error(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"Variable %s not set in efibootguard environment", key);
	return FALSE;
}

/* Fetch a variable from efibootguard environment for a slot and parse it as an integer.
 *
 * @slot: bootname of the slot
 * @key: variable name
 * @value_num: (out) integer value
 * @error: (out) error
 */
static gboolean efibootguard_env_get_int(const gchar *slot, const gchar *key, guint64 *value_num, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GString) value = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value_num, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efibootguard_env_get(slot, key, &value, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (!value->len) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Variable is empty");
		return FALSE;
	}
	*value_num = g_ascii_strtoull(value->str, NULL, 10);
	return TRUE;
}

gboolean r_efibootguard_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_message("efibootguard: setting slot %s state to %s", slot->name, good ? "OK" : "FAILED");

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			BG_SETENV_NAME,
			"-p", slot->bootname,
			"-s", good ? "OK" : "FAILED",
			NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BG_SETENV_NAME ": ");
		return FALSE;
	}
	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BG_SETENV_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

RaucSlot *r_efibootguard_get_primary(GError **error)
{
	RaucSlot *primary = NULL;
	gboolean primary_found = FALSE;
	guint64 highest_revision = 0;
	GHashTableIter iter;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);

	RaucSlot *slot;
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &slot)) {
		guint64 slot_revision, slot_ustate;

		if (!slot->bootname)
			continue;
		if (!efibootguard_env_get_int(slot->bootname, "REVISION", &slot_revision, &ierror)) {
			g_propagate_error(error, ierror);
			return NULL;
		}
		if (!efibootguard_env_get_int(slot->bootname, "USTATE", &slot_ustate, &ierror)) {
			g_propagate_error(error, ierror);
			return NULL;
		}
		g_debug("efibootguard: slot %s revision=%" G_GUINT64_FORMAT ", ustate=%" G_GUINT64_FORMAT,
				slot->name, slot_revision, slot_ustate);
		if (slot_ustate != 3 && (!primary_found || slot_revision > highest_revision)) {
			highest_revision = slot_revision;
			primary_found = TRUE;
			primary = slot;
		}
	}

	if (!primary) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Cannot find slot matching any configured bootname");
	}

	return primary;
}

gboolean r_efibootguard_set_primary(RaucSlot *slot, GError **error)
{
	guint64 highest_revision = 0;
	GHashTableIter iter;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);

	RaucSlot *slot_iter;
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &slot_iter)) {
		guint64 slot_revision;

		if (!slot_iter->bootname)
			continue;
		if (g_strcmp0(slot_iter->bootname, slot->bootname) == 0)
			continue;
		if (!efibootguard_env_get_int(slot_iter->bootname, "REVISION", &slot_revision, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		g_debug("efibootguard: slot %s revision=%" G_GUINT64_FORMAT, slot_iter->name, slot_revision);
		if (slot_revision > highest_revision)
			highest_revision = slot_revision;
	}

	guint64 bg_revision = highest_revision + 1;
	g_autofree gchar *bg_revision_str = g_strdup_printf("%" G_GUINT64_FORMAT, bg_revision);
	g_message("efibootguard: setting slot %s state to INSTALLED, revision to %" G_GUINT64_FORMAT,
			slot->name, bg_revision);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			BG_SETENV_NAME,
			"-p", slot->bootname,
			"-s", "INSTALLED",
			"-r", bg_revision_str,
			NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BG_SETENV_NAME ": ");
		return FALSE;
	}
	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BG_SETENV_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

gboolean r_efibootguard_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	GError *ierror = NULL;
	guint64 slot_ustate;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Function must not be called for slots without a bootname! */
	g_assert_nonnull(slot->bootname);

	if (!efibootguard_env_get_int(slot->bootname, "USTATE", &slot_ustate, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_debug("efibootguard: slot %s ustate=%" G_GUINT64_FORMAT, slot->name, slot_ustate);
	*good = (slot_ustate != 3);

	return TRUE;
}
