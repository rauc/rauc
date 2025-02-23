#include "grub.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define GRUB_EDITENV "grub-editenv"

static gboolean grub_env_get(const gchar *key, GString **value, GError **error)
{
	g_autoptr(GPtrArray) sub_args = NULL;
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) stdout_bytes = NULL;
	g_autofree gchar *stdout_str = NULL;
	gsize offset;
	gsize size;
	gint ret;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub_args = g_ptr_array_new_full(4, g_free);
	g_ptr_array_add(sub_args, g_strdup(GRUB_EDITENV));
	if (r_context()->config->grubenv_path) {
		g_ptr_array_add(sub_args, g_strdup(r_context()->config->grubenv_path));
	}
	g_ptr_array_add(sub_args, g_strdup("list"));
	g_ptr_array_add(sub_args, NULL);

	sub = r_subprocess_newv(sub_args, G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " GRUB_EDITENV ": ");
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " GRUB_EDITENV ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				GRUB_EDITENV " did not exit normally");
		return FALSE;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				GRUB_EDITENV " failed with exit code: %i", ret);
		return FALSE;
	}

	/* Call to grub-editenv lists all variables */
	stdout_str = r_bytes_unref_to_string(&stdout_bytes);
	if (stdout_str) {
		g_autofree gchar *key_prefix = g_strdup_printf("%s=", key);
		g_auto(GStrv) variables = g_strsplit(stdout_str, "\n", -1);
		for (gchar **variable = variables; *variable; variable++) {
			if (!g_str_has_prefix(*variable, key_prefix)) {
				continue;
			}

			offset = strlen(key_prefix);
			size = strlen(*variable);
			*value = g_string_new_len(*variable + offset, size - offset);
			g_strchomp((*value)->str);
			return TRUE;
		}
	}

	/* Environment variable with specified key not found */
	g_set_error(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"Variable %s not set in grub environment", key);
	return FALSE;
}

static gboolean grub_env_set(GPtrArray *pairs, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(pairs, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_cmpuint(pairs->len, >, 0);
	g_assert_nonnull(r_context()->config->grubenv_path);

	g_ptr_array_insert(pairs, 0, g_strdup(GRUB_EDITENV));
	g_ptr_array_insert(pairs, 1, g_strdup(r_context()->config->grubenv_path));
	g_ptr_array_insert(pairs, 2, g_strdup("set"));
	g_ptr_array_add(pairs, NULL);

	sub = r_subprocess_newv(pairs, G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " GRUB_EDITENV ": ");
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " GRUB_EDITENV ": ");
		goto out;
	}

out:
	g_ptr_array_remove_index(pairs, pairs->len-1);
	g_ptr_array_remove_index(pairs, 2);
	g_ptr_array_remove_index(pairs, 1);
	g_ptr_array_remove_index(pairs, 0);
	return res;
}

/* We assume bootstate to be good if slot is listed in 'ORDER', its
 * _TRY=0 and _OK=1 */
gboolean r_grub_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	g_autoptr(GString) order = NULL;
	g_autoptr(GString) slot_ok = NULL;
	g_autoptr(GString) slot_try = NULL;
	g_auto(GStrv) bootnames = NULL;
	g_autofree gchar *key = NULL;
	GError *ierror = NULL;
	gboolean found = FALSE;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(slot->bootname, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!grub_env_get("ORDER", &order, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Scan boot order list for given slot */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		if (g_strcmp0(*bootname, slot->bootname) == 0) {
			found = TRUE;
			break;
		}
	}
	if (!found) {
		*good = FALSE;
		return TRUE;
	}

	/* Check slot state */
	key = g_strdup_printf("%s_OK", slot->bootname);
	if (!grub_env_get(key, &slot_ok, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_free(key);
	key = g_strdup_printf("%s_TRY", slot->bootname);
	if (!grub_env_get(key, &slot_try, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	*good = (g_ascii_strtoull(slot_ok->str, NULL, 0) == 1) && (g_ascii_strtoull(slot_try->str, NULL, 0) == 0);

	return TRUE;
}

/* Set slot status values */
gboolean r_grub_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(6, g_free);
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(slot->bootname, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (good) {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=1", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	} else {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=0", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	}

	if (!grub_env_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* Get slot marked as primary one */
RaucSlot *r_grub_get_primary(GError **error)
{
	g_autoptr(GString) order = NULL;
	g_auto(GStrv) bootnames = NULL;
	GError *ierror = NULL;
	RaucSlot *primary = NULL;
	RaucSlot *slot = NULL;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!grub_env_get("ORDER", &order, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	if (!order->len) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Variable ORDER is empty");
		return NULL;
	}

	/* Iterate over current boot order */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* Find matching slot entry */
		g_hash_table_iter_init(&iter, r_context()->config->slots);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
			g_autofree gchar *key = NULL;
			g_autoptr(GString) slot_ok = NULL;
			g_autoptr(GString) slot_try = NULL;

			if (g_strcmp0(*bootname, slot->bootname) != 0) {
				continue;
			}

			/* Check slot state */
			key = g_strdup_printf("%s_OK", slot->bootname);
			if (!grub_env_get(key, &slot_ok, &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			g_free(key);
			key = g_strdup_printf("%s_TRY", slot->bootname);
			if (!grub_env_get(key, &slot_try, &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}

			if ((g_ascii_strtoull(slot_ok->str, NULL, 0) != 1) || (g_ascii_strtoull(slot_try->str, NULL, 0) > 0)) {
				continue;
			}

			primary = slot;
			break;
		}

		if (primary) {
			break;
		}
	}

	if (!primary) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"No bootable slot found in ORDER '%s'", order->str);
	}

	return primary;
}

/* Set slot as primary boot slot */
gboolean r_grub_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(7, g_free);
	g_autoptr(GString) order = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	order = r_bootchooser_order_primary(slot);

	g_ptr_array_add(pairs, g_strdup_printf("%s_OK=%i", slot->bootname, 1));
	g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=%i", slot->bootname, 0));
	g_ptr_array_add(pairs, g_strdup_printf("ORDER=%s", order->str));

	if (!grub_env_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
