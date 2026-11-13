#include <errno.h>

#include "fwu.h"
#include "bootchooser.h"
#include "context.h"
#include "uboot.h"

static gboolean fwu_env_get(const gchar *key, GString **value, GError **error)
{
	const gchar *opts[] = {"-m", r_context()->config->fwu_namespace, NULL};

	return r_uboot_env_get_opts(opts, key, value, error);
}

static gboolean fwu_env_set(GPtrArray *pairs, GError **error)
{
	const gchar *opts[] = {"-m", r_context()->config->fwu_namespace, NULL};

	return r_uboot_env_setv_opts(opts, pairs, error);
}

/* A bank in trial (valid) is considered good, as it has not failed yet */
gboolean r_fwu_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	g_autoptr(GString) state = NULL;
	g_autofree gchar *key = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key = g_strdup_printf("bank%s_state", slot->bootname);
	if (!fwu_env_get(key, &state, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_strcmp0(state->str, "accepted") == 0 || g_strcmp0(state->str, "valid") == 0) {
		*good = TRUE;
	} else if (g_strcmp0(state->str, "invalid") == 0) {
		*good = FALSE;
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Unknown state '%s' of bank %s", state->str, slot->bootname);
		return FALSE;
	}

	return TRUE;
}

gboolean r_fwu_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(2, g_free);
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(pairs, g_strdup_printf("bank%s_state", slot->bootname));
	g_ptr_array_add(pairs, g_strdup(good ? "accepted" : "invalid"));

	if (!fwu_env_set(pairs, &ierror)) {
		/* FWU metadata v1 has no bank state, so a bank can't be invalid */
		if (!good && g_error_matches(ierror, G_SPAWN_EXIT_ERROR, ENOTSUP)) {
			g_warning("Bank %s can't be marked invalid, assuming FWU metadata v1",
					slot->bootname);
			g_clear_error(&ierror);
			return TRUE;
		}
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

RaucSlot *r_fwu_get_primary(GError **error)
{
	g_autoptr(GString) active = NULL;
	GError *ierror = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	if (!fwu_env_get("active_index", &active, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(active->str, slot->bootname) == 0)
			return slot;
	}

	g_set_error(
			error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_PARSE_FAILED,
			"No slot found for active bank '%s'", active->str);

	return NULL;
}

gboolean r_fwu_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(6, g_free);
	g_autoptr(GString) active = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!fwu_env_get("active_index", &active, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_strcmp0(active->str, slot->bootname) != 0) {
		g_ptr_array_add(pairs, g_strdup("previous_active_index"));
		g_ptr_array_add(pairs, g_strdup(active->str));
		g_ptr_array_add(pairs, g_strdup("active_index"));
		g_ptr_array_add(pairs, g_strdup(slot->bootname));
	}
	/* Only a bank that is not running can hold a new image to try */
	if (slot->state != ST_BOOTED) {
		g_ptr_array_add(pairs, g_strdup_printf("bank%s_state", slot->bootname));
		g_ptr_array_add(pairs, g_strdup("valid"));
	}

	if (pairs->len == 0)
		return TRUE;

	if (!fwu_env_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
