#include "bootchooser.h"
#include "context.h"
#include "mark.h"

static RaucSlot* get_slot_by_identifier(const gchar *identifier, GError **error)
{
	GHashTableIter iter;
	RaucSlot *slot = NULL, *booted = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&booted)) {
		if (booted->state == ST_BOOTED)
			break;
		booted = NULL;
	}

	if (!g_strcmp0(identifier, "booted")) {
		if (booted)
			slot = booted;
		else
			g_set_error(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
				"Did not find booted slot");
	} else if (!g_strcmp0(identifier, "other")) {
		if (booted) {
			g_hash_table_iter_init(&iter, r_context()->config->slots);
			while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
				if (slot->sclass == booted->sclass && !slot->parent && slot->bootname && slot != booted)
					break;
				slot = NULL;
			}
			if (!slot)
				g_set_error(error,
					    R_SLOT_ERROR,
					    R_SLOT_ERROR_FAILED,
					    "No other bootable slot of the same class found");
		} else {
			g_set_error(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
				"Did not find booted slot needed to find another bootable slot of the same class");
		}
	} else {
		gchar **groupsplit = g_strsplit(identifier, ".", -1);

		if (g_strv_length(groupsplit) == 2) {
			g_hash_table_iter_init(&iter, r_context()->config->slots);
			while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
				if (!g_strcmp0(slot->sclass, groupsplit[0]) && !slot->parent && !g_strcmp0(slot->name, identifier))
					break;
				slot = NULL;
			}
			if (!slot)
				g_set_error(error,
					    R_SLOT_ERROR,
					    R_SLOT_ERROR_FAILED,
					    "No slot with class %s and name %s found",
					    groupsplit[0],
					    identifier);
		} else {
			g_set_error(error,
				    R_SLOT_ERROR,
				    R_SLOT_ERROR_FAILED,
				    "Invalid slot name format");
		}

		g_strfreev(groupsplit);
	}

	return slot;
}

gboolean mark_run(const gchar *state,
		  const gchar *slot_identifier,
		  gchar **slot_name,
		  gchar **message)
{
	RaucSlot *slot = NULL;
	GError *ierror = NULL;
	gboolean res;

	g_assert(slot_name == NULL || *slot_name == NULL);
	g_assert(message != NULL && *message == NULL);

	slot = get_slot_by_identifier(slot_identifier, &ierror);
	if (ierror) {
		res = FALSE;
		*message = g_strdup(ierror->message);
		g_error_free(ierror);
		goto out;
	}

	if (!g_strcmp0(state, "good")) {
		res = r_boot_set_state(slot, TRUE);
		*message = g_strdup_printf((res) ? "marked slot %s as good" : "failed to mark slot %s as good", slot->name);
	} else if (!g_strcmp0(state, "bad")) {
		res = r_boot_set_state(slot, FALSE);
		*message = g_strdup_printf((res) ? "marked slot %s as bad" : "failed to mark slot %s as bad", slot->name);
	} else if (!g_strcmp0(state, "active")) {
		res = r_boot_set_primary(slot);
		*message = g_strdup_printf((res) ? "activated slot %s" : "failed to activate slot %s", slot->name);
	} else {
		res = FALSE;
		*message = g_strdup_printf("unknown subcommand %s", state);
	}

out:
	if (res && slot_name)
		*slot_name = g_strdup(slot->name);

	return res;
}
