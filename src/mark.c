#include "bootchooser.h"
#include "context.h"
#include "install.h"
#include "mark.h"

static RaucSlot* get_slot_by_identifier(const gchar *identifier, GError **error)
{
	GHashTableIter iter;
	RaucSlot *slot = NULL, *booted = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &booted)) {
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
			while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
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
		g_auto(GStrv) groupsplit = g_strsplit(identifier, ".", -1);

		if (g_strv_length(groupsplit) == 2) {
			g_hash_table_iter_init(&iter, r_context()->config->slots);
			while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
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
					"Invalid slot name format: '%s'", identifier);
		}
	}

	return slot;
}

void mark_active(RaucSlot *slot, GError **error)
{
	RaucSlotStatus *slot_state;
	GError *ierror = NULL;
	GDateTime *now;
	gboolean res;

	g_return_if_fail(slot);
	g_return_if_fail(error == NULL || *error == NULL);

	load_slot_status(slot);
	slot_state = slot->status;

	res = r_boot_set_primary(slot, &ierror);
	if (!res) {
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_BOOTABLE,
				"failed to activate slot %s: %s", slot->name, ierror->message);
		g_error_free(ierror);
		return;
	}

	g_free(slot_state->activated_timestamp);
	now = g_date_time_new_now_utc();
	slot_state->activated_timestamp = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");
	slot_state->activated_count++;
	g_date_time_unref(now);

	res = save_slot_status(slot, &ierror);
	if (!res) {
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED, "%s", ierror->message);
		g_error_free(ierror);
		return;
	}
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
		goto out;
	}

	if (!g_strcmp0(state, "good")) {
		res = r_boot_set_state(slot, TRUE, &ierror);
		*message = res ? g_strdup_printf("marked slot %s as good", slot->name) : g_strdup(ierror->message);
	} else if (!g_strcmp0(state, "bad")) {
		res = r_boot_set_state(slot, FALSE, &ierror);
		*message = res ? g_strdup_printf("marked slot %s as bad", slot->name) : g_strdup(ierror->message);
	} else if (!g_strcmp0(state, "active")) {
		mark_active(slot, &ierror);
		if (g_error_matches(ierror, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_BOOTABLE)) {
			res = FALSE;
			*message = g_strdup(ierror->message);
		} else if (g_error_matches(ierror, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED)) {
			res = TRUE;
			*message = g_strdup_printf("activated slot %s, but failed to write status file: %s",
					slot->name, ierror->message);
		} else if (ierror) {
			res = FALSE;
			*message = g_strdup_printf("unexpected error while trying to activate slot %s: %s",
					slot->name, ierror->message);
		} else {
			res = TRUE;
			*message = g_strdup_printf("activated slot %s", slot->name);
		}
		g_clear_error(&ierror);
	} else {
		res = FALSE;
		*message = g_strdup_printf("unknown subcommand %s", state);
	}

out:
	if (res && slot_name)
		*slot_name = g_strdup(slot->name);

	g_clear_error(&ierror);

	return res;
}
