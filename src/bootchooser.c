#include <string.h>
#include <errno.h>
#include <gio/gio.h>

#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "install.h"

GQuark r_bootchooser_error_quark(void)
{
	return g_quark_from_static_string("r_bootchooser_error_quark");
}

#define BAREBOX_STATE_NAME "barebox-state"
#define BAREBOX_STATE_DEFAULT_ATTEMPS	3
#define BAREBOX_STATE_ATTEMPS_PRIMARY	3
#define BAREBOX_STATE_DEFAULT_PRIORITY	10
#define BAREBOX_STATE_PRIORITY_PRIMARY	20
#define UBOOT_FWSETENV_NAME "fw_setenv"
#define UBOOT_FWGETENV_NAME "fw_printenv"
#define EFIBOOTMGR_NAME "efibootmgr"

static GString *bootchooser_order_primay(RaucSlot *slot)
{
	GString *order = g_string_sized_new(10);
	GList *slots;

	g_return_val_if_fail(slot, NULL);

	g_string_append(order, slot->bootname);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		if (s == slot)
			continue;
		if (s->sclass != slot->sclass)
			continue;

		g_string_append_c(order, ' ');
		g_string_append(order, s->bootname);
	}

	return order;
}

typedef struct {
	guint32 prio;
	guint32 attempts;
} BareboxSlotState;

#define BOOTSTATE_PREFIX "bootstate"

static gboolean barebox_state_get(const gchar* bootname, BareboxSlotState *bb_state, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;
	guint64 result[2] = {};
	GPtrArray *args = g_ptr_array_new_full(6, g_free);

	g_return_val_if_fail(bootname, FALSE);
	g_return_val_if_fail(bb_state, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	if (r_context()->config->system_bb_statename) {
		g_ptr_array_add(args, g_strdup("-n"));
		g_ptr_array_add(args, g_strdup(r_context()->config->system_bb_statename));
	}
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority", bootname));
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts", bootname));
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(sub);
	datainstream = g_data_input_stream_new(instream);

	for (int i = 0; i < 2; i++) {
		gchar *endptr = NULL;
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, &ierror);
		if (!outline) {
			/* Having no error set there was means no content to read */
			if (ierror == NULL) {
				g_set_error(
						error,
						R_BOOTCHOOSER_ERROR,
						R_BOOTCHOOSER_ERROR_PARSE_FAILED,
						"No content to read");
			} else {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Failed parsing " BAREBOX_STATE_NAME " output: ");
			}
			goto out;
		}

		result[i] = g_ascii_strtoull(outline, &endptr, 10);
		if (result[i] == 0 && outline == endptr) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"Failed to parse value: '%s'", outline);
			goto out;
		} else if (result[i] == G_MAXUINT64 && errno != 0) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"Return value overflow: '%s', error: %d", outline, errno);
			goto out;
		}
	}

	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		goto out;
	}

	bb_state->prio = result[0];
	bb_state->attempts = result[1];

out:
	g_ptr_array_unref(args);
	return res;
}


/* names: list of gchar, values: list of gint */
static gboolean barebox_state_set(GPtrArray *pairs, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(2*pairs->len+2, g_free);

	g_return_val_if_fail(pairs, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_cmpuint(pairs->len, >, 0);

	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	if (r_context()->config->system_bb_statename) {
		g_ptr_array_add(args, g_strdup("-n"));
		g_ptr_array_add(args, g_strdup(r_context()->config->system_bb_statename));
	}
	for (guint i = 0; i < pairs->len; i++) {
		g_ptr_array_add(args, g_strdup("-s"));
		g_ptr_array_add(args, g_strdup(pairs->pdata[i]));
	}
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		goto out;
	}

out:
	g_ptr_array_unref(args);
	return res;
}

/* Set slot status values */
static gboolean barebox_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	int attempts;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (good) {
		attempts = BAREBOX_STATE_DEFAULT_ATTEMPS;
	} else {
		/* for marking bad, also set priority to 0 */
		attempts = 0;
		g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority=%i",
						slot->bootname, 0));
	}

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
					slot->bootname, attempts));

	res = barebox_state_set(pairs, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

/* Get slot marked as primary one */
static RaucSlot* barebox_get_primary(GError **error)
{
	RaucSlot *slot;
	GHashTableIter iter;
	RaucSlot *primary = NULL;
	guint32 top_prio = 0;
	GError *ierror = NULL;
	gboolean res;

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		BareboxSlotState state;

		if (!slot->bootname)
			continue;

		res = barebox_state_get(slot->bootname, &state, &ierror);
		if (!res) {
			g_debug("%s", ierror->message);
			g_clear_error(&ierror);
			continue;
		}

		if (state.attempts == 0)
			continue;

		/* We search for the slot with highest priority */
		if (state.prio > top_prio) {
			primary = slot;
			top_prio = state.prio;
		}
	}

	if (!primary) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Unable to obtain primary element");
	}

	return primary;
}

/* We assume a slot to be 'good' if its priority is > 0 AND its remaining
 * attempts counter is > 0 */
static gboolean barebox_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	BareboxSlotState state;
	GError *ierror = NULL;
	gboolean res = FALSE;

	res = barebox_state_get(slot->bootname, &state, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (state.prio > 0)
		*good = (state.attempts > 0) ? TRUE : FALSE;
	else
		*good = FALSE;

out:
	return res;
}

/* Set slot as primary boot slot */
static gboolean barebox_set_primary(RaucSlot *slot, GError **error)
{
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	GError *ierror = NULL;
	gboolean res = FALSE;
	GList *slots;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		int prio;
		BareboxSlotState bb_state;

		if (s->sclass != slot->sclass)
			continue;


		res = barebox_state_get(s->bootname, &bb_state, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}

		if (s == slot) {
			prio = BAREBOX_STATE_PRIORITY_PRIMARY;
		} else {
			if (bb_state.prio == 0)
				prio = 0;
			else
				prio = BAREBOX_STATE_DEFAULT_PRIORITY;
		}
		g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority=%i",
						s->bootname, prio));
	}

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
					slot->bootname, BAREBOX_STATE_ATTEMPS_PRIMARY));

	res = barebox_state_set(pairs, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

static gboolean grub_env_set(GPtrArray *pairs, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(pairs, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_cmpuint(pairs->len, >, 0);
	g_assert_nonnull(r_context()->config->grubenv_path);

	g_ptr_array_insert(pairs, 0, g_strdup("grub-editenv"));
	g_ptr_array_insert(pairs, 1, g_strdup(r_context()->config->grubenv_path));
	g_ptr_array_insert(pairs, 2, g_strdup("set"));
	g_ptr_array_add(pairs, NULL);

	sub = g_subprocess_newv((const gchar * const *)pairs->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start grub-editenv: ");
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run grub-editenv: ");
		goto out;
	}

out:
	g_ptr_array_remove_index(pairs, pairs->len-1);
	g_ptr_array_remove_index(pairs, 2);
	g_ptr_array_remove_index(pairs, 1);
	g_ptr_array_remove_index(pairs, 0);
	return res;
}

/* Set slot status values */
static gboolean grub_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (good) {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=1", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	} else {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=0", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	}

	res = grub_env_set(pairs, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

/* Set slot as primary boot slot */
static gboolean grub_set_primary(RaucSlot *slot, GError **error)
{
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	GString *order = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	order = bootchooser_order_primay(slot);

	g_ptr_array_add(pairs, g_strdup_printf("%s_OK=%i", slot->bootname, 1));
	g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=%i", slot->bootname, 0));
	g_ptr_array_add(pairs, g_strdup_printf("ORDER=%s", order->str));

	res = grub_env_set(pairs, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	if (order)
		g_string_free(order, TRUE);
	g_ptr_array_unref(pairs);
	return res;
}

static gboolean uboot_env_get(const gchar *key, GString **value, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	GBytes *stdout_buf = NULL;
	const char *data;
	gsize offset;
	gsize size;
	gboolean res = FALSE;
	gint ret;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror,
			UBOOT_FWGETENV_NAME, key, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " UBOOT_FWGETENV_NAME ": ");
		goto out;
	}

	res = g_subprocess_communicate(sub, NULL, NULL, &stdout_buf, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " UBOOT_FWGETENV_NAME ": ");
		goto out;
	}

	res = g_subprocess_get_if_exited(sub);
	if (!res) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				UBOOT_FWGETENV_NAME " did not exit normally");
		goto out;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				UBOOT_FWGETENV_NAME " failed with exit code: %i", ret);
		res = FALSE;
		goto out;
	}

	/* offset is composed of key + equal sign, e.g. 'BOOT_ORDER=A B R' */
	offset = strlen(key) + 1;
	data = g_bytes_get_data(stdout_buf, &size);
	*value = g_string_new_len(data + offset, size - offset);
	g_strchomp((*value)->str);

out:
	g_bytes_unref(stdout_buf);

	return res;
}

static gboolean uboot_env_set(const gchar *key, const gchar *value, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, UBOOT_FWSETENV_NAME,
			key, value, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start fw_setenv: ");
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run fw_setenv: ");
		goto out;
	}

out:
	return res;
}

/* Set slot status values */
static gboolean uboot_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	res = uboot_env_set(key, good ? "3" : "0", &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_free(key);
	return res;
}

/* Set slot as primary boot slot */
static gboolean uboot_set_primary(RaucSlot *slot, GError **error)
{
	GString *order_new = g_string_sized_new(10);
	GString *order_current = NULL;
	gchar **bootnames = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Add updated slot as first entry in new boot order */
	g_string_append(order_new, slot->bootname);

	res = uboot_env_get("BOOT_ORDER", &order_current, &ierror);
	if (!res) {
		g_message("Unable to obtain BOOT_ORDER, using defaults");
		g_clear_error(&ierror);

		order_current = bootchooser_order_primay(slot);
	}

	/* Iterate over current boot order */
	bootnames = g_strsplit(order_current->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* Skip updated slot, as it is already at the beginning */
		if (g_strcmp0(*bootname, slot->bootname) == 0)
			continue;

		/* skip empty strings from head or tail */
		if (g_strcmp0(*bootname, "") == 0)
			continue;

		g_string_append_c(order_new, ' ');
		g_string_append(order_new, *bootname);
	}

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	res = uboot_env_set(key, "3", &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}
	res = uboot_env_set("BOOT_ORDER", order_new->str, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_string_free(order_current, TRUE);
	if (order_new)
		g_string_free(order_new, TRUE);
	g_strfreev(bootnames);
	g_free(key);
	return res;
}

typedef struct {
	gchar* num;
	gchar* name;
	gboolean active;
} efi_bootentry;

static gboolean efi_bootorder_set(gchar *order, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(order, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);


	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, "efibootmgr",
			"--bootorder", order, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		goto out;
	}


	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		goto out;
	}

out:
	return res;
}

static gboolean efi_set_bootnext(gchar *bootnumber, GError **error)
{
	GSubprocess *sub;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(bootnumber, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, "efibootmgr",
			"--bootnext", bootnumber, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		goto out;
	}


	res = g_subprocess_wait_check(sub, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		goto out;
	}

out:
	return res;
}

static efi_bootentry* get_efi_entry_by_bootnum(GList *entries, const gchar *bootnum)
{
	efi_bootentry *found_entry = NULL;

	g_return_val_if_fail(entries, NULL);
	g_return_val_if_fail(bootnum, NULL);

	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *ptr = entry->data;
		if (g_strcmp0(bootnum, ptr->num) == 0) {
			found_entry = ptr;
			break;
		}
	}

	return found_entry;
}

/* Parses output of efibootmgr and returns information obtained.
 *
 * @param bootorder_entries Return location for List (of efi_bootentry
 *        elements) of slots that are currently in EFI 'BootOrder'
 * @param all_entries Return location for List (of efi_bootentry element) of
 *        all EFI boot entries
 * @param bootnext Return location for EFI boot slot currently selected as
 *        'BootNext' (if any)
 * @param error Return location for a GError
 */
static gboolean efi_bootorder_get(GList **bootorder_entries, GList **all_entries, efi_bootentry **bootnext, GError **error)
{
	GSubprocess *sub = NULL;
	GError *ierror = NULL;
	GBytes *stdout_buf = NULL;
	gboolean res = FALSE;
	gint ret;
	GRegex *regex = NULL;
	GMatchInfo *match = NULL;
	GList *entries = NULL;
	GList *returnorder = NULL;
	gchar **bootnumorder = NULL;

	g_return_val_if_fail(bootorder_entries == NULL || *bootorder_entries == NULL, FALSE);
	g_return_val_if_fail(all_entries == NULL || *all_entries == NULL, FALSE);
	g_return_val_if_fail(bootnext == NULL || *bootnext == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror,
			EFIBOOTMGR_NAME, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		goto out;
	}

	res = g_subprocess_communicate(sub, NULL, NULL, &stdout_buf, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				EFIBOOTMGR_NAME " communication failed: ");
		goto out;
	}

	res = g_subprocess_get_if_exited(sub);
	if (!res) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				EFIBOOTMGR_NAME " did not exit normally");
		goto out;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				EFIBOOTMGR_NAME " failed with exit code: %i", ret);
		res = FALSE;
		goto out;
	}

	/* Obtain mapping of efi boot numbers to bootnames */
	regex = g_regex_new("^Boot([0-9a-fA-F]{4})[\\* ] (.+)$", G_REGEX_MULTILINE, 0, NULL);
	if (!g_regex_match(regex, g_bytes_get_data(stdout_buf, NULL), 0, &match)) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Regex matching failed!");
		res = FALSE;
		goto out;
	}

	while (g_match_info_matches(match)) {
		efi_bootentry *entry = g_new0(efi_bootentry, 1);
		entry->num = g_strdup(g_match_info_fetch(match, 1));
		entry->name = g_strdup(g_match_info_fetch(match, 2));
		entries = g_list_append(entries, entry);
		g_match_info_next(match, NULL);
	}

	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	/* obtain bootnext */
	regex = g_regex_new("^BootNext: ([0-9a-fA-F]{4})$", G_REGEX_MULTILINE, 0, NULL);
	if (g_regex_match(regex, g_bytes_get_data(stdout_buf, NULL), 0, &match)) {
		if (bootnext)
			*bootnext = get_efi_entry_by_bootnum(entries, g_match_info_fetch(match, 1));
	}

	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	/* Obtain boot order */
	regex = g_regex_new("^BootOrder: (\\S+)$", G_REGEX_MULTILINE, 0, NULL);
	if (!g_regex_match(regex, g_bytes_get_data(stdout_buf, NULL), 0, &match)) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"unable to obtain boot order!");
		res = FALSE;
		goto out;
	}

	bootnumorder = g_strsplit(g_match_info_fetch(match, 1), ",", 0);

	/* Iterate over boot entries list in boot order */
	for (gchar **element = bootnumorder; *element; element++) {
		efi_bootentry *bentry = get_efi_entry_by_bootnum(entries, *element);
		if (bentry)
			returnorder = g_list_append(returnorder, bentry);
	}

	g_strfreev(bootnumorder);

	if (bootorder_entries)
		*bootorder_entries = returnorder;
	if (all_entries)
		*all_entries = entries;

out:
	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	g_bytes_unref(stdout_buf);

	return res;
}

static gboolean efi_set_temp_primary(RaucSlot *slot, GError **error)
{
	GList *entries = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	efi_bootentry *efi_slot_entry = NULL;

	res = efi_bootorder_get(NULL, &entries, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Obtaining bootorder failed: ");
		goto out;
	}

	/* Lookup efi boot entry matching slot. */
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		if (g_strcmp0(efi->name, slot->bootname) == 0) {
			efi_slot_entry = efi;
			break;
		}
	}

	if (!efi_slot_entry) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Did not find efi entry for bootname '%s'!", slot->bootname);
		res = FALSE;
		goto out;
	}

	res = efi_set_bootnext(efi_slot_entry->num, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Obtaining bootorder failed: ");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

/* Deletes given slot from efi bootorder list.
 * Prepends it to bootorder list if prepend arguemnt is set to TRUE */
static gboolean efi_modify_persistent_bootorder(RaucSlot *slot, gboolean prepend, GError **error)
{
	GList *entries = NULL;
	GList *all_entries = NULL;
	GPtrArray *bootorder = NULL;
	gchar *order = NULL;
	gboolean res = FALSE;
	GError *ierror = NULL;
	efi_bootentry *efi_slot_entry = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = efi_bootorder_get(&entries, &all_entries, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Modifying bootorder failed: ");
		goto out;
	}

	/* Iterate over bootorder list until reaching boot entry to remove (if available) */
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		if (g_strcmp0(efi->name, slot->bootname) == 0) {
			entries = g_list_remove(entries, efi);
			break;
		}
	}

	if (prepend) {
		/* Iterate over full list to get entry to prepend to bootorder */
		for (GList *entry = all_entries; entry != NULL; entry = entry->next) {
			efi_bootentry *efi = entry->data;
			if (g_strcmp0(efi->name, slot->bootname) == 0) {
				efi_slot_entry = efi;
				break;
			}
		}

		if (!efi_slot_entry) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_FAILED,
					"No entry for bootname '%s' found", slot->bootname);
			res = FALSE;
			goto out;
		}

		entries = g_list_prepend(entries, efi_slot_entry);
	}

	bootorder = g_ptr_array_sized_new(g_list_length(entries));
	/* Construct bootorder string out of boot entry list */
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		g_ptr_array_add(bootorder, efi->num);
	}
	g_ptr_array_add(bootorder, NULL);

	/* No need to free the individual strings here as we only declared
	 * pointers to already-existing string members of efi_bootentry items. */
	order = g_strjoinv(",", (gchar**) g_ptr_array_free(bootorder, FALSE));

	res = efi_bootorder_set(order, NULL);
	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Modifying bootorder failed: ");
		goto out;
	}

	res = TRUE;
out:
	g_free(order);
	return res;
}

static gboolean efi_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = efi_modify_persistent_bootorder(slot, good, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static RaucSlot *efi_get_primary(GError **error)
{
	GList *bootorder_entries = NULL;
	gboolean res = FALSE;
	GError *ierror = NULL;
	efi_bootentry *bootnext = NULL;
	RaucSlot *primary = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = efi_bootorder_get(&bootorder_entries, NULL, &bootnext, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* We prepend the content of BootNext if set */
	if (bootnext) {
		g_debug("Detected BootNext set to %s", bootnext->name);
		bootorder_entries = g_list_prepend(bootorder_entries, bootnext);
	}

	for (GList *entry = bootorder_entries; entry != NULL; entry = entry->next) {
		efi_bootentry *bootentry = entry->data;

		/* find matching slot entry */
		g_hash_table_iter_init(&iter, r_context()->config->slots);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
			if (g_strcmp0(bootentry->name, slot->bootname) == 0) {
				primary = slot;
				break;
			}
		}

		if (primary)
			break;
	}

	if (!primary) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Did not find slot for boot entry '%s' !", bootnext->name);
		res = FALSE;
		goto out;
	}

	res = TRUE;
out:
	return res ? primary : NULL;
}

static gboolean efi_set_primary(RaucSlot *slot, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = efi_set_temp_primary(slot, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	return res;
}

/* We assume bootstate to be good if slot is listed in 'bootorder', otherwise
 * bad */
static gboolean efi_get_state(RaucSlot* slot, gboolean *good, GError **error)
{
	efi_bootentry *found_entry = NULL;
	gboolean res = FALSE;
	GError *ierror = NULL;
	GList *bootorder_entries = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = efi_bootorder_get(&bootorder_entries, NULL, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* Scan bootorder list for given slot */
	for (GList *entry = bootorder_entries; entry != NULL; entry = entry->next) {
		efi_bootentry *ptr = entry->data;
		if (g_strcmp0(slot->bootname, ptr->name) == 0) {
			found_entry = ptr;
			break;
		}
	}

	*good = found_entry ? TRUE : FALSE;

out:
	return res;
}

gboolean r_boot_get_state(RaucSlot* slot, gboolean *good, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		res = barebox_get_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "efi") == 0) {
		res = efi_get_state(slot, good, &ierror);
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
				"Obtaining state from bootloader '%s' not supported yet", r_context()->config->system_bootloader);
		return FALSE;
	}

	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get state of %s: ", slot->name);
	}

	return res;
}

gboolean r_boot_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		res = barebox_set_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		res = grub_set_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		res = uboot_set_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "efi") == 0) {
		res = efi_set_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "noop") == 0) {
		g_message("noop bootloader: ignore setting slot %s status to %s", slot->name, good ? "good" : "bad");
		res = TRUE;
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
				"Bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
		return FALSE;
	}

	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed marking '%s' as %s: ", slot->name, good ? "good" : "bad");
	}

	return res;
}

RaucSlot* r_boot_get_primary(GError **error)
{
	RaucSlot *slot = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		slot = barebox_get_primary(&ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "efi") == 0) {
		slot = efi_get_primary(&ierror);
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
				"Obtaining primary entry from bootloader '%s' not supported yet", r_context()->config->system_bootloader);
		return NULL;
	}

	if (!slot) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed getting primary slot: ");
	}

	return slot;
}

gboolean r_boot_set_primary(RaucSlot *slot, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		res = barebox_set_primary(slot, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		res = grub_set_primary(slot, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		res = uboot_set_primary(slot, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "efi") == 0) {
		res = efi_set_primary(slot, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "noop") == 0) {
		g_message("noop bootloader: ignore setting slot %s as primary", slot->name);
		res = TRUE;
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_NOT_SUPPORTED,
				"Bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
		return FALSE;
	}

	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed marking '%s' as primary: ", slot->name);
	}

	return res;
}

