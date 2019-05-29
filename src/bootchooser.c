#include <string.h>
#include <errno.h>
#include <gio/gio.h>

#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "install.h"
#include "utils.h"

GQuark r_bootchooser_error_quark(void)
{
	return g_quark_from_static_string("r_bootchooser_error_quark");
}

#define BAREBOX_STATE_NAME "barebox-state"
#define BAREBOX_STATE_DEFAULT_ATTEMPTS	3
#define BAREBOX_STATE_ATTEMPTS_PRIMARY	3
#define BAREBOX_STATE_DEFAULT_PRIORITY	10
#define BAREBOX_STATE_PRIORITY_PRIMARY	20
#define UBOOT_FWSETENV_NAME "fw_setenv"
#define UBOOT_FWPRINTENV_NAME "fw_printenv"
#define UBOOT_DEFAULT_ATTEMPTS		"3"
#define UBOOT_ATTEMPTS_PRIMARY		"3"
#define EFIBOOTMGR_NAME "efibootmgr"
#define GRUB_EDITENV "grub-editenv"

static GString *bootchooser_order_primay(RaucSlot *slot)
{
	GString *order = NULL;
	GList *slots;

	g_return_val_if_fail(slot, NULL);

	order = g_string_new(slot->bootname);

	/* Iterate over boot selection-handled slots (bootname set) */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		if (s == slot)
			continue;
		if (!s->bootname)
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
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;
	guint64 result[2] = {};
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(6, g_free);

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

	r_debug_subprocess(args);
	sub = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		return FALSE;
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
			return FALSE;
		}

		result[i] = g_ascii_strtoull(outline, &endptr, 10);
		if (result[i] == 0 && outline == endptr) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"Failed to parse value: '%s'", outline);
			return FALSE;
		} else if (result[i] == G_MAXUINT64 && errno != 0) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"Return value overflow: '%s', error: %d", outline, errno);
			return FALSE;
		}
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	bb_state->prio = result[0];
	bb_state->attempts = result[1];

	return TRUE;
}


/* names: list of gchar, values: list of gint */
static gboolean barebox_state_set(GPtrArray *pairs, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(2*pairs->len+2, g_free);

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

	r_debug_subprocess(args);
	sub = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

/* Set slot status values */
static gboolean barebox_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(10, g_free);
	int attempts;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (good) {
		attempts = BAREBOX_STATE_DEFAULT_ATTEMPTS;
	} else {
		/* for marking bad, also set priority to 0 */
		attempts = 0;
		g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority=%i",
				slot->bootname, 0));
	}

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
			slot->bootname, attempts));

	if (!barebox_state_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* Get slot marked as primary one */
static RaucSlot* barebox_get_primary(GError **error)
{
	RaucSlot *slot;
	GHashTableIter iter;
	RaucSlot *primary = NULL;
	guint32 top_prio = 0;
	GError *ierror = NULL;

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		BareboxSlotState state;

		if (!slot->bootname)
			continue;

		if (!barebox_state_get(slot->bootname, &state, &ierror)) {
			g_propagate_error(error, ierror);
			return NULL;
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

	if (!barebox_state_get(slot->bootname, &state, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (state.prio > 0)
		*good = (state.attempts > 0) ? TRUE : FALSE;
	else
		*good = FALSE;

	return TRUE;
}

/* Set slot as primary boot slot */
static gboolean barebox_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(10, g_free);
	GError *ierror = NULL;
	GList *slots;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		int prio;
		BareboxSlotState bb_state;

		if (!s->bootname)
			continue;

		if (!barebox_state_get(s->bootname, &bb_state, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
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
			slot->bootname, BAREBOX_STATE_ATTEMPTS_PRIMARY));

	if (!barebox_state_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean grub_env_get(const gchar *key, GString **value, GError **error)
{
	g_autoptr(GPtrArray) sub_args = NULL;
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) sub_stdout_buf = NULL;
	const char *sub_stdout;
	gsize sub_stdout_size;
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

	r_debug_subprocess(sub_args);
	sub = g_subprocess_newv((const gchar * const *)sub_args->pdata,
			G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " GRUB_EDITENV ": ");
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &sub_stdout_buf, NULL, &ierror)) {
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
	sub_stdout = g_bytes_get_data(sub_stdout_buf, &sub_stdout_size);
	if (sub_stdout) {
		g_autofree gchar *key_prefix = g_strdup_printf("%s=", key);
		g_auto(GStrv) variables = g_strsplit(sub_stdout, "\n", -1);
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

	r_debug_subprocess(pairs);
	sub = g_subprocess_newv((const gchar * const *)pairs->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
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
static gboolean grub_get_state(RaucSlot* slot, gboolean *good, GError **error)
{
	g_autoptr(GString) order = NULL;
	g_autoptr(GString) slot_ok = NULL;
	g_autoptr(GString) slot_try = NULL;
	g_auto(GStrv) bootnames = NULL;
	g_autofree gchar *key = NULL;
	GError *ierror = NULL;
	gboolean found = FALSE;

	g_return_val_if_fail(slot, FALSE);
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
	if (!grub_env_get(key, &slot_ok,  &ierror)) {
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
static gboolean grub_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(6, g_free);
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
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
static RaucSlot* grub_get_primary(GError **error)
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

	/* Iterate over current boot order */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* find matching slot entry */
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
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Unable to detect primary slot");
	}

	return primary;
}

/* Set slot as primary boot slot */
static gboolean grub_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(7, g_free);
	g_autoptr(GString) order = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	order = bootchooser_order_primay(slot);

	g_ptr_array_add(pairs, g_strdup_printf("%s_OK=%i", slot->bootname, 1));
	g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=%i", slot->bootname, 0));
	g_ptr_array_add(pairs, g_strdup_printf("ORDER=%s", order->str));

	if (!grub_env_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean uboot_env_get(const gchar *key, GString **value, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) stdout_buf = NULL;
	const char *data;
	gsize offset;
	gsize size;
	gint ret;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror,
			UBOOT_FWPRINTENV_NAME, key, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " UBOOT_FWPRINTENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_buf, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " UBOOT_FWPRINTENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				UBOOT_FWPRINTENV_NAME " did not exit normally");
		return FALSE;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				UBOOT_FWPRINTENV_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	/* offset is composed of key + equal sign, e.g. 'BOOT_ORDER=A B R' */
	offset = strlen(key) + 1;
	data = g_bytes_get_data(stdout_buf, &size);
	*value = g_string_new_len(data + offset, size - offset);
	g_strchomp((*value)->str);

	return TRUE;
}

static gboolean uboot_env_set(const gchar *key, const gchar *value, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, UBOOT_FWSETENV_NAME,
			key, value, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " UBOOT_FWSETENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " UBOOT_FWSETENV_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

/* We assume bootstate to be good if slot is listed in 'BOOT_ORDER' and its
 * remaining attempts counter is > 0 */
static gboolean uboot_get_state(RaucSlot* slot, gboolean *good, GError **error)
{
	g_autoptr(GString) order = NULL;
	g_autoptr(GString) attempts = NULL;
	g_auto(GStrv) bootnames = NULL;
	g_autofree gchar *key = NULL;
	GError *ierror = NULL;
	gboolean found = FALSE;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!uboot_env_get("BOOT_ORDER", &order, &ierror)) {
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

	/* Check remaining attempts */
	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);
	if (!uboot_env_get(key, &attempts, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	*good = (atoi(attempts->str) > 0) ? TRUE : FALSE;

	return TRUE;
}

/* Set slot status values */
static gboolean uboot_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!good) {
		g_autoptr(GString) order_current = NULL;
		g_autoptr(GPtrArray) order_new = NULL;
		g_auto(GStrv) bootnames = NULL;
		g_autofree gchar *order = NULL;

		if (!uboot_env_get("BOOT_ORDER", &order_current, &ierror)) {
			g_message("Unable to obtain BOOT_ORDER: %s", ierror->message);
			g_clear_error(&ierror);
			goto set_left;
		}

		order_new = g_ptr_array_new();
		/* Iterate over current boot order */
		bootnames = g_strsplit(order_current->str, " ", -1);
		for (gchar **bootname = bootnames; *bootname; bootname++) {
			/* Skip selected slot, as we want it to be removed */
			if (g_strcmp0(*bootname, slot->bootname) == 0)
				continue;

			/* skip empty strings from head or tail */
			if (g_strcmp0(*bootname, "") == 0)
				continue;

			g_ptr_array_add(order_new, *bootname);
		}
		g_ptr_array_add(order_new, NULL);

		order = g_strjoinv(" ", (gchar**) order_new->pdata);
		if (!uboot_env_set("BOOT_ORDER", order, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

set_left:

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	if (!uboot_env_set(key, good ? UBOOT_DEFAULT_ATTEMPTS : "0", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* Get slot marked as primary one */
static RaucSlot* uboot_get_primary(GError **error)
{
	g_autoptr(GString) order = NULL;
	g_auto(GStrv) bootnames = NULL;
	GError *ierror = NULL;
	RaucSlot *primary = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!uboot_env_get("BOOT_ORDER", &order, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* Iterate over current boot order */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* find matching slot entry */
		g_hash_table_iter_init(&iter, r_context()->config->slots);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
			g_autofree gchar *key = NULL;
			g_autoptr(GString) attempts = NULL;

			if (g_strcmp0(*bootname, slot->bootname) != 0)
				continue;

			/* Check that > 0 attempts left */
			key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);
			if (!uboot_env_get(key, &attempts, &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}

			if (atoi(attempts->str) <= 0)
				continue;

			primary = slot;
			break;
		}

		if (primary)
			break;
	}

	if (!primary) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Unable to find primary boot slot");
	}

	return primary;
}

/* Set slot as primary boot slot */
static gboolean uboot_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GString) order_new = NULL;
	g_autoptr(GString) order_current = NULL;
	g_auto(GStrv) bootnames = NULL;
	GError *ierror = NULL;
	g_autofree gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Add updated slot as first entry in new boot order */
	order_new = g_string_new(slot->bootname);

	if (!uboot_env_get("BOOT_ORDER", &order_current, &ierror)) {
		g_message("Unable to obtain BOOT_ORDER (%s), using defaults", ierror->message);
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

	if (!uboot_env_set(key, UBOOT_ATTEMPTS_PRIMARY, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (!uboot_env_set("BOOT_ORDER", order_new->str, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

typedef struct {
	gchar* num;
	gchar* name;
	gboolean active;
} efi_bootentry;

static gboolean efi_bootorder_set(gchar *order, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(order, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);


	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, EFIBOOTMGR_NAME,
			"--bootorder", order, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}


	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

static gboolean efi_set_bootnext(gchar *bootnumber, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(bootnumber, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, EFIBOOTMGR_NAME,
			"--bootnext", bootnumber, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}


	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	return TRUE;
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
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) stdout_buf = NULL;
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

	return res;
}

static gboolean efi_set_temp_primary(RaucSlot *slot, GError **error)
{
	GList *entries = NULL;
	GError *ierror = NULL;
	efi_bootentry *efi_slot_entry = NULL;

	if (!efi_bootorder_get(NULL, &entries, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
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
		return FALSE;
	}

	if (!efi_set_bootnext(efi_slot_entry->num, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Setting bootnext failed: ");
		return FALSE;
	}

	return TRUE;
}

/* Deletes given slot from efi bootorder list.
 * Prepends it to bootorder list if prepend arguemnt is set to TRUE */
static gboolean efi_modify_persistent_bootorder(RaucSlot *slot, gboolean prepend, GError **error)
{
	GList *entries = NULL;
	GList *all_entries = NULL;
	GPtrArray *bootorder = NULL;
	g_autofree gchar *order = NULL;
	GError *ierror = NULL;
	efi_bootentry *efi_slot_entry = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_bootorder_get(&entries, &all_entries, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
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
			return FALSE;
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

	if (!efi_bootorder_set(order, NULL)) {
		g_propagate_prefixed_error(error, ierror, "Modifying bootorder failed: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean efi_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_modify_persistent_bootorder(slot, good, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static RaucSlot *efi_get_primary(GError **error)
{
	GList *bootorder_entries = NULL;
	GError *ierror = NULL;
	efi_bootentry *bootnext = NULL;
	RaucSlot *primary = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_bootorder_get(&bootorder_entries, NULL, &bootnext, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
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
				"Did not find primary boot entry!");
		return NULL;
	}

	return primary;
}

static gboolean efi_set_primary(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->efi_use_bootnext) {
		if (!efi_set_temp_primary(slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		return TRUE;
	}

	if (!efi_modify_persistent_bootorder(slot, TRUE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* We assume bootstate to be good if slot is listed in 'bootorder', otherwise
 * bad */
static gboolean efi_get_state(RaucSlot* slot, gboolean *good, GError **error)
{
	efi_bootentry *found_entry = NULL;
	GError *ierror = NULL;
	GList *bootorder_entries = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_bootorder_get(&bootorder_entries, NULL, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
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

	return TRUE;
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
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		res = grub_get_state(slot, good, &ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		res = uboot_get_state(slot, good, &ierror);
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
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		slot = grub_get_primary(&ierror);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		slot = uboot_get_primary(&ierror);
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

