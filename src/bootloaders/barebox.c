#include <errno.h>

#include "barebox.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define BAREBOX_STATE_NAME "barebox-state"
#define BAREBOX_STATE_DEFAULT_ATTEMPTS	3
#define BAREBOX_STATE_ATTEMPTS_PRIMARY	3
#define BAREBOX_STATE_DEFAULT_PRIORITY	10
#define BAREBOX_STATE_PRIORITY_PRIMARY	20

typedef struct {
	guint32 prio;
	guint32 attempts;
} BareboxSlotState;

#define BOOTSTATE_PREFIX "bootstate"

gchar *r_barebox_get_current_bootname(const gchar *cmdline, GError **error)
{
	g_return_val_if_fail(cmdline, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	return r_regex_match_simple(
			"(?:bootstate|bootchooser)\\.active=(\\S+)",
			cmdline);
}

static gboolean barebox_state_get(const gchar *bootname, BareboxSlotState *bb_state, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
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
	if (r_context()->config->system_bb_dtbpath) {
		g_ptr_array_add(args, g_strdup("-i"));
		g_ptr_array_add(args, g_strdup(r_context()->config->system_bb_dtbpath));
	}
	g_ptr_array_add(args, NULL);

	sub = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	g_autoptr(GBytes) stdout_bytes = NULL;
	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				BAREBOX_STATE_NAME " did not exit normally");
		return FALSE;
	}

	gint ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				BAREBOX_STATE_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	g_autofree gchar *stdout_str = r_bytes_unref_to_string(&stdout_bytes);
	g_auto(GStrv) outlines = g_strsplit (stdout_str, "\n", -1);
	for (int i = 0; i < 2; i++) {
		gchar *endptr = NULL;
		const gchar *outline = outlines[i];
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
	if (r_context()->config->system_bb_dtbpath) {
		g_ptr_array_add(args, g_strdup("-i"));
		g_ptr_array_add(args, g_strdup(r_context()->config->system_bb_dtbpath));
	}
	g_ptr_array_add(args, NULL);

	sub = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_NONE, &ierror);
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
gboolean r_barebox_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(10, g_free);
	int attempts;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (good) {
		attempts = r_context()->config->boot_default_attempts;
		if (attempts <= 0)
			attempts = BAREBOX_STATE_DEFAULT_ATTEMPTS;
	} else {
		/* For marking bad, also set priority to 0 */
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

/* This freezes the remaining attempts counters in barebox by setting the attempts_locked variable */
gboolean r_barebox_set_lock_counter(gboolean locked, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(1, g_free);

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".attempts_locked=%i",
			locked ? 1 : 0));

	if (!barebox_state_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* This returns the value of the attempts_locked variable in barebox which
 * controls the locking of the remaining_attempts counter */
gboolean r_barebox_get_lock_counter(gboolean *locked, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GSubprocess) sub = NULL;
	GInputStream *instream = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	g_autofree gchar *outline = NULL;
	gchar *endptr = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GPtrArray) args = g_ptr_array_new_full(4, g_free);
	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	/* does not support -n here as it is also called during context setup and will cause recursion */
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup_printf(BOOTSTATE_PREFIX ".attempts_locked"));
	g_ptr_array_add(args, NULL);

	sub = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	instream = g_subprocess_get_stdout_pipe(sub);
	datainstream = g_data_input_stream_new(instream);

	outline = g_data_input_stream_read_line(datainstream, NULL, NULL, &ierror);
	if (!outline) {
		/* Having no error set means no content to read */
		if (ierror == NULL)
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"No content to read");
		else
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed parsing " BAREBOX_STATE_NAME " output: ");
		return FALSE;
	}

	guint64 lock_value = g_ascii_strtoull(outline, &endptr, 10);
	if (lock_value == 0 && outline == endptr) {
			g_set_error(
					error,
					R_BOOTCHOOSER_ERROR,
					R_BOOTCHOOSER_ERROR_PARSE_FAILED,
					"Failed to parse value: '%s'", outline);
		return FALSE;
	} else if (lock_value == G_MAXUINT64 && errno != 0) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Return value overflow: '%s', error: %d", outline, errno);
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " BAREBOX_STATE_NAME ": ");
		return FALSE;
	}

	if (lock_value > 0)
		*locked = TRUE;

	return TRUE;
}

/* Get slot marked as primary one */
RaucSlot *r_barebox_get_primary(GError **error)
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
gboolean r_barebox_get_state(RaucSlot *slot, gboolean *good, GError **error)
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
gboolean r_barebox_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GPtrArray) pairs = g_ptr_array_new_full(10, g_free);
	GError *ierror = NULL;
	g_autoptr(GList) slots = NULL;
	int attempts;

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

	attempts = r_context()->config->boot_attempts_primary;
	if (attempts <= 0)
		attempts = BAREBOX_STATE_ATTEMPTS_PRIMARY;

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
			slot->bootname, attempts));

	if (!barebox_state_set(pairs, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
