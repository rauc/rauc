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

static gboolean barebox_state_get(const gchar *bootname, BareboxSlotState *bb_state, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	GInputStream *instream;
	g_autoptr(GDataInputStream) datainstream = NULL;
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

	instream = g_subprocess_get_stdout_pipe(sub);
	datainstream = g_data_input_stream_new(instream);

	for (int i = 0; i < 2; i++) {
		gchar *endptr = NULL;
		g_autofree gchar *outline = g_data_input_stream_read_line(datainstream, NULL, NULL, &ierror);
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
