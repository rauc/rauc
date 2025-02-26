#include "custom.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

/* Wrapper for get commands accessing custom script
 *
 * @param cmd What to input as command to the custom backend. Mandatory.
   Valid values:
   - get-primary
   - get-state
 * @param bootname slot.bootname
 * @param ret_str Return string from stdout after running the command
 * @param error Return location for a GError
 */
static gboolean custom_backend_get(const gchar *cmd, const gchar *bootname, gchar **ret_str, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) stdout_bytes = NULL;
	gint ret;
	gchar *backend_name = r_context()->config->custom_bootloader_backend;

	g_return_val_if_fail(cmd, FALSE);
	g_return_val_if_fail(ret_str && *ret_str == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (bootname)
		sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror, backend_name, cmd, bootname, NULL);
	else
		sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror, backend_name, cmd, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start %s: ", backend_name);
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run %s: ", backend_name);
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				"%s did not exit normally", backend_name);
		return FALSE;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				"%s failed with exit code %d", backend_name, ret);
		return FALSE;
	}

	*ret_str = r_bytes_unref_to_string(&stdout_bytes);

	/* Cleanup string for newlines */
	g_strstrip(*ret_str);

	return TRUE;
}

/* Wrapper for set commands accessing custom script
 *
 * @param cmd What to input as command to the custom backend. Mandatory.
   Valid values:
   - set-primary
   - set-state
 * @param bootname slot.bootname
 * @param arg extra arguments if needed
 * @param error Return location for a GError
 */
static gboolean custom_backend_set(const gchar *cmd, const gchar *bootname, const gchar *arg, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	gchar *backend_name = r_context()->config->custom_bootloader_backend;

	g_return_val_if_fail(cmd, FALSE);
	g_return_val_if_fail(bootname, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (arg)
		sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, backend_name, cmd, bootname, arg, NULL);
	else
		sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, backend_name, cmd, bootname, NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start %s: ", backend_name);
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run %s: ", backend_name);
		return FALSE;
	}

	return TRUE;
}

/* Get current bootname */
gchar *r_custom_get_current_bootname(RaucConfig *config, GError **error)
{
	g_autoptr(GSubprocessLauncher) launcher = NULL;
	g_autoptr(GSubprocess) handle = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	g_autoptr(GPtrArray) args_array = NULL;
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *outline = NULL;
	GInputStream *instream;
	int res;

	args_array = g_ptr_array_new();
	g_ptr_array_add(args_array, config->custom_bootloader_backend);
	g_ptr_array_add(args_array, (gchar *)("get-current"));
	g_ptr_array_add(args_array, NULL);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE);
	handle = r_subprocess_launcher_spawnv(launcher, args_array, &ierror);
	if (handle == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run custom backend '%s': ",
				config->custom_bootloader_backend);
		return NULL;
	}

	instream = g_subprocess_get_stdout_pipe(handle);
	datainstream = g_data_input_stream_new(instream);
	outline = g_data_input_stream_read_line(datainstream, NULL, NULL, &ierror);
	if (ierror) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to read custom backend output '%s': ",
				config->custom_bootloader_backend);
		return NULL;
	}

	res = g_subprocess_wait_check(handle, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to get custom backend output '%s': ",
				config->custom_bootloader_backend);
		return NULL;
	}
	if (!outline || *outline == 0) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Failed to get custom backend bootname '%s': no output",
				config->custom_bootloader_backend);
		return NULL;
	}

	g_debug("Resolved custom backend bootname to %s", outline);

	return g_steal_pointer(&outline);
}

/* Set slot status values */
gboolean r_custom_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	return custom_backend_set("set-state", slot->bootname, good ? "good" : "bad", error);
}

/* Get slot marked as primary one */
RaucSlot *r_custom_get_primary(GError **error)
{
	RaucSlot *slot;
	GHashTableIter iter;
	RaucSlot *primary = NULL;
	GError *ierror = NULL;
	g_autofree gchar *ret_str = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!custom_backend_get("get-primary", NULL, &ret_str, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* Check result. Ensure returned bootname is in the list */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (!slot->bootname)
			continue;

		if (g_strcmp0(ret_str, slot->bootname) == 0) {
			primary = slot;
			break;
		}
	}

	if (!primary) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"'%s' does not match any configured bootname", ret_str);
	}

	return primary;
}

/* Get state of given slot */
gboolean r_custom_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *ret_str = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!custom_backend_get("get-state", slot->bootname, &ret_str, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_strcmp0(ret_str, "good") == 0) {
		*good = TRUE;
	} else if (g_strcmp0(ret_str, "bad") == 0) {
		*good = FALSE;
	} else {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Obtained string does not match \"good\" or \"bad\": '%s'", ret_str);
		return FALSE;
	}

	return TRUE;
}

/* Set slot as primary boot slot */
gboolean r_custom_set_primary(RaucSlot *slot, GError **error)
{
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	return custom_backend_set("set-primary", slot->bootname, NULL, error);
}
