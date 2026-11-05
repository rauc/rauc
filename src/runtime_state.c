#include <errno.h>
#include <glib/gstdio.h>

#include "runtime_state.h"
#include "status_file.h"

/* Module-private state. Kept here rather than on the RaucContext struct
 * because the API must remain usable both during configure_target (when
 * r_context() would recurse) and after configure (when r_context_conf()
 * would re-set pending=TRUE and risk a spurious re-configure). */
static GMutex runtime_state_lock;
static GKeyFile *runtime_state_keyfile = NULL;
static gchar *runtime_state_path = NULL;

static gchar *make_group_name(RaucSlot *slot)
{
	return g_strdup_printf(RAUC_SLOT_PREFIX ".%s", slot->name);
}

gboolean r_runtime_state_init(const gchar *path, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(path, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	G_GNUC_UNUSED g_autoptr(GMutexLocker) locker = g_mutex_locker_new(&runtime_state_lock);

	g_autoptr(GKeyFile) key_file = g_key_file_new();
	if (!g_key_file_load_from_file(key_file, path, G_KEY_FILE_NONE, &ierror)) {
		if (g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_info("Runtime state file '%s' does not exist yet", path);
			g_clear_error(&ierror);
		} else {
			g_autofree gchar *broken_file = g_strconcat(path, ".broken", NULL);
			g_warning("Failed to load runtime state '%s': %s", path, ierror->message);
			g_warning("Will move runtime state file to %s and re-create it.", broken_file);
			g_clear_error(&ierror);
			if (g_rename(path, broken_file) != 0) {
				int err = errno;
				g_warning("Renaming %s to %s failed: %s", path, broken_file, g_strerror(err));
			}
			g_clear_pointer(&key_file, g_key_file_unref);
			key_file = g_key_file_new();
		}
	}

	g_clear_pointer(&runtime_state_keyfile, g_key_file_unref);
	g_clear_pointer(&runtime_state_path, g_free);
	runtime_state_keyfile = g_steal_pointer(&key_file);
	runtime_state_path = g_strdup(path);

	return TRUE;
}

void r_runtime_state_slot_set(RaucSlot *slot, const gchar *key, const gchar *value)
{
	g_return_if_fail(slot);
	g_return_if_fail(key);

	G_GNUC_UNUSED g_autoptr(GMutexLocker) locker = g_mutex_locker_new(&runtime_state_lock);

	g_return_if_fail(runtime_state_keyfile);

	g_autofree gchar *group = make_group_name(slot);
	if (value == NULL)
		g_key_file_remove_key(runtime_state_keyfile, group, key, NULL);
	else
		g_key_file_set_string(runtime_state_keyfile, group, key, value);
}

gboolean r_runtime_state_slot_get(RaucSlot *slot, const gchar *key, gchar **value)
{
	g_autoptr(GError) ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);

	G_GNUC_UNUSED g_autoptr(GMutexLocker) locker = g_mutex_locker_new(&runtime_state_lock);

	if (!runtime_state_keyfile)
		return FALSE;

	g_autofree gchar *group = make_group_name(slot);
	gchar *result = g_key_file_get_string(runtime_state_keyfile, group, key, &ierror);
	if (!result) {
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND) ||
		    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND))
			return FALSE;
		g_warning("Failed to read runtime-state key '%s' in [%s]: %s",
				key, group, ierror->message);
		return FALSE;
	}

	*value = result;
	return TRUE;
}

gboolean r_runtime_state_commit(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	G_GNUC_UNUSED g_autoptr(GMutexLocker) locker = g_mutex_locker_new(&runtime_state_lock);

	g_return_val_if_fail(runtime_state_keyfile, FALSE);
	g_return_val_if_fail(runtime_state_path, FALSE);

	g_autofree gchar *dir = g_path_get_dirname(runtime_state_path);
	if (g_mkdir_with_parents(dir, 0755) != 0) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"Failed to create runtime state directory '%s': %s",
				dir, g_strerror(err));
		return FALSE;
	}

	if (!g_key_file_save_to_file(runtime_state_keyfile, runtime_state_path, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

void r_runtime_state_cleanup(void)
{
	G_GNUC_UNUSED g_autoptr(GMutexLocker) locker = g_mutex_locker_new(&runtime_state_lock);

	g_clear_pointer(&runtime_state_keyfile, g_key_file_unref);
	g_clear_pointer(&runtime_state_path, g_free);
}
