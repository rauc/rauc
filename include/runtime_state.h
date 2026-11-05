#pragma once

#include <glib.h>

#include "slot.h"

/**
 * Initialize the runtime-state subsystem.
 *
 * Allocates an internal GKeyFile and remembers the path. If @path already
 * exists it is loaded; missing files yield an empty GKeyFile and success. A
 * corrupt file is renamed to <path>.broken and a fresh empty GKeyFile is used.
 *
 * @param path Path to the runtime-state file
 * @param error Return location for a GError, or NULL
 *
 * @return TRUE on success (including the "file does not exist" case),
 *         FALSE on a non-recoverable error
 */
gboolean r_runtime_state_init(const gchar *path, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Set a per-slot key/value pair.
 *
 * If @value is NULL, the key is removed from the slot's group.
 * Changes are held in memory until r_runtime_state_commit() is called.
 *
 * @param slot Slot whose name selects the group
 * @param key Key name within the slot group
 * @param value Value, or NULL to remove the key
 */
void r_runtime_state_slot_set(RaucSlot *slot, const gchar *key, const gchar *value);

/**
 * Get a per-slot key value.
 *
 * @param slot Slot whose name selects the group
 * @param key Key name within the slot group
 * @param value Out-parameter, newly-allocated value on TRUE, NULL on FALSE
 *
 * @return TRUE if the key exists, FALSE otherwise (also FALSE if init
 *         has not been called)
 */
gboolean r_runtime_state_slot_get(RaucSlot *slot, const gchar *key, gchar **value)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Persist the current runtime-state.
 *
 * Creates the parent directory if needed.
 *
 * @param error Return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE on error
 */
gboolean r_runtime_state_commit(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Free the runtime-state subsystem's storage.
 *
 * Called from r_context_clean() at process teardown.
 */
void r_runtime_state_cleanup(void);
