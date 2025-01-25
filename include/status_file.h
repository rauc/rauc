#pragma once

#include <glib.h>

#include "slot.h"

#define RAUC_SLOT_PREFIX	"slot"

/**
 * Load a single slot status from a file into a pre-allocated status structure.
 * If a problem occurs this structure is left unmodified.
 *
 * @param filename file to load
 * @param slotstatus pointer to the pre-allocated structure going to store the slot status
 * @param error a GError, or NULL
 *
 * @return TRUE if the slot status was successfully loaded. FALSE if there were errors.
 */
gboolean r_slot_status_read(const gchar *filename, RaucSlotStatus *slotstatus, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Save slot status file.
 *
 * @param filename name of destination file
 * @param ss the slot status to save
 * @param error a GError, or NULL
 */
gboolean r_slot_status_write(const gchar *filename, RaucSlotStatus *ss, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Loads the status of all slots.
 *
 * Note: Callable from context setup.
 *
 * @param filename Status file to load from
 * @param slots Hast table of slots to set status for
 */
void r_slot_status_load_globally(const gchar *filename, GHashTable *slots);

/**
 * Load slot status.
 *
 * Takes care to fill in slot status information into the designated component
 * of the slot data structure. If the user configured a global status file in
 * the system.conf they are read from this file. Otherwise mount the given slot,
 * read the status information from its local status file and unmount the slot
 * afterwards. If a problem occurs the stored slot status consists of default
 * values. Do nothing if the status information have already been loaded before.
 *
 * @param dest_slot Slot to load status information for
 */
void r_slot_status_load(RaucSlot *dest_slot);

/**
 * Save slot status.
 *
 * This persists the status information from the designated component of the
 * given slot data structure. If the user configured a global status file in the
 * system.conf they are written to this file. Otherwise mount the given slot,
 * transfer the status information to the local status file and unmount the slot
 * afterwards.
 *
 * @param dest_slot Slot to write status information for
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if slot is not mountable or saving status succeeded, FALSE otherwise
 */
gboolean r_slot_status_save(RaucSlot *dest_slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

typedef struct {
	gchar *boot_id;
} RSystemStatus;

/**
 * Load system status from central status file.
 *
 * Note that filename and status are passed explicitly here since the method is
 * designed to be called during context setup where we cannot access context,
 * yet.
 *
 * @param filename File name to load status from
 * @param status RSystemStatus to update from file
 * @param[out] error Return location for a GError, or NULL
 *
 * @return
 */
gboolean r_system_status_load(const gchar *filename, RSystemStatus *status, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Save system status to central status file.
 *
 * @param[out] error Return location for a GError, or NULL
 */
gboolean r_system_status_save(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Free system status.
 *
 * @param status RSystemStatus to free
 */
void r_system_status_free(RSystemStatus *status);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RSystemStatus, r_system_status_free);
