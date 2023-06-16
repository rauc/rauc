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
gboolean read_slot_status(const gchar *filename, RaucSlotStatus *slotstatus, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Save slot status file.
 *
 * @param filename name of destination file
 * @param ss the slot status to save
 * @param error a GError, or NULL
 */
gboolean write_slot_status(const gchar *filename, RaucSlotStatus *ss, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
void load_slot_status(RaucSlot *dest_slot);

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
gboolean save_slot_status(RaucSlot *dest_slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
