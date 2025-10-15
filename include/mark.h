#pragma once

#include <glib.h>

#include "slot.h"

/**
 * Mark a bootname slot as active.
 *
 * This means it is expected to be the next being booted.
 *
 * @param slot Slot to mark as active
 * @param error Return location for a GError
 *
 * @return Return TRUE on success and FALSE on error
 */
gboolean r_mark_active(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mark a bootname slot as good.
 *
 * This means it is considered working after an update.
 *
 * @param slot Slot to mark as good
 * @param error Return location for a GError
 *
 * @return Return TRUE on success and FALSE on error
 */
gboolean r_mark_good(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mark a bootname slot as bad.
 *
 * This means it is considered broken after an update.
 *
 * @param slot Slot to mark as bad
 * @param error Return location for a GError
 *
 * @return Return TRUE on success and FALSE on error
 */
gboolean r_mark_bad(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mark a bootname slot.
 *
 * @param state String representation of slot state
 *              (e.g. "good", "bad", or "active")
 * @param slot_identifier String representation of slot identifier
 *                        (e.g. "booted", "other", or the slot name)
 * @param slot_name Return location for the resulting slot name
 * @param message Return location for message describing what has been done
 *                (e.g. "marked slot(s) rootfs.0 as good")
 *
 * @return Return TRUE on success and FALSE on error
 */
gboolean mark_run(const gchar *state,
		const gchar *slot_identifier,
		gchar **slot_name,
		gchar **message)
G_GNUC_WARN_UNUSED_RESULT;
