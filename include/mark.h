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
 * Check whether a slot identifier names the booted slot.
 *
 * @param slot_identifier String representation of slot identifier
 *                        (e.g. "booted" or the slot name)
 *
 * @return TRUE if one of the slots it names is the booted one
 */
gboolean r_mark_names_booted_slot(const gchar *slot_identifier);

typedef struct {
	/* all of them are "ok" and from the same bundle */
	gboolean install_complete;
	/* all of them are at or above min-bundle-version */
	gboolean meets_version_limit;
	/* the slot was activated after it was last installed */
	gboolean activated_since_install;
} RMarkActivationChecks;

/**
 * Check the status of a slot and its children before activating it.
 *
 * All checks are FALSE for an identifier that does not name exactly one slot.
 *
 * @param slot_identifier String representation of slot identifier
 *                        (e.g. "other" or the slot name)
 * @param checks Return location for the results
 */
void r_mark_activation_checks(const gchar *slot_identifier, RMarkActivationChecks *checks);

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
