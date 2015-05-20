#pragma once

#include <glib.h>

#include "config_file.h"

/**
 * Mark slot as good or bad.
 *
 * @param slot Slot to mark
 * @param good Whether to mark it as good (instead of bad)
 *
 * @return TRUE if successfull, FALSE if failed
 */
gboolean r_boot_set_state(RaucSlot *slot, gboolean good);

/**
 * Mark slot as primary boot option of its slot class.
 *
 * @param slot Slot to mark
 *
 * @return TRUE if successfull, FALSE if failed
 */
gboolean r_boot_set_primary(RaucSlot *slot);
