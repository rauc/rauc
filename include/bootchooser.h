#pragma once

#include <glib.h>

#include "config_file.h"

/**
 * Mark slot as non-bootable.
 *
 * @param slot Slot to mark
 *
 * @return TRUE if successfull, FALSE if failed
 */
gboolean r_boot_disable(RaucSlot *slot);

/**
 * Mark slot as primary boot option of its slot class.
 *
 * @param slot Slot to mark
 *
 * @return TRUE if successfull, FALSE if failed
 */
gboolean r_boot_set_primary(RaucSlot *slot);
