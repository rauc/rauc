#pragma once

#include <glib.h>

#include "config_file.h"

/**
 * Mark slot as (non)bootable for the bootloader.
 *
 * @param slot Slot to mark
 * @param bootable TRUE for marking as *bootable*, FALSE for marking as *non-bootable*
 *
 * @return TRUE if successfull, FALSE if failed
 */
gboolean r_boot_mark_bootable(RaucSlot *slot, gboolean bootable);
