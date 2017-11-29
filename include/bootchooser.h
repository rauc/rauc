#pragma once

#include <glib.h>

#include "config_file.h"

#define R_BOOTCHOOSER_ERROR r_bootchooser_error_quark ()
GQuark r_bootchooser_error_quark (void);

#define R_BOOTCHOOSER_ERROR_FAILED		0
#define R_BOOTCHOOSER_ERROR_NOT_SUPPORTED	10
#define R_BOOTCHOOSER_ERROR_PARSE_FAILED	20

/**
 * Mark slot as good or bad.
 *
 * @param slot Slot to mark
 * @param good Whether to mark it as good (instead of bad)
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if successful, FALSE if failed
 */
gboolean r_boot_set_state(RaucSlot *slot, gboolean good, GError **error);

/**
 * Mark slot as primary boot option of its slot class.
 *
 * @param slot Slot to mark
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if successful, FALSE if failed
 */
gboolean r_boot_set_primary(RaucSlot *slot, GError **error);
