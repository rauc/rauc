#pragma once

#include <glib.h>

#include "context.h"

#define R_BOOTCHOOSER_ERROR r_bootchooser_error_quark()
GQuark r_bootchooser_error_quark(void);

#define R_BOOTCHOOSER_ERROR_FAILED		0
#define R_BOOTCHOOSER_ERROR_NOT_SUPPORTED	10
#define R_BOOTCHOOSER_ERROR_PARSE_FAILED	20

/**
 * Check if bootloader (name) is supported
 *
 * @param typename Name of bootloader as represented in config
 *
 * @return TRUE if it is supported, otherwise FALSE
 */
gboolean r_boot_is_supported_bootloader(const gchar *bootloader)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get current bootname slot.
 *
 * @param config the RaucConfig
 * @param error return location for a GError, or NULL
 *
 * @return bootname, NULL if detection failed
 */
gchar *r_boot_get_current_bootname(RaucConfig *config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mark slot as good or bad.
 *
 * @param slot Slot to mark
 * @param good Whether to mark it as good (instead of bad)
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if successful, FALSE if failed
 */
gboolean r_boot_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Mark slot as primary boot option of its slot class.
 *
 * @param slot Slot to mark
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if successful, FALSE if failed
 */
gboolean r_boot_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get primary boot slot.
 *
 * @param error return location for a GError, or NULL
 *
 * @return Primary slot, NULL if detection failed
 */
RaucSlot *r_boot_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get bootloader state.
 *
 * @param slot Slot to get boot state from
 * @param good return location for slot status.
 *             TRUE means 'good', FALSE means 'bad')
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if successful, FALSE if failed
 */
gboolean r_boot_get_state(RaucSlot *slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_barebox_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gchar *r_custom_get_current_bootname(RaucConfig *config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_custom_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_custom_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_custom_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_custom_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_efi_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_efi_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_efi_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_efi_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_grub_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_grub_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_grub_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_grub_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_uboot_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_uboot_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_uboot_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_uboot_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
