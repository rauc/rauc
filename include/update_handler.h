#pragma once

#include <glib.h>

#include "config_file.h"
#include "manifest.h"

#define R_UPDATE_ERROR r_update_error_quark()

GQuark r_update_error_quark(void);

typedef enum {
	R_UPDATE_ERROR_FAILED,
	R_UPDATE_ERROR_NO_HANDLER,
	R_UPDATE_ERROR_UNSUPPORTED_ADAPTIVE_MODE,
	R_UPDATE_ERROR_EMMC_MIGRATION,
} RUpdateError;

typedef gboolean (*img_to_slot_handler)(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot  *dest_slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Matches the file name extension of the input filename with a corresponding
 * image type.
 *
 * Uses the internal matching 'ext_type_map'.
 *
 * @param filename name of image file to inspect
 *
 * @return matching image type, or NULL if none found
 */
const gchar* derive_image_type_from_filename_pattern(const gchar *filename)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Checks if the provided name is a valid image type.
 *
 * Uses the internal 'image_type_map' to check for supported types.
 *
 * @param type name of an image type
 *
 * @return TRUE if supported, FALSE otherwise
 */
gboolean is_image_type_supported(const gchar *type)
G_GNUC_WARN_UNUSED_RESULT;

struct boot_switch_partition {
	guint64 start;          /* address in bytes */
	guint64 size;           /* size in bytes */
};
