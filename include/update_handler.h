#pragma once

#include <glib.h>

#include "config_file.h"
#include "manifest.h"

#define R_UPDATE_ERROR r_update_error_quark()

GQuark r_update_error_quark(void);

typedef enum {
	R_UPDATE_ERROR_FAILED,
	R_UPDATE_ERROR_NO_HANDLER,
	R_UPDATE_ERROR_UNSUPPORTED_INCREMENTAL_MODE,
} RUpdateError;

typedef gboolean (*img_to_slot_handler)(RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot  *dest_slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

struct boot_switch_partition {
	guint64 start;          /* address in bytes */
	guint64 size;           /* size in bytes */
};
