#pragma once

#include <glib.h>

#include "config_file.h"
#include "manifest.h"

#define R_UPDATE_ERROR r_update_error_quark()

GQuark r_update_error_quark(void);

typedef enum {
	R_UPDATE_ERROR_FAILED,
	R_UPDATE_ERROR_NO_HANDLER
} RUpdateError;

typedef gboolean (*img_to_slot_handler) (RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error);

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot  *dest_slot, GError **error);
