#pragma once

#include <glib.h>

#include "manifest.h"

typedef gboolean (*img_to_slot_handler) (RaucImage *image, RaucSlot *dest_slot, const gchar *hook_name, GError **error);

img_to_slot_handler get_update_handler(RaucImage *mfimage, RaucSlot  *dest_slot, GError **error);
