#pragma once

#include <glib.h>

#include "manifest.h"

typedef gboolean (*img_to_fs_handler) (RaucImage *image, RaucSlot *dest_slot, GError **error);

img_to_fs_handler get_update_handler(RaucImage *mfimage, RaucSlot  *dest_slot, GError **error);
