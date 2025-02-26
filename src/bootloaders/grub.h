#pragma once

#include <glib.h>

#include <slot.h>

gboolean r_grub_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_grub_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_grub_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_grub_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
