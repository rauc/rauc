#pragma once

#include <glib.h>

#include <slot.h>
#include <config_file.h>

gchar *r_raspberrypi_get_bootname(RaucConfig *config, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_raspberrypi_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_raspberrypi_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_raspberrypi_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_raspberrypi_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
