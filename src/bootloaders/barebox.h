#pragma once

#include <glib.h>

#include <slot.h>

gchar *r_barebox_get_current_bootname(const gchar *cmdline, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_set_lock_counter(gboolean locked, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_get_lock_counter(gboolean *locked, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_barebox_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_barebox_get_state(RaucSlot* slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
