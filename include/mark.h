#pragma once

#include <glib.h>

#include "slot.h"

gboolean mark_active(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean mark_run(const gchar *state,
		const gchar *slot_identifier,
		gchar **slot_name,
		gchar **message)
G_GNUC_WARN_UNUSED_RESULT;
