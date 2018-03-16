#pragma once

#include <glib.h>

void mark_active(RaucSlot *slot, GError **error);

gboolean mark_run(const gchar *state,
		const gchar *slot_identifier,
		gchar **slot_name,
		gchar **message);
