#pragma once

#include <glib.h>

gboolean mark_run(const gchar *state,
		  const gchar *slot_identifier,
		  gchar **slot_name,
		  gchar **message);
