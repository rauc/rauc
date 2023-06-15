#pragma once

#include <glib.h>

gboolean r_service_run(void)
G_GNUC_WARN_UNUSED_RESULT;
void set_last_error(const gchar *message);
