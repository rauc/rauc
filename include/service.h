#pragma once

#include <glib.h>

#include "rauc-installer-generated.h"

gboolean r_service_run(void)
G_GNUC_WARN_UNUSED_RESULT;
void set_last_error(const gchar *message);

/* used by poll.c */
extern RInstaller *r_installer;
