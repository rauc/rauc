#pragma once

#include <glib.h>

void network_init(void);

gboolean download_file(const gchar *target, const gchar *tmpname,
		       const gchar *url, gsize limit);
gboolean download_mem(GBytes **data, const gchar *url, gsize limit);
