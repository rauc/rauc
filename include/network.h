#pragma once

#include <glib.h>

#include <checksum.h>

void network_init(void);

gboolean download_file(const gchar *target, const gchar *url, gsize limit);
gboolean download_file_checksum(const gchar *target, const gchar *url,
				const RaucChecksum *checksum);
gboolean download_mem(GBytes **data, const gchar *url, gsize limit);
