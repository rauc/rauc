#pragma once

#include <glib.h>

#include <checksum.h>

#if ENABLE_NETWORK
void network_init(void);
#else
static inline void network_init(void)
{
	return;
}
#endif

gboolean download_file(const gchar *target, const gchar *url, gsize limit, GError **error);
gboolean download_file_checksum(const gchar *target, const gchar *url,
		const RaucChecksum *checksum);
gboolean download_mem(GBytes **data, const gchar *url, gsize limit);
