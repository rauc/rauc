#pragma once

#include <glib.h>

#include <checksum.h>

#if ENABLE_NETWORK
/**
 * Network initalization routine.
 *
 * Sets up libcurl.
 *
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean network_init(GError **error);
#else
static inline gboolean network_init(GError **error)
{
	return TRUE;
}
#endif

gboolean download_file(const gchar *target, const gchar *url, gsize limit, GError **error);
gboolean download_file_checksum(const gchar *target, const gchar *url,
		const RaucChecksum *checksum);
gboolean download_mem(GBytes **data, const gchar *url, gsize limit, GError **error);
