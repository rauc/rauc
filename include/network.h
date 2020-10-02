#pragma once

#include <glib.h>

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
gboolean network_init(GError **error)
G_GNUC_WARN_UNUSED_RESULT;
#else
static inline gboolean network_init(GError **error)
{
	return TRUE;
}
#endif

gboolean download_file(const gchar *target, const gchar *url, goffset limit, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
