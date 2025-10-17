#pragma once

#include <glib.h>

#define R_SERVICE_ERROR r_service_error_quark()
GQuark r_service_error_quark(void);

typedef enum {
	R_SERVICE_ERROR_FAILED,
} RServiceError;

/**
 * Run the service (blocking).
 *
 * @param error a GError, or NULL
 *
 * @return TRUE if running the service was successful. FALSE if there were
 * errors.
 */
gboolean r_service_run(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

void set_last_error(const gchar *message);
