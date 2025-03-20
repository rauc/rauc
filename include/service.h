#pragma once

#include <glib.h>

#include "rauc-installer-generated.h"

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

/* used by poll.c */
extern RInstaller *r_installer;

/* Track whether the running slot has been marked as good.
 * This is used to inhibit polling until we have something to fall back to.
 * Currently, this information is lost when restarting the service, so this
 * approach should be reworked when we have explicit tracking of
 * installation cycles.
 **/
extern gboolean r_service_booted_slot_is_good;
