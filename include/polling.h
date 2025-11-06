#pragma once

#include <glib.h>
#include <gio/gio.h>

#define R_POLLING_ERROR r_polling_error_quark()
GQuark r_polling_error_quark(void);

typedef enum {
	R_POLLING_ERROR_DISABLED,
	R_POLLING_ERROR_INVALID_BUNDLE,
	R_POLLING_ERROR_CONFIG,
} RPollingError;

/**
 * Register Poller interface.
 *
 * @param connection the connection on which the name was acquired
 */
void r_polling_on_bus_acquired(GDBusConnection *connection);

/**
 * Set up the polling GSource and D-Bus interface.
 *
 * @param error a GError, or NULL
 *
 * @return TRUE if setup was successful
 */
gboolean r_polling_setup(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Names of supported and default criteria for the configuration.
 */
extern const gchar * const r_polling_supported_candidate_criteria[];
extern const gchar * const r_polling_default_candidate_criteria[];
extern const gchar * const r_polling_supported_install_criteria[];
extern const gchar * const r_polling_supported_reboot_criteria[];
