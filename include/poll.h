#pragma once

#include <glib.h>
#include <gio/gio.h>

/**
 * Register Poller interface.
 *
 * @param connection the connection on which the name was acquired
 */
void r_poll_on_bus_acquired(GDBusConnection *connection);

/**
 * Set up the polling GSource and D-Bus interface.
 *
 * @return new GSource or NULL if polling is disabled
 */
GSource *r_poll_setup(void)
G_GNUC_WARN_UNUSED_RESULT;
