#pragma once

#include <gio/gio.h>

/**
 * Called once the caller is authorized, takes ownership of data and must reply
 * to invocation exactly once.
 */
typedef void (*RAuthorizedFunc)(GDBusMethodInvocation *invocation, gpointer data);

/**
 * Asks polkit whether the caller of invocation may perform action_id.
 *
 * If refused, returns an AccessDenied error on invocation and frees data.
 * Without polkit support, func is called directly.
 *
 * @param invocation the method call to authorize
 * @param action_id the polkit action, e.g. "de.pengutronix.rauc.install"
 * @param details NULL-terminated key, value pairs that polkit rules can inspect
 *        (action.lookup("key")), or NULL
 * @param func called with invocation and data once authorized
 * @param data passed to func
 * @param data_free releases data if the caller is refused
 */
void r_authorize(GDBusMethodInvocation *invocation, const gchar *action_id,
		const gchar *const *details, RAuthorizedFunc func, gpointer data,
		GDestroyNotify data_free);
