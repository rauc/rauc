#include "authorize.h"

#if ENABLE_POLKIT
#include <polkit/polkit.h>

/* below the default D-Bus call timeout of 25 seconds */
#define AUTHORIZE_TIMEOUT 20
#define AUTHORIZE_INTERACTIVE_TIMEOUT 300

typedef struct {
	GDBusMethodInvocation *invocation;
	gchar *action_id;
	PolkitDetails *details;
	PolkitCheckAuthorizationFlags flags;
	GCancellable *cancellable;
	guint timeout_id;
	guint name_watch_id;
	const gchar *cancel_reason;
	RAuthorizedFunc func;
	gpointer data;
	GDestroyNotify data_free;
} RAuthorizeCall;

static PolkitAuthority *authority = NULL;
/* calls waiting for the authority, which is fetched once */
static GList *waiting = NULL;
static gboolean fetching = FALSE;

static void authorize_call_free(RAuthorizeCall *call)
{
	if (call->name_watch_id)
		g_bus_unwatch_name(call->name_watch_id);
	if (call->timeout_id)
		g_source_remove(call->timeout_id);
	g_object_unref(call->cancellable);
	g_object_unref(call->invocation);
	g_free(call->action_id);
	g_object_unref(call->details);
	g_free(call);
}

static void refuse(RAuthorizeCall *call, const gchar *reason)
{
	const gchar *sender = g_dbus_method_invocation_get_sender(call->invocation);

	if (call->cancel_reason)
		reason = call->cancel_reason;
	g_message("Refused %s for %s: %s", call->action_id,
			sender ? sender : "a peer-to-peer caller", reason);
	g_dbus_method_invocation_return_dbus_error(call->invocation,
			"org.freedesktop.DBus.Error.AccessDenied", reason);
	if (call->data_free)
		call->data_free(call->data);
	authorize_call_free(call);
}

static void authorized(RAuthorizeCall *call)
{
	call->func(call->invocation, call->data);
	authorize_call_free(call);
}

static gboolean refuse_waiting(gpointer user_data)
{
	RAuthorizeCall *call = user_data;

	refuse(call, call->cancel_reason);
	return G_SOURCE_REMOVE;
}

static void cancel(RAuthorizeCall *call, const gchar *reason)
{
	if (!call->cancel_reason)
		call->cancel_reason = reason;

	/* a call waiting for the authority has nothing to cancel yet */
	if (g_list_find(waiting, call)) {
		waiting = g_list_remove(waiting, call);
		g_idle_add(refuse_waiting, call);
		return;
	}
	g_cancellable_cancel(call->cancellable);
}

static gboolean on_timeout(gpointer user_data)
{
	RAuthorizeCall *call = user_data;

	call->timeout_id = 0;
	cancel(call, "polkit did not answer in time");
	return G_SOURCE_REMOVE;
}

static void on_sender_vanished(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
	RAuthorizeCall *call = user_data;

	g_message("Caller for %s left the bus before authorization completed", call->action_id);
	cancel(call, "the caller left the bus");
}

static gboolean on_system_bus(GDBusConnection *connection)
{
	g_autoptr(GDBusConnection) system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

	/* the GUID is the bus daemon's, so this also matches a second connection to it */
	return system_bus && g_strcmp0(g_dbus_connection_get_guid(system_bus),
			g_dbus_connection_get_guid(connection)) == 0;
}

static void on_check_done(GObject *source, GAsyncResult *res, gpointer user_data)
{
	RAuthorizeCall *call = user_data;
	g_autoptr(PolkitAuthorizationResult) result = NULL;
	g_autoptr(GError) ierror = NULL;

	result = polkit_authority_check_authorization_finish(POLKIT_AUTHORITY(source), res, &ierror);
	if (!result) {
		g_autofree gchar *reason = g_strdup_printf("authorization check failed: %s", ierror->message);
		refuse(call, reason);
		return;
	}
	/* a timeout or the caller leaving wins over an answer already queued */
	if (g_cancellable_is_cancelled(call->cancellable)) {
		refuse(call, "authorization cancelled");
		return;
	}
	if (!polkit_authorization_result_get_is_authorized(result)) {
		refuse(call, polkit_authorization_result_get_is_challenge(result)
				? "authentication required" : "not authorized");
		return;
	}

	authorized(call);
}

static void check(RAuthorizeCall *call)
{
	g_autoptr(PolkitSubject) subject = NULL;

	subject = polkit_system_bus_name_new(g_dbus_method_invocation_get_sender(call->invocation));

	polkit_authority_check_authorization(authority, subject, call->action_id, call->details,
			call->flags, call->cancellable, on_check_done, call);
}

static void on_authority(GObject *source, GAsyncResult *res, gpointer user_data)
{
	g_autoptr(GError) ierror = NULL;
	g_autoptr(GList) calls = g_steal_pointer(&waiting);

	fetching = FALSE;
	authority = polkit_authority_get_finish(res, &ierror);
	for (GList *l = calls; l != NULL; l = l->next) {
		RAuthorizeCall *call = l->data;

		if (authority) {
			check(call);
		} else {
			g_autofree gchar *reason = g_strdup_printf("no polkit authority: %s", ierror->message);
			refuse(call, reason);
		}
	}
}

static void on_credentials(GObject *source, GAsyncResult *res, gpointer user_data)
{
	RAuthorizeCall *call = user_data;
	g_autoptr(GVariant) reply = NULL;
	g_autoptr(GVariant) creds = NULL;
	g_autoptr(GError) ierror = NULL;
	guint32 uid;

	reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), res, &ierror);
	if (!reply) {
		g_autofree gchar *reason = g_strdup_printf("cannot identify the caller: %s", ierror->message);
		refuse(call, reason);
		return;
	}
	g_variant_get(reply, "(@a{sv})", &creds);
	if (!g_variant_lookup(creds, "UnixUserID", "u", &uid)) {
		refuse(call, "cannot identify the caller");
		return;
	}
	/* polkit allows root anyway, so do not depend on polkitd for it */
	if (uid == 0) {
		authorized(call);
		return;
	}
	/* polkit looks the caller's name up on the system bus */
	if (!on_system_bus(G_DBUS_CONNECTION(source))) {
		refuse(call, "polkit can only check callers on the system bus");
		return;
	}

	if (authority) {
		check(call);
		return;
	}

	/* polkit sets its authority up under a lock that the calling thread
	 * also takes, so concurrent fetches would block the main loop */
	waiting = g_list_append(waiting, call);
	if (!fetching) {
		fetching = TRUE;
		polkit_authority_get_async(NULL, on_authority, NULL);
	}
}

void r_authorize(GDBusMethodInvocation *invocation, const gchar *action_id,
		const gchar *const *details, RAuthorizedFunc func, gpointer data,
		GDestroyNotify data_free)
{
	RAuthorizeCall *call;
	const gchar *sender;

	g_return_if_fail(invocation);
	g_return_if_fail(action_id);
	g_return_if_fail(func);

	call = g_new0(RAuthorizeCall, 1);
	call->invocation = g_object_ref(invocation);
	call->action_id = g_strdup(action_id);
	call->details = polkit_details_new();
	call->cancellable = g_cancellable_new();
	call->func = func;
	call->data = data;
	call->data_free = data_free;

	for (const gchar *const *d = details; d && d[0]; d += 2)
		polkit_details_insert(call->details, d[0], d[1]);

	sender = g_dbus_method_invocation_get_sender(invocation);
	if (!sender) {
		refuse(call, "no caller to authorize");
		return;
	}

	/* cancel the check if the caller goes away */
	call->name_watch_id = g_bus_watch_name_on_connection(
			g_dbus_method_invocation_get_connection(invocation), sender,
			G_BUS_NAME_WATCHER_FLAGS_NONE, NULL, on_sender_vanished, call, NULL);

	if (g_dbus_message_get_flags(g_dbus_method_invocation_get_message(invocation)) &
	    G_DBUS_MESSAGE_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION)
		call->flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
	call->timeout_id = g_timeout_add_seconds(
			(call->flags & POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION)
			? AUTHORIZE_INTERACTIVE_TIMEOUT : AUTHORIZE_TIMEOUT,
			on_timeout, call);

	g_dbus_connection_call(g_dbus_method_invocation_get_connection(invocation),
			"org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
			"GetConnectionCredentials", g_variant_new("(s)", sender),
			G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE, -1,
			call->cancellable, on_credentials, call);
}

#else

void r_authorize(GDBusMethodInvocation *invocation, const gchar *action_id,
		const gchar *const *details, RAuthorizedFunc func, gpointer data,
		GDestroyNotify data_free)
{
	func(invocation, data);
}

#endif
