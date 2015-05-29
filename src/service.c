#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <context.h>
#include <install.h>
#include <service.h>
#include "rauc-installer-generated.h"

GMainLoop *service_loop = NULL;
RInstaller *r_installer = NULL;
guint r_bus_name_id = 0;

static gboolean service_install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_message("installing %s: %s\n", args->name, msg);
		r_installer_set_operation(r_installer, msg);
		g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
	}
	g_mutex_unlock(&args->status_mutex);

	return G_SOURCE_REMOVE;
}

static gboolean service_install_cleanup(gpointer data)
{
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	g_message("installing %s done: %d\n", args->name, args->status_result);
	r_installer_emit_completed(r_installer, args->status_result);
	g_mutex_unlock(&args->status_mutex);

	install_args_free(args);

	return G_SOURCE_REMOVE;
}

static gboolean r_on_handle_install(RInstaller *interface,
				    GDBusMethodInvocation  *invocation,
				    const gchar *source) {
	RaucInstallArgs *args = install_args_new();
	gchar *msg = NULL;
	gboolean res;

	g_print("input bundle: %s\n", source);

	res = !r_context_get_busy();
	if (!res)
		goto out;

	args->name = g_strdup(source);
	args->notify = service_install_notify;
	args->cleanup = service_install_cleanup;

	res = install_run(args);
	if (!res) {
		goto out;
	}
	args = NULL;

out:
	g_clear_pointer(&msg, g_free);
	g_clear_pointer(&args, g_free);
	if (res) {
		r_installer_complete_install(interface, invocation);
	} else {
		g_dbus_method_invocation_return_error(invocation,
				 		      G_IO_ERROR,
						      G_IO_ERROR_FAILED_HANDLED,
						      "rauc installer error");
	}

	return TRUE;
}

static void r_on_bus_acquired(GDBusConnection *connection,
			      const gchar     *name,
			      gpointer         user_data) {

	r_installer = r_installer_skeleton_new();

	g_signal_connect(r_installer, "handle-install",
			 G_CALLBACK(r_on_handle_install),
			 NULL);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(r_installer),
					      connection,
					      "/",
					      NULL)) {
		g_error("Failed to export interface");
	}

	return;
}

static void r_on_name_acquired(GDBusConnection *connection,
			       const gchar     *name,
			       gpointer         user_data) {
	g_message("name acquired");
	return;
}

static void r_on_name_lost(GDBusConnection *connection,
			   const gchar     *name,
			   gpointer         user_data) {
	g_message("name lost, stopping service\n");
	g_main_loop_quit(service_loop);

	return;
}

gboolean r_service_run(void) {
	r_context();

	service_loop = g_main_loop_new(NULL, FALSE);

	r_bus_name_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				       "de.pengutronix.rauc",
				       G_BUS_NAME_OWNER_FLAGS_NONE,
				       r_on_bus_acquired,
				       r_on_name_acquired,
				       r_on_name_lost,
				       NULL, NULL);

	g_main_loop_run(service_loop);

	if (r_bus_name_id)
		g_bus_unown_name(r_bus_name_id);

	g_main_loop_unref(service_loop);

	return TRUE;
}
