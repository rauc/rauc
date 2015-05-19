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
	gchar *msg = NULL;

	g_message("foo!\n");

	r_installer_set_busy(r_installer, FALSE);
	msg = g_strdup_printf("done result=%d", args->result);
	r_installer_set_operation(r_installer, msg);
	g_free(msg);

	return G_SOURCE_REMOVE;
}

static gboolean service_install_cleanup(gpointer data)
{
	(void) data;

	return G_SOURCE_REMOVE;
}

static gboolean r_on_handle_install(RInstaller *interface,
				    GDBusMethodInvocation  *invocation,
				    const gchar *source) {
	RaucInstallArgs *args = g_new0(RaucInstallArgs, 1);
	gchar *msg = NULL;
	gboolean res;

	g_print("input bundle: %s\n", source);

	res = !r_installer_get_busy(r_installer);
	if (!res)
		goto out;

	r_installer_set_busy(r_installer, TRUE);
	msg = g_strdup_printf("install source=%s", source);
	r_installer_set_operation(r_installer, msg);

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
		r_installer_set_busy(r_installer, FALSE);
		r_installer_set_operation(r_installer, "failed");
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
	return;
}

static void r_on_name_lost(GDBusConnection *connection,
			   const gchar     *name,
			   gpointer         user_data) {
	return;
}

gboolean r_service_run(void) {
	r_context();

	service_loop = g_main_loop_new(NULL, FALSE);

	r_bus_name_id = g_bus_own_name(G_BUS_TYPE_SESSION,
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
