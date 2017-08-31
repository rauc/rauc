#include <config.h>

#include <gio/gio.h>
#include <glib-unix.h>
#include <glib.h>
#include <stdio.h>

#include "bundle.h"
#include "context.h"
#include "install.h"
#include "mark.h"
#include "rauc-installer-generated.h"
#include "service.h"
#include "utils.h"

GMainLoop *service_loop = NULL;
RInstaller *r_installer = NULL;
guint r_bus_name_id = 0;

static gboolean service_install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_message("installing %s: %s", args->name, msg);
	}
	g_mutex_unlock(&args->status_mutex);

	return G_SOURCE_REMOVE;
}

static gboolean service_install_cleanup(gpointer data)
{
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	if (args->status_result == 0) {
		g_message("installing `%s` succeeded", args->name);
	} else {
		g_message("installing `%s` failed: %d", args->name, args->status_result);
	}
	r_installer_emit_completed(r_installer, args->status_result);
	r_installer_set_operation(r_installer, "idle");
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
	g_mutex_unlock(&args->status_mutex);

	install_args_free(args);

	return G_SOURCE_REMOVE;
}

static gboolean r_on_handle_install(RInstaller *interface,
				    GDBusMethodInvocation  *invocation,
				    const gchar *source) {
	RaucInstallArgs *args = install_args_new();
	gboolean res;

	g_print("input bundle: %s\n", source);

	res = !r_context_get_busy();
	if (!res)
		goto out;

	args->name = g_strdup(source);
	args->notify = service_install_notify;
	args->cleanup = service_install_cleanup;

	r_installer_set_operation(r_installer, "installing");
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
	res = install_run(args);
	if (!res) {
		goto out;
	}
	args = NULL;

out:
	g_clear_pointer(&args, g_free);
	if (res) {
		r_installer_complete_install(interface, invocation);
	} else {
		r_installer_set_operation(r_installer, "idle");
		g_dbus_method_invocation_return_error(invocation,
				 		      G_IO_ERROR,
						      G_IO_ERROR_FAILED_HANDLED,
						      "rauc installer error");
	}

	return TRUE;
}


static gboolean r_on_handle_info(RInstaller *interface,
				 GDBusMethodInvocation  *invocation,
				 const gchar *arg_bundle)
{
	gchar* tmpdir = NULL;
	gchar* bundledir = NULL;
	gchar* manifestpath = NULL;
	RaucManifest *manifest = NULL;
	RaucBundle *bundle = NULL;
	GError *error = NULL;
	gboolean res = TRUE;

	g_print("bundle: %s\n", arg_bundle);

	res = !r_context_get_busy();
	if (!res)
		goto out;

	tmpdir = g_dir_make_tmp("bundle-XXXXXX", &error);
	if (!tmpdir) {
		g_warning("%s", error->message);
		g_clear_error(&error);
		res = FALSE;
		goto out;
	}

	bundledir = g_build_filename(tmpdir, "bundle-content", NULL);
	manifestpath = g_build_filename(bundledir, "manifest.raucm", NULL);

	res = check_bundle(arg_bundle, &bundle, TRUE, &error);
	if (!res) {
		g_warning("%s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = extract_file_from_bundle(bundle, bundledir, "manifest.raucm", &error);
	if (!res) {
		g_warning("%s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = load_manifest_file(manifestpath, &manifest, &error);
	if (!res) {
		g_warning("%s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:
	if (tmpdir)
		rm_tree(tmpdir, NULL);

	g_clear_pointer(&tmpdir, g_free);
	g_clear_pointer(&bundledir, g_free);
	g_clear_pointer(&manifestpath, g_free);

	if (res) {
		r_installer_complete_info(
				interface,
				invocation,
				manifest->update_compatible,
				manifest->update_version ? manifest->update_version : "");
	} else {
		g_dbus_method_invocation_return_error(invocation,
						      G_IO_ERROR,
						      G_IO_ERROR_FAILED_HANDLED,
						      "rauc info error");
	}

	g_clear_pointer(&bundle, free_bundle);

	return TRUE;
}

static gboolean r_on_handle_mark(RInstaller *interface,
				 GDBusMethodInvocation  *invocation,
				 const gchar *arg_state,
				 const gchar *arg_slot_identifier)
{
	gchar *slot_name = NULL;
	gchar *message = NULL;
	GError *ierror = NULL;
	gboolean res;

	res = !r_context_get_busy();
	if (!res) {
		message = g_strdup("already processing a different method");
		goto out;
	}

	res = determine_slot_states(&ierror);
	if (!res) {
		message = g_strdup_printf("Failed to determine slot states: %s\n", ierror->message);
		g_clear_error(&ierror);
		goto out;
	}

	res = mark_run(arg_state, arg_slot_identifier, &slot_name, &message);

out:
	if (res) {
		r_installer_complete_mark(interface, invocation, slot_name, message);
	} else {
		g_dbus_method_invocation_return_error(invocation,
						      G_IO_ERROR,
						      G_IO_ERROR_FAILED_HANDLED,
						      "%s", message);
	}
	if (message)
		g_message("rauc mark: %s", message);

	g_free(slot_name);
	g_free(message);

	return TRUE;
}

static gboolean auto_install(const gchar *source) {
	RaucInstallArgs *args = install_args_new();
	gboolean res = TRUE;

	if (!g_file_test(r_context()->config->autoinstall_path, G_FILE_TEST_EXISTS))
		return FALSE;

	g_message("input bundle: %s", source);

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
	g_clear_pointer(&args, g_free);

	return res;
}

void set_last_error(gchar *message) {
	if (r_installer)
		r_installer_set_last_error(r_installer, message);
}

static void send_progress_callback(gint percentage,
				   const gchar *message,
				   gint nesting_depth) {

	GVariant **progress_update;
	GVariant *progress_update_tuple;

	progress_update = g_new(GVariant*, 3);
	progress_update[0] = g_variant_new_int32(percentage);
	progress_update[1] = g_variant_new_string(message);
	progress_update[2] = g_variant_new_int32(nesting_depth);

	progress_update_tuple = g_variant_new_tuple(progress_update, 3);
	r_installer_set_progress(r_installer, progress_update_tuple);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
}

static void r_on_bus_acquired(GDBusConnection *connection,
			      const gchar     *name,
			      gpointer         user_data) {
	GError *ierror = NULL;

	r_installer = r_installer_skeleton_new();

	g_signal_connect(r_installer, "handle-install",
			 G_CALLBACK(r_on_handle_install),
			 NULL);

	g_signal_connect(r_installer, "handle-info",
			 G_CALLBACK(r_on_handle_info),
			 NULL);

	g_signal_connect(r_installer, "handle-mark",
			 G_CALLBACK(r_on_handle_mark),
			 NULL);

	r_context_register_progress_callback(send_progress_callback);

	// Set initial Operation status to "idle"
	r_installer_set_operation(r_installer, "idle");

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(r_installer),
					      connection,
					      "/",
					      &ierror)) {
		g_error("Failed to export interface: %s", ierror->message);
		g_error_free (ierror);
	}

	return;
}

static void r_on_name_acquired(GDBusConnection *connection,
			       const gchar     *name,
			       gpointer         user_data) {
	g_debug("name '%s' acquired", name);

	if (r_context()->config->autoinstall_path)
		auto_install(r_context()->config->autoinstall_path);

	return;
}

static void r_on_name_lost(GDBusConnection *connection,
			   const gchar     *name,
			   gpointer         user_data) {
	if (connection == NULL) {
		g_message("Connection to the bus can't be made for %s", name);
	} else {
		g_message("Failed to obtain name %s", name);
	}

	if (service_loop) {
		g_main_loop_quit(service_loop);
	}

	return;
}

static gboolean r_on_signal(gpointer user_data)
{
	g_message("stopping service");
	if (service_loop) {
		g_main_loop_quit(service_loop);
	}
	return G_SOURCE_REMOVE;
}

gboolean r_service_run(void) {
	GBusType bus_type = (!g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session"))
		? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;

	r_context();

	service_loop = g_main_loop_new(NULL, FALSE);
	g_unix_signal_add(SIGTERM, r_on_signal, NULL);

	r_bus_name_id = g_bus_own_name(bus_type,
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
	service_loop = NULL;

	return TRUE;
}
