#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <glib-unix.h>
#include <gio/gio.h>

#include <context.h>
#include <install.h>
#include <service.h>
#include <mount.h>
#include "rauc-installer-generated.h"

GMainLoop *service_loop = NULL;
RInstaller *r_installer = NULL;
guint r_bus_name_id = 0;

static gboolean service_install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_message("installing %s: %s", args->name, msg);
		g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
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

/*
 * Builds GVariant structure from slot info.
 */
static GVariant** get_slot_status(RaucSlot *slot) {
	GVariant **g_slot_status;
	gchar *version = g_strdup("");

	if (slot->status) {
		version = g_strdup(slot->status->checksum.digest);
	}

	g_slot_status = g_new(GVariant*, 3);
	g_slot_status[0] = g_variant_new_string(slot->name);
	g_slot_status[1] = g_variant_new_string(slot->description);
	g_slot_status[2] = g_variant_new_string(version);
	return g_slot_status;
}

/*
 * Makes slot status information available via DBUS.
 */
static void set_slot_status_dbus(void) {
	GHashTableIter iter;
	gpointer key, value;
	gint slot_number = g_hash_table_size(r_context()->config->slots);
	GVariant **slot_status_tuples;
	GVariant *slot_status_array;
	gint slot_count = 0;

	slot_status_tuples = g_new(GVariant*, slot_number);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		RaucSlot *slot = value;
		GVariant **slot_status;
		slot_status = get_slot_status(value);
		slot_status_tuples[slot_count] = g_variant_new_tuple(
			slot_status, 3);
		if (slot->state == ST_BOOTED) {
			r_installer_set_booted_slot(r_installer,
						    g_strdup(slot->name));
		}
		slot_count++;
	}

	slot_status_array = g_variant_new_array(G_VARIANT_TYPE("(sss)"),
						slot_status_tuples,
						slot_number);
	r_installer_set_slot_status(r_installer, slot_status_array);
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
}

static void r_on_bus_acquired(GDBusConnection *connection,
			      const gchar     *name,
			      gpointer         user_data) {

	r_installer = r_installer_skeleton_new();

	g_signal_connect(r_installer, "handle-install",
			 G_CALLBACK(r_on_handle_install),
			 NULL);

	r_context_register_progress_callback(send_progress_callback);

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

	if (r_context()->config->autoinstall_path)
		auto_install(r_context()->config->autoinstall_path);

	set_slot_status_dbus();

	return;
}

static void r_on_name_lost(GDBusConnection *connection,
			   const gchar     *name,
			   gpointer         user_data) {
	g_message("name lost, stopping service");
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
	GBusType bus_type = G_BUS_TYPE_SYSTEM;

	if (g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session") == 0) {
		bus_type = G_BUS_TYPE_SESSION;
	}

	r_context_prepare();

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
