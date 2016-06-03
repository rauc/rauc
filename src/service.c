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
		g_message("installing %s: %s\n", args->name, msg);
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

	g_message("input bundle: %s\n", source);

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
 * Retrieves slot information from config and adds information from slot
 * status files when possible
 */
static gboolean set_slot_status(void) {
	GHashTableIter iter;
	gpointer key, value;
	RaucSlot *booted = NULL;
	gboolean res = FALSE;
	gint slot_number = g_hash_table_size(r_context()->config->slots);
	GVariant **slot_status_tuples;
	GVariant *slot_status_array;
	gint slot_count = 0;

	slot_status_tuples = g_new(GVariant*, slot_number);

	res = determine_slot_states(NULL);
	if (!res)
		return FALSE;

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		gchar *name = key;
		RaucSlot *slot = value;
		gchar *slotstatuspath = NULL;
		RaucSlotStatus *slot_state = NULL;
		gchar *version = g_strdup("");
		GVariant **slot_status;

		res = r_mount_slot(slot, NULL);
		if (res) {
			slotstatuspath = g_build_filename(slot->mount_point, "slot.raucs", NULL);
			res = load_slot_status(slotstatuspath, &slot_state, NULL);
			if (res) {
				version = g_strdup(slot_state->checksum.digest);
				g_clear_pointer(&slot_state, free_slot_status);

			}
			r_umount_slot(slot, NULL);
			g_clear_pointer(&slotstatuspath, g_free);
		}

		if (slot->state == ST_BOOTED)
			booted = slot;

		slot_status = g_new(GVariant*, 3);
		slot_status[0] = g_variant_new_string(name);
		slot_status[1] = g_variant_new_string(slot->description);
		slot_status[2] = g_variant_new_string(version);
		slot_status_tuples[slot_count] = g_variant_new_tuple(slot_status, 3);

		slot_count++;
	}

	slot_status_array = g_variant_new_array(G_VARIANT_TYPE("(sss)"), slot_status_tuples, slot_number);
	r_installer_set_slot_status(r_installer, slot_status_array);

	if (booted)
		r_installer_set_booted_slot(r_installer, g_strdup(booted->name));

	return TRUE;
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
	r_installer_set_progress_updated(r_installer, progress_update_tuple);
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

	set_slot_status();

	return;
}

static void r_on_name_lost(GDBusConnection *connection,
			   const gchar     *name,
			   gpointer         user_data) {
	g_message("name lost, stopping service\n");
	if (service_loop) {
		g_main_loop_quit(service_loop);
	}

	return;
}

static gboolean r_on_signal(gpointer user_data)
{
	g_message("stopping service\n");
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
