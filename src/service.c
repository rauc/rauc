#include <gio/gio.h>
#include <glib-unix.h>
#include <glib.h>
#include <stdio.h>

#include "bundle.h"
#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "install.h"
#include "mark.h"
#include "rauc-installer-generated.h"
#include "service.h"
#include "utils.h"

GMainLoop *service_loop = NULL;
RInstaller *r_installer = NULL;
guint r_bus_name_id = 0;

static gboolean service_install_notify(gpointer data)
{
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
		const gchar *source)
{
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
	g_autofree gchar* tmpdir = NULL;
	g_autofree gchar* bundledir = NULL;
	g_autofree gchar* manifestpath = NULL;
	RaucManifest *manifest = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
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

	return TRUE;
}

static gboolean r_on_handle_mark(RInstaller *interface,
		GDBusMethodInvocation  *invocation,
		const gchar *arg_state,
		const gchar *arg_slot_identifier)
{
	g_autofree gchar *slot_name = NULL;
	g_autofree gchar *message = NULL;
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

	return TRUE;
}

/*
 * Constructs a GVariant dictionary representing a slot status.
 */
static GVariant* convert_slot_status_to_dict(RaucSlot *slot)
{
	RaucSlotStatus *slot_state = NULL;
	GVariantDict dict;

	load_slot_status(slot);
	slot_state = slot->status;

	g_variant_dict_init(&dict, NULL);

	if (slot->sclass)
		g_variant_dict_insert(&dict, "class", "s", slot->sclass);
	if (slot->device)
		g_variant_dict_insert(&dict, "device", "s", slot->device);
	if (slot->type)
		g_variant_dict_insert(&dict, "type", "s", slot->type);
	if (slot->bootname)
		g_variant_dict_insert(&dict, "bootname", "s", slot->bootname);
	if (slot->state)
		g_variant_dict_insert(&dict, "state", "s", slotstate_to_str(slot->state));
	if (slot->description)
		g_variant_dict_insert(&dict, "description", "s", slot->description);
	if (slot->parent)
		g_variant_dict_insert(&dict, "parent", "s", slot->parent->name);
	if (slot->mount_point || slot->ext_mount_point)
		g_variant_dict_insert(&dict, "mountpoint", "s", slot->mount_point ? slot->mount_point : slot->ext_mount_point);
	if (slot->bootname)
		g_variant_dict_insert(&dict, "boot-status", "s", slot->boot_good ? "good" : "bad");

	if (slot_state->bundle_compatible)
		g_variant_dict_insert(&dict, "bundle.compatible", "s", slot_state->bundle_compatible);

	if (slot_state->bundle_version)
		g_variant_dict_insert(&dict, "bundle.version", "s", slot_state->bundle_version);

	if (slot_state->bundle_description)
		g_variant_dict_insert(&dict, "bundle.description", "s", slot_state->bundle_description);

	if (slot_state->bundle_build)
		g_variant_dict_insert(&dict, "bundle.build", "s", slot_state->bundle_build);

	if (slot_state->status)
		g_variant_dict_insert(&dict, "status", "s", slot_state->status);

	if (slot_state->checksum.digest && slot_state->checksum.type == G_CHECKSUM_SHA256) {
		g_variant_dict_insert(&dict, "sha256", "s", slot_state->checksum.digest);
		g_variant_dict_insert(&dict, "size", "t", (guint64) slot_state->checksum.size);
	}

	if (slot_state->installed_timestamp) {
		g_variant_dict_insert(&dict, "installed.timestamp", "s", slot_state->installed_timestamp);
		g_variant_dict_insert(&dict, "installed.count", "u", slot_state->installed_count);
	}

	if (slot_state->activated_timestamp) {
		g_variant_dict_insert(&dict, "activated.timestamp", "s", slot_state->activated_timestamp);
		g_variant_dict_insert(&dict, "activated.count", "u", slot_state->activated_count);
	}

	return g_variant_dict_end(&dict);
}

/*
 * Makes slot status information available via DBUS.
 */
static GVariant* create_slotstatus_array(void)
{
	gint slot_number = g_hash_table_size(r_context()->config->slots);
	GVariant **slot_status_tuples;
	GVariant *slot_status_array;
	gint slot_count = 0;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(r_installer, NULL);

	slot_status_tuples = g_new(GVariant*, slot_number);

	res = determine_slot_states(&ierror);
	if (!res) {
		g_debug("Failed to determine slot states: %s\n", ierror->message);
		g_clear_error(&ierror);
	}

	res = determine_boot_states(&ierror);
	if (!res) {
		g_debug("Failed to determine boot states: %s\n", ierror->message);
		g_clear_error(&ierror);
	}

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		GVariant* slot_status[2];

		slot_status[0] = g_variant_new_string(slot->name);
		slot_status[1] = convert_slot_status_to_dict(slot);

		slot_status_tuples[slot_count] = g_variant_new_tuple(slot_status, 2);
		slot_count++;
	}

	/* it's an array of (slotname, dict) tuples */
	slot_status_array = g_variant_new_array(G_VARIANT_TYPE("(sa{sv})"), slot_status_tuples, slot_number);
	g_free(slot_status_tuples);

	return slot_status_array;
}

static gboolean r_on_handle_get_slot_status(RInstaller *interface,
		GDBusMethodInvocation  *invocation)
{
	gboolean res;

	res = !r_context_get_busy();

	if (res) {
		r_installer_complete_get_slot_status(interface, invocation, create_slotstatus_array());
	} else {
		g_dbus_method_invocation_return_error(invocation,
				G_IO_ERROR,
				G_IO_ERROR_FAILED_HANDLED,
				"already processing a different method");
	}

	return TRUE;
}

static gboolean r_on_handle_get_primary(RInstaller *interface,
		GDBusMethodInvocation  *invocation)
{
	GError *ierror = NULL;
	RaucSlot *primary = NULL;

	if (r_context_get_busy()) {
		g_dbus_method_invocation_return_error(invocation,
				G_IO_ERROR,
				G_IO_ERROR_FAILED_HANDLED,
				"already processing a different method");
		return TRUE;
	}

	primary = r_boot_get_primary(&ierror);
	if (!primary) {
		g_dbus_method_invocation_return_error(invocation,
				G_IO_ERROR,
				G_IO_ERROR_FAILED_HANDLED,
				"Failed getting primary slot: %s\n", ierror->message);
		g_printerr("Failed getting primary slot: %s\n", ierror->message);
		g_clear_error(&ierror);
		return TRUE;
	}

	r_installer_complete_get_primary(interface, invocation, primary->name);

	return TRUE;
}

static gboolean auto_install(const gchar *source)
{
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

void set_last_error(gchar *message)
{
	if (r_installer)
		r_installer_set_last_error(r_installer, message);
}

static void send_progress_callback(gint percentage,
		const gchar *message,
		gint nesting_depth)
{

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
		gpointer user_data)
{
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

	g_signal_connect(r_installer, "handle-get-slot-status",
			G_CALLBACK(r_on_handle_get_slot_status),
			NULL);

	g_signal_connect(r_installer, "handle-get-primary",
			G_CALLBACK(r_on_handle_get_primary),
			NULL);

	r_context_register_progress_callback(send_progress_callback);

	// Set initial Operation status to "idle"
	r_installer_set_operation(r_installer, "idle");

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(r_installer),
			connection,
			"/",
			&ierror)) {
		g_error("Failed to export interface: %s", ierror->message);
		g_error_free(ierror);
	}

	r_installer_set_compatible(r_installer, r_context()->config->system_compatible);
	r_installer_set_variant(r_installer, r_context()->config->system_variant);
	r_installer_set_boot_slot(r_installer, r_context()->bootslot);

	return;
}

static void r_on_name_acquired(GDBusConnection *connection,
		const gchar     *name,
		gpointer user_data)
{
	g_debug("name '%s' acquired", name);

	if (r_context()->config->autoinstall_path)
		auto_install(r_context()->config->autoinstall_path);

	return;
}

static void r_on_name_lost(GDBusConnection *connection,
		const gchar     *name,
		gpointer user_data)
{
	gboolean *service_return = (gboolean*)user_data;

	if (connection == NULL) {
		g_printerr("Connection to the bus can't be made for %s\n", name);
	} else {
		g_printerr("Failed to obtain name %s\n", name);
	}

	/* Abort service with exit code */
	*service_return = FALSE;

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

gboolean r_service_run(void)
{
	gboolean service_return = TRUE;
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
			&service_return, NULL);

	g_main_loop_run(service_loop);

	if (r_bus_name_id)
		g_bus_unown_name(r_bus_name_id);

	g_main_loop_unref(service_loop);
	service_loop = NULL;

	return service_return;
}
