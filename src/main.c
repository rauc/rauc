#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#if ENABLE_JSON
#include <json-glib/json-glib.h>
#include <json-glib/json-gobject.h>
#endif

#include <config.h>
#include <bootchooser.h>
#include <bundle.h>
#include <config_file.h>
#include <context.h>
#include <install.h>
#include <service.h>
#include "rauc-installer-generated.h"
#include "utils.h"

GMainLoop *r_loop = NULL;
int r_exit_status = 0;

gboolean install_ignore_compatible = FALSE;
gboolean info_noverify = FALSE;
gchar *output_format = NULL;

static gboolean install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_message("installing %s: %s", args->name, msg);
	}
	r_exit_status = args->status_result;
	g_mutex_unlock(&args->status_mutex);

	return G_SOURCE_REMOVE;
}

static gboolean install_cleanup(gpointer data)
{
	g_main_loop_quit(r_loop);

	return G_SOURCE_REMOVE;
}

static void on_installer_changed(GDBusProxy *proxy, GVariant *changed,
				 const gchar* const *invalidated,
				 gpointer data) {
	RaucInstallArgs *args = data;
	gchar *msg;
	gint32 percentage, depth;
	const gchar *message = NULL;

	if (invalidated && invalidated[0]) {
		g_warning("rauc service disappeared\n");
		g_mutex_lock(&args->status_mutex);
		args->status_result = 2;
		g_mutex_unlock(&args->status_mutex);
		args->cleanup(args);
		return;
	}

	g_mutex_lock(&args->status_mutex);
	if (g_variant_lookup(changed, "Operation", "s", &msg)) {
		g_queue_push_tail(&args->status_messages, g_strdup(msg));
	} else if (g_variant_lookup(changed, "Progress", "(isi)", &percentage, &message, &depth)) {
		g_queue_push_tail(&args->status_messages, g_strdup_printf("%3"G_GINT32_FORMAT"%% %s", percentage, message));
	} else if (g_variant_lookup(changed, "LastError", "s", &message) && message[0] != '\0') {
		g_queue_push_tail(&args->status_messages, g_strdup_printf("LastError: %s", message));
	}
	g_mutex_unlock(&args->status_mutex);

	if (!g_queue_is_empty(&args->status_messages)) {
		args->notify(args);
	}
}

static void on_installer_completed(GDBusProxy *proxy, gint result,
				   gpointer data) {
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	args->status_result = result;
	g_mutex_unlock(&args->status_mutex);

	if (result >= 0) {
		args->cleanup(args);
	}
}

static gboolean install_start(int argc, char **argv)
{
	RInstaller *installer = NULL;
	RaucInstallArgs *args = NULL;
	GError *error = NULL;
	gchar *bundlelocation = NULL, *bundlescheme = NULL;

	g_debug("install started");

	r_exit_status = 1;

	if (argc < 3) {
		g_printerr("a bundle filename name must be provided\n");
		goto out;
	}

	bundlescheme = g_uri_parse_scheme(argv[2]);
	if (bundlescheme == NULL && !g_path_is_absolute(argv[2])) {
		bundlelocation = g_build_filename(g_get_current_dir(), argv[2], NULL);
	} else {
		bundlelocation = g_strdup(argv[2]);
	}

	/* If the URI parser returns NULL, assume bundle install with local path */
	if (bundlescheme == NULL) {
		/* A valid local bundle path name must end with `.raucb` */
		if (!g_str_has_suffix(bundlelocation, ".raucb")) {
			g_printerr("Bundle must have a .raucb extension: %s\n", bundlelocation);
			g_clear_pointer(&bundlelocation, g_free);
			goto out;
		}

		if (!g_file_test (bundlelocation, G_FILE_TEST_EXISTS)) {
			g_printerr("No such file: %s\n", bundlelocation);
			g_clear_pointer(&bundlelocation, g_free);
			goto out;
		}
	}

	g_debug("input bundle: %s", bundlelocation);

	args = install_args_new();
	args->name = bundlelocation;
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	args->status_result = 2;

	r_context_conf()->ignore_compatible = install_ignore_compatible;

	r_loop = g_main_loop_new(NULL, FALSE);
	if (ENABLE_SERVICE) {
		installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
			"de.pengutronix.rauc", "/", NULL, &error);
		if (installer == NULL) {
			g_printerr("Error creating proxy: %s\n", error->message);
			g_error_free (error);
			goto out_loop;
		}
		if (g_signal_connect(installer, "g-properties-changed",
				     G_CALLBACK(on_installer_changed), args) <= 0) {
			g_printerr("failed to connect properties-changed signal\n");
			goto out_loop;
		}
		if (g_signal_connect(installer, "completed",
				     G_CALLBACK(on_installer_completed), args) <= 0) {
			g_printerr("failed to connect completed signal\n");
			goto out_loop;
		}
		g_print("trying to contact rauc service\n");
		if (!r_installer_call_install_sync(installer, bundlelocation, NULL,
						   &error)) {
			g_printerr("failed %s\n", error->message);
			g_error_free (error);
			goto out_loop;
		}
	} else {
		install_run(args);
	}

	g_main_loop_run(r_loop);


out_loop:
	switch (args->status_result) {
		case 0:
			g_print("installing `%s` succeeded\n", args->name);
			break;
		case 1:
			g_printerr("installing `%s` failed\n", args->name);
			break;
		case 2:
			g_printerr("D-Bus error while installing `%s`\n", args->name);
			break;
		default:
			g_printerr("installing `%s` failed with unknown exit code: %d\n", args->name, args->status_result);
			break;
	}
	r_exit_status = args->status_result;
	g_clear_pointer(&r_loop, g_main_loop_unref);

	if (installer)
		g_signal_handlers_disconnect_by_data(installer, args);
	g_clear_pointer(&installer, g_object_unref);
	install_args_free(args);

out:
	g_clear_pointer(&bundlescheme, g_free);

	return TRUE;
}

static gboolean bundle_start(int argc, char **argv)
{
	GError *ierror = NULL;
	g_debug("bundle start");

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_warning("cert and key files must be provided");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 3) {
		g_warning("an input directory name must be provided");
		r_exit_status = 1;
		goto out;
	}

	if (argc != 4) {
		g_warning("an output bundle name must be provided");
		r_exit_status = 1;
		goto out;
	}

	g_print("input directory: %s\n", argv[2]);
	g_print("output bundle: %s\n", argv[3]);

	if (!update_manifest(argv[2], FALSE, &ierror)) {
		g_warning("failed to update manifest: %s", ierror->message);
		r_exit_status = 1;
		goto out;
	}

	if (!create_bundle(argv[3], argv[2], &ierror)) {
		g_warning("failed to create bundle: %s", ierror->message);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

static gboolean checksum_start(int argc, char **argv)
{
	GError *error = NULL;
	gboolean sign = FALSE;

	g_debug("checksum start");

	if (r_context()->certpath != NULL &&
	    r_context()->keypath != NULL) {
		sign = TRUE;
	} else if (r_context()->certpath != NULL ||
	    r_context()->keypath != NULL) {
		g_warning("Either both or none of cert and key files must be provided");
		r_exit_status = 1;
		goto out;
	}

	if (argc != 3) {
		g_warning("A directory name must be provided");
		r_exit_status = 1;
		goto out;
	}

	g_message("updating checksums for: %s", argv[2]);

	if (!update_manifest(argv[2], sign, &error)) {
		g_warning("Failed to update manifest: %s", error->message);
		g_clear_error(&error);
		r_exit_status = 1;
	}

out:
	return TRUE;
}

/* Takes a shell variable and its desired argument as input and appends it to
 * the provided text with taking care of correct shell quoting */
static void formatter_shell_append(GString* text, const gchar* varname, const gchar* argument) {
	gchar* quoted = g_shell_quote (argument ?: "");
	g_string_append_printf(text, "%s=%s\n", varname, quoted);
	g_clear_pointer(&quoted, g_free);
}
/* Same as above, expect that it has a cnt argument to add per-slot-number
 * strings */
static void formatter_shell_append_n(GString* text, const gchar* varname, gint cnt, const gchar* argument) {
	gchar* quoted = g_shell_quote (argument ?: "");
	g_string_append_printf(text, "%s_%d=%s\n", varname, cnt, quoted);
	g_clear_pointer(&quoted, g_free);
}

static gchar *info_formatter_shell(RaucManifest *manifest)
{
	GString *text = g_string_new(NULL);
	GPtrArray *hooks = NULL;
	gchar *hookstring = NULL;
	gint cnt;

	formatter_shell_append(text, "RAUC_MF_COMPATIBLE", manifest->update_compatible);
	formatter_shell_append(text, "RAUC_MF_VERSION", manifest->update_version);
	formatter_shell_append(text, "RAUC_MF_DESCRIPTION", manifest->update_description);
	formatter_shell_append(text, "RAUC_MF_BUILD", manifest->update_build);
	g_string_append_printf(text, "RAUC_MF_IMAGES=%d\n", g_list_length(manifest->images));
	g_string_append_printf(text, "RAUC_MF_FILES=%d\n", g_list_length(manifest->files));

	hooks = g_ptr_array_new();
	if (manifest->hooks.install_check == TRUE) {
		g_ptr_array_add(hooks, g_strdup("install-check"));
	}
	g_ptr_array_add(hooks, NULL);

	hookstring = g_strjoinv(" ", (gchar**) hooks->pdata);
	formatter_shell_append(text, "RAUC_MF_HOOKS", hookstring);
	g_free(hookstring);

	g_ptr_array_unref(hooks);

	cnt = 0;
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		formatter_shell_append_n(text, "RAUC_IMAGE_NAME", cnt, img->filename);
		formatter_shell_append_n(text, "RAUC_IMAGE_CLASS", cnt, img->slotclass);
		formatter_shell_append_n(text, "RAUC_IMAGE_DIGEST", cnt, img->checksum.digest);
		g_string_append_printf(text, "RAUC_IMAGE_SIZE_%d=%"G_GSIZE_FORMAT"\n", cnt, img->checksum.size);

		hooks = g_ptr_array_new();
		if (img->hooks.pre_install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("pre-install"));
		}
		if (img->hooks.install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("install"));
		}
		if (img->hooks.post_install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("post-install"));
		}
		g_ptr_array_add(hooks, NULL);

		hookstring = g_strjoinv(" ", (gchar**) hooks->pdata);
		formatter_shell_append_n(text, "RAUC_IMAGE_HOOKS", cnt, hookstring);
		g_free(hookstring);

		g_ptr_array_unref(hooks);
		cnt++;
	}

	cnt = 0;
	for (GList *l = manifest->files; l != NULL; l = l->next) {
		RaucFile *file = l->data;
		g_string_append_printf(text, "RAUC_FILE_NAME_%d=%s\n", cnt, file->filename);
		g_string_append_printf(text, "RAUC_FILE_CLASS_%d=%s\n", cnt, file->slotclass);
		g_string_append_printf(text, "RAUC_FILE_DEST_%d=%s\n", cnt, file->destname);
		g_string_append_printf(text, "RAUC_FILE_DIGEST_%d=%s\n", cnt, file->checksum.digest);
		g_string_append_printf(text, "RAUC_FILE_SIZE_%d=%"G_GSIZE_FORMAT"\n", cnt, file->checksum.size);
		cnt++;
	}

	return g_string_free(text, FALSE);
}

static gchar *info_formatter_readable(RaucManifest *manifest)
{
	GString *text = g_string_new(NULL);
	GPtrArray *hooks = NULL;
	gchar *hookstring = NULL;
	gint cnt;

	g_string_append_printf(text, "Compatible: \t'%s'\n", manifest->update_compatible);
	g_string_append_printf(text, "Version:    \t'%s'\n", manifest->update_version);
	g_string_append_printf(text, "Description:\t'%s'\n", manifest->update_description);
	g_string_append_printf(text, "Build:      \t'%s'\n", manifest->update_build);

	hooks = g_ptr_array_new();
	if (manifest->hooks.install_check == TRUE) {
		g_ptr_array_add(hooks, g_strdup("install-check"));
	}
	g_ptr_array_add(hooks, NULL);

	hookstring = g_strjoinv(" ", (gchar**) hooks->pdata);
	g_string_append_printf(text, "Hooks:      \t'%s'\n", hookstring);
	g_free(hookstring);

	g_ptr_array_unref(hooks);

	cnt = g_list_length(manifest->images);
	g_string_append_printf(text, "%d Image%s%s\n", cnt, cnt == 1 ? "" : "s", cnt > 0 ? ":" : "");
	cnt = 1;
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		g_string_append_printf(text, "(%d)\t%s\n", cnt, img->filename);
		g_string_append_printf(text, "\tSlotclass: %s\n", img->slotclass);
		g_string_append_printf(text, "\tChecksum:  %s\n", img->checksum.digest);
		g_string_append_printf(text, "\tSize:      %"G_GSIZE_FORMAT"\n", img->checksum.size);

		hooks = g_ptr_array_new();
		if (img->hooks.pre_install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("pre-install"));
		}
		if (img->hooks.install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("install"));
		}
		if (img->hooks.post_install == TRUE) {
			g_ptr_array_add(hooks, g_strdup("post-install"));
		}
		g_ptr_array_add(hooks, NULL);

		hookstring = g_strjoinv(" ", (gchar**) hooks->pdata);
		g_string_append_printf(text, "\tHooks:     %s\n", hookstring);
		g_free(hookstring);

		g_ptr_array_unref(hooks);

		cnt++;
	}

	cnt = g_list_length(manifest->files);
	g_string_append_printf(text, "%d File%s%s\n", cnt, cnt == 1 ? "" : "s", cnt > 0 ? ":" : "");
	cnt = 1;
	for (GList *l = manifest->files; l != NULL; l = l->next) {
		RaucFile *file = l->data;
		g_string_append_printf(text, "(%d)\t%s\n", cnt, file->filename);
		g_string_append_printf(text, "\tSlotclass: %s\n", file->slotclass);
		g_string_append_printf(text, "\tDest:      %s\n", file->destname);
		g_string_append_printf(text, "\tChecksum:  %s\n", file->checksum.digest);
		g_string_append_printf(text, "\tSize:      %"G_GSIZE_FORMAT"\n", file->checksum.size);
		cnt++;
	}

	return g_string_free(text, FALSE);
}


static gchar* info_formatter_json_base(RaucManifest *manifest, gboolean pretty)
{
#if ENABLE_JSON
	JsonGenerator *gen;
	JsonNode * root;
	gchar *str;
	JsonBuilder *builder = json_builder_new ();

	json_builder_begin_object (builder);

	json_builder_set_member_name (builder, "compatible");
	json_builder_add_string_value (builder, manifest->update_compatible);

	json_builder_set_member_name (builder, "version");
	json_builder_add_string_value (builder, manifest->update_version);

	json_builder_set_member_name (builder, "description");
	json_builder_add_string_value (builder, manifest->update_description);

	json_builder_set_member_name (builder, "build");
	json_builder_add_string_value (builder, manifest->update_build);

	json_builder_set_member_name (builder, "hooks");
	json_builder_begin_array (builder);
	if (manifest->hooks.install_check == TRUE) {
		json_builder_add_string_value (builder, "install-check");
	}
	json_builder_end_array (builder);

	json_builder_set_member_name (builder, "images");
	json_builder_begin_array (builder);

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;

		json_builder_begin_object (builder);
		json_builder_set_member_name (builder, img->slotclass);
		json_builder_begin_object (builder);
		json_builder_set_member_name (builder, "filename");
		json_builder_add_string_value (builder, img->filename);
		json_builder_set_member_name (builder, "checksum");
		json_builder_add_string_value (builder, img->checksum.digest);
		json_builder_set_member_name (builder, "size");
		json_builder_add_int_value (builder, img->checksum.size);
		json_builder_set_member_name (builder, "hooks");
		json_builder_begin_array (builder);
		if (img->hooks.pre_install == TRUE) {
			json_builder_add_string_value (builder, "pre-install");
		}
		if (img->hooks.install == TRUE) {
			json_builder_add_string_value (builder, "install");
		}
		if (img->hooks.post_install == TRUE) {
			json_builder_add_string_value (builder, "post-install");
		}
		json_builder_end_array (builder);
		json_builder_end_object (builder);
		json_builder_end_object (builder);

	}

	json_builder_end_array (builder);

	json_builder_end_object (builder);

	gen = json_generator_new ();
	root = json_builder_get_root (builder);
	json_generator_set_root (gen, root);
	json_generator_set_pretty (gen, pretty);
	str = json_generator_to_data (gen, NULL);

	json_node_free (root);
	g_object_unref (gen);
	g_object_unref (builder);

	return str;
#else
	g_error("json support is disabled");
	return NULL;
#endif
}

static gchar* info_formatter_json(RaucManifest *manifest)
{
	return info_formatter_json_base(manifest, FALSE);
}

static gchar* info_formatter_json_pretty(RaucManifest *manifest)
{
	return info_formatter_json_base(manifest, TRUE);
}

static gboolean info_start(int argc, char **argv)
{
	gchar* tmpdir = NULL;
	gchar* bundledir = NULL;
	gchar* manifestpath = NULL;
	RaucManifest *manifest = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	gchar* (*formatter)(RaucManifest *manifest) = NULL;

	if (argc != 3) {
		g_warning("a file name must be provided");
		r_exit_status = 1;
		return FALSE;
	}

	if (!output_format || g_strcmp0(output_format, "readable") == 0) {
		formatter = info_formatter_readable;
	} else if (g_strcmp0(output_format, "shell") == 0) {
		formatter = info_formatter_shell;
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json") == 0) {
		formatter = info_formatter_json;
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json-pretty") == 0) {
		formatter = info_formatter_json_pretty;
	} else {
		g_printerr("Unknown output format: '%s'\n", output_format);
		goto out;
	}

	tmpdir = g_dir_make_tmp("bundle-XXXXXX", &error);
	if (!tmpdir) {
		g_warning("%s", error->message);
		g_clear_error(&error);
		goto out;
	}

	bundledir = g_build_filename(tmpdir, "bundle-content", NULL);
	manifestpath = g_build_filename(bundledir, "manifest.raucm", NULL);

	res = extract_file_from_bundle(argv[2], bundledir, "manifest.raucm", !info_noverify, &error);
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

	g_print("%s\n", formatter(manifest));

out:
	r_exit_status = res ? 0 : 1;
	if (tmpdir)
		rm_tree(tmpdir, NULL);

	g_clear_pointer(&tmpdir, g_free);
	g_clear_pointer(&bundledir, g_free);
	g_clear_pointer(&manifestpath, g_free);
	return TRUE;
}

/* returns string representation of slot state */
static gchar* slotstate_to_str(SlotState slotstate)
{
	gchar *state = NULL;

	switch (slotstate) {
	case ST_ACTIVE:
		state = g_strdup("active");
		break;
	case ST_INACTIVE:
		state = g_strdup("inactive");
		break;
	case ST_BOOTED:
		state = g_strdup("booted");
		break;
	case ST_UNKNOWN:
	default:
		g_error("invalid slot status %d", slotstate);
		break;
	}

	return state;
}


static gchar* r_status_formatter_readable(void)
{
	GHashTableIter iter;
	gpointer key, value;
	gint slotcnt = 0;
	GString *text = g_string_new(NULL);

	g_string_append_printf(text, "Compatible:  %s\n", r_context()->config->system_compatible);
	g_string_append_printf(text, "booted from: %s\n", r_context()->bootslot);

	g_string_append(text, "slot states:\n");
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		gchar *name = key;
		RaucSlot *slot = value;

		slotcnt++;


		g_string_append_printf(text, "  %s: class=%s, device=%s, type=%s, bootname=%s\n",
				name, slot->sclass, slot->device, slot->type, slot->bootname);
		g_string_append_printf(text, "      state=%s, description=%s", slotstate_to_str(slot->state), slot->description);
		if (slot->parent)
			g_string_append_printf(text, ", parent=%s", slot->parent->name);
		else
			g_string_append(text, ", parent=(none)");
		if (slot->mount_point)
			g_string_append_printf(text, ", mountpoint=%s", slot->mount_point);
		else
			g_string_append(text, ", mountpoint=(none)");
		g_string_append_c(text, '\n');

	}

	return g_string_free(text, FALSE);
}

static gchar* r_status_formatter_shell(void)
{
	GHashTableIter iter;
	gpointer key, value;
	gint slotcnt = 0;
	GString *text = g_string_new(NULL);
	GPtrArray *slotnames, *slotnumbers = NULL;
	gchar* slotstring = NULL;

	formatter_shell_append(text, "RAUC_SYSTEM_COMPATIBLE", r_context()->config->system_compatible);
	formatter_shell_append(text, "RAUC_SYSTEM_BOOTED_BOOTNAME", r_context()->bootslot);

	slotnames = g_ptr_array_new();
	slotnumbers = g_ptr_array_new();
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		g_ptr_array_add(slotnames, (gchar*) key);
		g_ptr_array_add(slotnumbers, g_strdup_printf("%i", ++slotcnt));
	}
	g_ptr_array_add(slotnames, NULL);
	g_ptr_array_add(slotnumbers, NULL);

	slotstring = g_strjoinv(" ", (gchar**) slotnames->pdata);
	formatter_shell_append(text, "RAUC_SYSTEM_SLOTS", slotstring);
	g_free(slotstring);
	slotstring = g_strjoinv(" ", (gchar**) slotnumbers->pdata);
	formatter_shell_append(text, "RAUC_SLOTS", slotstring);
	g_free(slotstring);

	g_ptr_array_unref(slotnumbers);
	g_ptr_array_unref(slotnames);

	slotcnt = 0;
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		RaucSlot *slot = value;

		slotcnt++;


		formatter_shell_append_n(text, "RAUC_SLOT_STATE", slotcnt, slotstate_to_str(slot->state));
		formatter_shell_append_n(text, "RAUC_SLOT_CLASS", slotcnt, slot->sclass);
		formatter_shell_append_n(text, "RAUC_SLOT_DEVICE", slotcnt, slot->device);
		formatter_shell_append_n(text, "RAUC_SLOT_TYPE", slotcnt, slot->type);
		formatter_shell_append_n(text, "RAUC_SLOT_BOOTNAME", slotcnt, slot->bootname);
		formatter_shell_append_n(text, "RAUC_SLOT_PARENT", slotcnt, slot->parent ? slot->parent->name : NULL);
		formatter_shell_append_n(text, "RAUC_SLOT_MOUNTPOINT", slotcnt, slot->mount_point);
	}

	return g_string_free(text, FALSE);
}

static gchar* r_status_formatter_json(gboolean pretty)
{
#if ENABLE_JSON
	JsonGenerator *gen;
	JsonNode * root;
	GHashTableIter iter;
	gpointer key, value;
	gchar *str;
	JsonBuilder *builder = json_builder_new ();

	json_builder_begin_object (builder);

	json_builder_set_member_name (builder, "compatible");
	json_builder_add_string_value (builder, r_context()->config->system_compatible);

	json_builder_set_member_name (builder, "booted");
	json_builder_add_string_value (builder, r_context()->bootslot);

	json_builder_set_member_name (builder, "slots");
	json_builder_begin_array (builder);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		RaucSlot *slot = value;

		json_builder_begin_object (builder);
		json_builder_set_member_name (builder, slot->name);
		json_builder_begin_object (builder);
		json_builder_set_member_name (builder, "class");
		json_builder_add_string_value (builder, slot->sclass);
		json_builder_set_member_name (builder, "device");
		json_builder_add_string_value (builder, slot->device);
		json_builder_set_member_name (builder, "type");
		json_builder_add_string_value (builder, slot->type);
		json_builder_set_member_name (builder, "bootname");
		json_builder_add_string_value (builder, slot->bootname);
		json_builder_set_member_name (builder, "state");
		json_builder_add_string_value (builder, slotstate_to_str(slot->state));
		json_builder_set_member_name (builder, "parent");
		json_builder_add_string_value (builder, slot->parent ? slot->parent->name : NULL);
		json_builder_set_member_name (builder, "mountpoint");
		json_builder_add_string_value (builder, slot->mount_point);
		json_builder_end_object (builder);
		json_builder_end_object (builder);

	}

	json_builder_end_array (builder);

	json_builder_end_object (builder);

	gen = json_generator_new ();
	root = json_builder_get_root (builder);
	json_generator_set_root (gen, root);
	json_generator_set_pretty (gen, pretty);
	str = json_generator_to_data (gen, NULL);

	json_node_free (root);
	g_object_unref (gen);
	g_object_unref (builder);

	return str;
#else
	g_error("json support is disabled");
	return NULL;
#endif
}

static gboolean status_start(int argc, char **argv)
{
	GHashTableIter iter;
	RaucSlot *slot, *booted = NULL;
	gchar *text = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_debug("status start");

	res = determine_slot_states(&ierror);
	if (!res) {
		g_printerr("Failed to determine slot states: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!output_format || g_strcmp0(output_format, "readable") == 0) {
		text = r_status_formatter_readable();
	} else if (g_strcmp0(output_format, "shell") == 0) {
		text = r_status_formatter_shell();
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json") == 0) {
		text = r_status_formatter_json(FALSE);
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json-pretty") == 0) {
		text = r_status_formatter_json(TRUE);
	} else {
		g_printerr("Unknown output format: '%s'\n", output_format);
		r_exit_status = 1;
		goto out;
	}

	g_print("%s\n", text);

	if (argc < 3) {
		r_exit_status = 0;
		goto out;
	}

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		if (slot->state == ST_BOOTED) {
			booted = slot;
		}
	}

	if (!booted) {
		g_warning("Failed to determine booted slot");
		r_exit_status = 1;
		goto out;
	}

	if (g_strcmp0(argv[2], "mark-good") == 0) {
		g_print("marking slot %s as good\n", booted->name);
		r_exit_status = r_boot_set_state(booted, TRUE) ? 0 : 1;
	} else if (g_strcmp0(argv[2], "mark-bad") == 0) {
		g_print("marking slot %s as bad\n", booted->name);
		r_exit_status = r_boot_set_state(booted, FALSE) ? 0 : 1;
	} else {
		g_message("unknown subcommand %s", argv[2]);
		r_exit_status = 1;
	}

out:
	return TRUE;
}

#if ENABLE_SERVICE == 1
static gboolean service_start(int argc, char **argv)
{
	g_debug("service start");

	return r_service_run();
}
#endif

static gboolean unknown_start(int argc, char **argv)
{
	g_debug("unknown start");

	return TRUE;
}

typedef enum  {
	UNKNOWN = 0,
	INSTALL,
	BUNDLE,
	CHECKSUM,
	STATUS,
	INFO,
	SERVICE,
} RaucCommandType;

typedef struct {
	const RaucCommandType type;
	const gchar* name;
	const gchar* usage;
	gboolean (*cmd_handler) (int argc, char **argv);
	GOptionGroup* options;
	gboolean while_busy;
} RaucCommand;

GOptionEntry entries_install[] = {
	{"ignore-compatible", '\0', 0, G_OPTION_ARG_NONE, &install_ignore_compatible, "disable compatible check", NULL},
	{0}
};

GOptionEntry entries_info[] = {
	{"no-verify", '\0', 0, G_OPTION_ARG_NONE, &info_noverify, "disable bundle verification", NULL},
	{"output-format", '\0', 0, G_OPTION_ARG_STRING, &output_format, "output format", "FORMAT"},
	{0}
};

GOptionEntry entries_status[] = {
	{"output-format", '\0', 0, G_OPTION_ARG_STRING, &output_format, "output format", "FORMAT"},
	{0}
};

static void cmdline_handler(int argc, char **argv)
{
	gboolean help = FALSE, debug = FALSE, version = FALSE;
	gchar *confpath = NULL, *certpath = NULL, *keypath = NULL, *mount = NULL,
	      *handlerextra = NULL, *bootslot = NULL;
	char *cmdarg = NULL;
	GOptionContext *context = NULL;
	GOptionEntry entries[] = {
		{"conf", 'c', 0, G_OPTION_ARG_FILENAME, &confpath, "config file", "FILENAME"},
		{"cert", '\0', 0, G_OPTION_ARG_FILENAME, &certpath, "cert file", "PEMFILE"},
		{"key", '\0', 0, G_OPTION_ARG_FILENAME, &keypath, "key file", "PEMFILE"},
		{"mount", '\0', 0, G_OPTION_ARG_FILENAME, &mount, "mount prefix", "PATH"},
		{"override-boot-slot", '\0', 0, G_OPTION_ARG_STRING, &bootslot, "override auto-detection of booted slot", "SLOTNAME"},
		{"handler-args", '\0', 0, G_OPTION_ARG_STRING, &handlerextra, "extra handler arguments", "ARGS"},
		{"debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL},
		{"version", '\0', 0, G_OPTION_ARG_NONE, &version, "display version", NULL},
		{"help", 'h', 0, G_OPTION_ARG_NONE, &help, NULL, NULL},
		{0}
	};
	GOptionGroup *install_group = g_option_group_new("install", "Install options:", "help dummy", NULL, NULL);
	GOptionGroup *info_group = g_option_group_new("info", "Info options:", "help dummy", NULL, NULL);
	GOptionGroup *status_group = g_option_group_new("status", "Status options:", "help dummy", NULL, NULL);

	GError *error = NULL;
	gchar *text;

	RaucCommand rcommands[] = {
		{UNKNOWN, "help", "<COMMAND>", unknown_start, NULL, TRUE},
		{INSTALL, "install", "install <BUNDLE>", install_start, install_group, FALSE},
		{BUNDLE, "bundle", "bundle <FILE>", bundle_start, NULL, FALSE},
		{CHECKSUM, "checksum", "checksum <DIRECTORY>", checksum_start, NULL, FALSE},
		{INFO, "info", "info <FILE>", info_start, info_group, FALSE},
		{STATUS, "status", "status", status_start, status_group, TRUE},
#if ENABLE_SERVICE == 1
		{SERVICE, "service", "service", service_start, NULL, TRUE},
#endif
		{0}
	};
	RaucCommand *rc;
	RaucCommand *rcommand = NULL;

	g_option_group_add_entries(install_group, entries_install);
	g_option_group_add_entries(info_group, entries_info);
	g_option_group_add_entries(status_group, entries_status);

	context = g_option_context_new("<COMMAND>");
	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_set_ignore_unknown_options(context, TRUE);
	g_option_context_add_main_entries(context, entries, NULL);
	g_option_context_set_description(context, 
			"List of rauc commands:\n" \
			"  bundle\tCreate a bundle\n" \
			"  checksum\tUpdate a manifest with checksums (and optionally sign it)\n" \
			"  install\tInstall a bundle\n" \
			"  info\t\tShow file information\n" \
			"  status\tShow status");

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_printerr("%s\n", error->message);
		g_error_free(error);
		r_exit_status = 1;
		goto done;
	}

	if (debug) {
		const gchar *domains = g_getenv("G_MESSAGES_DEBUG");
		if (!domains) {
			g_assert(g_setenv("G_MESSAGES_DEBUG", G_LOG_DOMAIN, TRUE));
		} else if (!g_str_equal(domains, "all") && !g_strrstr(domains, G_LOG_DOMAIN)) {
			gchar *newdomains = g_strdup_printf("%s %s", domains, G_LOG_DOMAIN);
			g_setenv("G_MESSAGES_DEBUG", newdomains, TRUE);
			g_free(newdomains);
		}
		domains = g_getenv("G_MESSAGES_DEBUG");
		g_print("Domains: '%s'\n", domains);
	}

	/* get first parameter wihtout dashes */
	for (gint i = 1; i <= argc; i++) {
		if (argv[i] && !g_str_has_prefix (argv[i], "-")) {
			cmdarg = argv[i];
			break;
		}
	}

	if (cmdarg == NULL) {
		if (version) {
			g_print(PACKAGE_STRING"\n");
			goto done;
		}

		/* NO COMMAND given */

		if (!help) {
			r_exit_status = 1;
		}
		goto print_help;
	}



	/* try to get known command */
	rc = rcommands;
	while (rc->name) {
		if (g_strcmp0(rc->name, cmdarg) == 0) {
			rcommand = rc;
			break;
		}
		rc++;
	}

	if (rcommand == NULL) {
		/* INVALID COMMAND given */
		g_message("Invalid command '%s' given", cmdarg);
		r_exit_status = 1;
		goto print_help;
	}

	/* re-setup option context for showing command-specific help */
	g_clear_pointer(&context, g_option_context_free);
	context = g_option_context_new(rcommand->usage);
	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_add_main_entries(context, entries, NULL);
	if (rcommand->options)
		g_option_context_add_group(context, rcommand->options);

	/* parse command-specific options */
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_printerr("%s\n", error->message);
		g_error_free(error);
		r_exit_status = 1;
		goto print_help;
	}

	if (help) {
		goto print_help;
	}

	/* configuration updates are handled here */
	if (!r_context_get_busy()) {
		r_context_conf();
		if (confpath)
			r_context_conf()->configpath = confpath;
		if (certpath)
			r_context_conf()->certpath = certpath;
		if (keypath)
			r_context_conf()->keypath = keypath;
		if (mount)
			r_context_conf()->mountprefix = mount;
		if (bootslot)
			r_context_conf()->bootslot = bootslot;
		if (handlerextra)
			r_context_conf()->handlerextra = handlerextra;
	} else {
		if (confpath != NULL ||
		    certpath != NULL ||
		    keypath != NULL) {
			g_error("rauc busy, cannot reconfigure");
			r_exit_status = 1;
			goto done;
		}
	}

	if (r_context_get_busy() && !rcommand->while_busy) {
		g_error("rauc busy: cannot run %s", rcommand->name);
		r_exit_status = 1;
		goto done;
	}

	/* real commands are handled here */
	if (rcommand->cmd_handler) {
		rcommand->cmd_handler(argc, argv);
	}
	goto done;

print_help:
	text = g_option_context_get_help(context, FALSE, NULL);
	g_print("%s", text);
	g_free(text);

done:
	g_clear_pointer(&context, g_option_context_free);;
}

int main(int argc, char **argv) {
	/* disable remote VFS */
	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	cmdline_handler(argc, argv);

	return r_exit_status;
}
