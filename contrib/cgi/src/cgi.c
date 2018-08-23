#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <rauc-installer-generated.h>

/*
 * Bundle/status file locations
 * It is assumed that these files do not survive a reboot.
 */
const gchar *BUNDLE_TARGET_LOCATION = "/tmp/bundle.raucb";
const gchar *STATUS_FILE_LOCATION = "/tmp/rauc-status.json";

/*
 * HTTP request headers that should be saved during PUT and are then available
 * in status method, lowercase, NULL-terminated
 */
const gchar *HTTP_HEADERS[] = {"upload_client_id", NULL};


#define CGI_ERROR cgi_error_quark()

static GQuark cgi_error_quark(void)
{
	return g_quark_from_static_string("cgi_error_quark");
}

typedef enum {
	CGI_ERROR_FAILED,
	CGI_ERROR_METHOD_NOT_ALLOWED,
	CGI_ERROR_LENGTH_REQUIRED,
	CGI_ERROR_BAD_REQUEST,
	CGI_ERROR_SERVICE_UNAVAILABLE,
} CGIError;

/*
 * Print HTTP headers and two new lines to start HTTP body.
 */
static void print_headers(const gchar* status, const gchar* content_type)
{
	g_print("Status: %s\n", status);
	g_print("Content-type: %s\n", content_type);
	g_print("\n");
}

/*
 * Retrieve LastError property via rauc D-Bus service.
 */
static gchar* get_last_error(RInstaller *installer, GError **error)
{
	gchar* last_error = r_installer_dup_last_error(installer);
	if (!last_error)
		g_set_error(error, CGI_ERROR, CGI_ERROR_FAILED, "D-Bus error");

	return last_error;
}

/*
 * Retrieve Operation property via rauc D-Bus service.
 */
static gchar* get_operation(RInstaller *installer, GError **error)
{
	gchar* operation = r_installer_dup_operation(installer);
	if (!operation)
		g_set_error(error, CGI_ERROR, CGI_ERROR_FAILED, "D-Bus error");

	return operation;
}

/*
 * Retrieve ProgressUpdated property via rauc D-Bus service.
 */
static gboolean get_progress_updated(RInstaller *installer, gint *percentage, gchar **description, GError **error)
{
	gboolean res = FALSE;
	GVariant* progress_updated;
	GVariant* g_percentage;
	GVariant* g_description;

	g_return_val_if_fail(percentage != NULL, FALSE);
	g_return_val_if_fail(description == NULL || *description == NULL, FALSE);

	*percentage = -1;

	progress_updated = r_installer_get_progress(installer);
	if (!progress_updated) {
		g_set_error(error, CGI_ERROR, CGI_ERROR_FAILED, "D-Bus error");
		goto out;
	}

	g_percentage = g_variant_get_child_value(progress_updated, 0);
	*percentage = g_variant_get_int32(g_percentage);

	g_description = g_variant_get_child_value(progress_updated, 1);
	*description = g_strdup(g_variant_get_string(g_description, NULL));

	res = TRUE;

	g_variant_unref(g_percentage);
	g_variant_unref(g_description);

out:
	return res;
}

/*
 * Last installation was successfull if LastError D-Bus property is an empty
 * string.
 */
static gboolean get_last_installation_success(RInstaller *installer, gboolean *last_install_success, GError **error)
{
	gboolean res = FALSE;
	gchar* last_error = NULL;

	g_return_val_if_fail(last_install_success != NULL, FALSE);

	last_error = r_installer_dup_last_error(installer);
	if (!last_error) {
		g_set_error(error, CGI_ERROR, CGI_ERROR_FAILED, "D-Bus error");
		goto out;
	}

	*last_install_success = g_strcmp0("", last_error) == 0;
	res = TRUE;

out:
	g_free(last_error);

	return res;
}

/*
 * Retrieve property string from status/lock file by name.
 */
static gchar* get_str_from_status_or_empty(const gchar* name, GError **error)
{
	JsonParser *parser = json_parser_new();
	JsonReader *reader = NULL;
	gchar *value = NULL;
	GError *ierror = NULL;

	if (!json_parser_load_from_file(parser, STATUS_FILE_LOCATION, &ierror)) {
		/* the file might not exist at this point, ignore that */
		if (!g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_propagate_prefixed_error(error, ierror, "Could not load status file: ");
			goto out;
		}

		/* no previous status available, return empty */
		value = g_strdup("");
		goto out;
	}

	reader = json_reader_new(json_parser_get_root(parser));

	json_reader_read_member(reader, name);
	value = g_strdup(json_reader_get_string_value(reader));
	json_reader_end_member(reader);

	g_object_unref(reader);
	g_object_unref(parser);

out:
	return value;
}

/*
 * Retrieve property int from status/lock file by name.
 */
static gint get_int_from_status_or_negative(const gchar* name, GError **error)
{
	JsonParser *parser = json_parser_new();
	JsonReader *reader = NULL;
	gint value = -1;
	GError *ierror = NULL;

	if (!json_parser_load_from_file(parser, STATUS_FILE_LOCATION, &ierror)) {
		/* the file might not exist at this point, ignore it */
		if (!g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			g_propagate_prefixed_error(error, ierror, "Could not load status file: ");
		goto out;
	}

	reader = json_reader_new(json_parser_get_root(parser));

	json_reader_read_member(reader, name);
	value = json_reader_get_int_value(reader);
	json_reader_end_member(reader);

	g_object_unref(reader);
	g_object_unref(parser);

out:
	return value;
}

/*
 * The device will reboot shortly after the install process succeeded.
 * This function determines if all requirements are met and the postinstall
 * hook will fire soon.
 */
static gboolean get_will_reboot(RInstaller *installer, gboolean *will_reboot, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	gboolean last_install_success = FALSE;
	gchar* install_message = NULL;
	gint install_percentage = -1;

	g_return_val_if_fail(will_reboot != NULL, FALSE);

	if (!get_last_installation_success(installer, &last_install_success, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (!get_progress_updated(installer, &install_percentage, &install_message, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	*will_reboot = last_install_success && install_percentage == 100 && g_file_test(STATUS_FILE_LOCATION, G_FILE_TEST_EXISTS);
	res = TRUE;

out:
	g_free(install_message);

	return res;
}

/* remove stale status and bundle files */
static void try_cleanup_status_on_install_failure(RInstaller *installer)
{
	gboolean last_install_success = FALSE;
	gchar* install_message = NULL;
	gint install_percentage = -1;

	if (!get_last_installation_success(installer, &last_install_success, NULL))
		goto out;

	if (!get_progress_updated(installer, &install_percentage, &install_message, NULL))
		goto out;

	/* Previous install failure is identified by "LastError" D-Bus property (also
	 * set if no previous install happened), 100% install percentage of D-Bus
	 * "Pogress" property and an existing status file (means the previous
	 * installation was started via CGI).
	 */
	if (!last_install_success && install_percentage == 100 && g_file_test(STATUS_FILE_LOCATION, G_FILE_TEST_EXISTS)) {
		g_remove(STATUS_FILE_LOCATION);
		g_remove(BUNDLE_TARGET_LOCATION);
	}

out:
	g_free(install_message);
}

/*
 * Write upload status information that is not available via D-Bus to status
 * file.
 */
static gboolean write_upload_status(gint upload_progress, GError **error)
{
	gboolean res = FALSE;
	JsonBuilder *builder = json_builder_new();
	JsonGenerator *gen = NULL;
	JsonNode *root = NULL;
	const gchar **header_ptr;
	GError *ierror = NULL;

	json_builder_begin_object(builder);

	/*
	 * progression of the running upload operation in percent, any upload
	 * not necessarily triggered by the client requesting the status value
	 * from 0 to 100, -1 if no upload in progress
	 */
	json_builder_set_member_name(builder, "upload_progress");
	json_builder_add_int_value(builder, upload_progress);

	/*
	 * value of a custom HTTP header that may be provided by the client
	 * performing the upload used to identify who is currently uploading a
	 * firmware
	 */
	header_ptr = &HTTP_HEADERS[0];
	while (*header_ptr) {
		gchar *header_name_upper = g_ascii_strup(*header_ptr, -1);
		gchar *full_header_name = g_strdup_printf("HTTP_%s", header_name_upper);
		gchar *header_value = g_strdup(g_getenv(full_header_name));
		if (!header_value)
			/* no header value found, use empty string */
			header_value = g_strdup("");

		json_builder_set_member_name(builder, *header_ptr);
		json_builder_add_string_value(builder, header_value);
		header_ptr++;

		g_free(header_name_upper);
		g_free(full_header_name);
		g_free(header_value);
	}

	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);

	if (!json_generator_to_file(gen, STATUS_FILE_LOCATION, error)) {
		g_propagate_prefixed_error(error, ierror, "Unable to create status file: ");
		goto out;
	}

	res = TRUE;

out:
	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(builder);

	return res;
}

/*
 * Generate JSON containing status information and print it to stdout.
 */
static gboolean progress_status(RInstaller *installer, GError **error)
{
	gboolean res = FALSE;
	JsonBuilder *builder = json_builder_new();
	JsonGenerator *gen = NULL;
	JsonNode *root = NULL;
	gint percentage;
	gint upload_progress;
	gchar *description = NULL;
	gchar *operation = NULL;
	gchar *last_error = NULL;
	gchar *header_value = NULL;
	gchar *json_str = NULL;
	const gchar **header_ptr;
	gboolean will_reboot;
	gboolean last_installation_success;

	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	json_builder_begin_object(builder);

	/*
	 * progression of the running upload operation in percent, any upload
	 * not necessarily triggered by the client requesting the status value
	 * from 0 to 100, -1 if no upload in progress
	 */
	upload_progress = get_int_from_status_or_negative("upload_progress", &ierror);
	if (ierror) {
		g_propagate_error(error, ierror);
		goto out;
	}

	json_builder_set_member_name(builder, "upload_progress");
	json_builder_add_int_value(builder, upload_progress);

	/*
	 * value of the HTTP headers specified in HTTP_HEADERS
	 */
	header_ptr = &HTTP_HEADERS[0];
	while (*header_ptr) {
		header_value = get_str_from_status_or_empty(*header_ptr, &ierror);
		if (!header_value) {
			g_propagate_error(error, ierror);
			goto out;
		}

		json_builder_set_member_name(builder, *header_ptr);
		json_builder_add_string_value(builder, header_value);
		header_ptr++;
	}

	if (!get_progress_updated(installer, &percentage, &description, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	/* progression of the installation in percent, 0 to 100. -1 if no
	 * upload in progress
	 */
	json_builder_set_member_name(builder, "installation_progress");
	json_builder_add_int_value(builder, percentage);

	if (g_strcmp0(description, "") != 0) {
		operation = get_operation(installer, &ierror);
		if (!operation) {
			g_propagate_error(error, ierror);
			goto out;
		}
		description = g_strdup_printf("%s (%s)", operation, description);
	}

	/* what the update handler is currently doing, comes from the default
	 * handler or from the custom update handler
	 */
	json_builder_set_member_name(builder, "installation_operation");
	json_builder_add_string_value(builder, description);

	if (!get_will_reboot(installer, &will_reboot, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	json_builder_set_member_name(builder, "will_reboot");
	json_builder_add_boolean_value(builder, will_reboot);

	/* was the last installation tentative successful? (during this
	 * session, no need for it to be persistent)
	 */
	if (!get_last_installation_success(installer, &last_installation_success, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	json_builder_set_member_name(builder, "last_installation_success");
	json_builder_add_boolean_value(builder, last_installation_success);

	/* what went wrong? Empty string if no error */
	last_error = get_last_error(installer, &ierror);
	if (ierror) {
		g_propagate_error(error, ierror);
		goto out;
	}

	json_builder_set_member_name(builder, "last_installation_error");
	json_builder_add_string_value(builder, last_error);

	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	json_str = json_generator_to_data(gen, NULL);

	print_headers("200 OK", "application/json");
	g_print("%s", json_str);

	json_node_free(root);
	g_object_unref(gen);

	res = TRUE;

out:
	g_object_unref(builder);
	g_free(description);
	g_free(operation);
	g_free(last_error);
	g_free(header_value);
	g_free(json_str);

	return res;
}

/*
 * Generate JSON containing status information about slots and print it to
 * stdout.
 */
static gboolean slot_status(RInstaller *installer, GError **error)
{
	JsonBuilder *builder = json_builder_new();
	JsonGenerator *gen = NULL;
	JsonNode *root = NULL;
	GVariantIter iter_slots;
	GVariantIter iter_props;
	GVariant *slot_status_array = NULL;
	GVariant *properties = NULL;
	GVariant *value = NULL;
	gchar *key = NULL;
	gchar *slot_name = NULL;
	const gchar *property_str = NULL;
	guint32 property_u32;
	guint64 property_u64;
	gboolean res = FALSE;

	res = r_installer_call_get_slot_status_sync(installer, &slot_status_array, NULL, error);
	if (!res)
		goto out;

	json_builder_begin_object(builder);

	g_variant_iter_init(&iter_slots, slot_status_array);

	/* iterate slots */
	while ((g_variant_iter_next(&iter_slots, "(s@a{sv})", &slot_name, &properties))) {
		json_builder_set_member_name(builder, slot_name);
		json_builder_begin_object(builder);

		g_variant_iter_init(&iter_props, properties);

		/* iterate attributes */
		while ((g_variant_iter_next(&iter_props, "{sv}", &key, &value))) {
			json_builder_set_member_name(builder, key);

			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				property_str = g_variant_get_string(value, NULL);
				json_builder_add_string_value(builder, property_str);
			}
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32)) {
				property_u32 = g_variant_get_uint32(value);
				json_builder_add_int_value(builder, property_u32);
			}
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_UINT64)) {
				property_u64 = g_variant_get_uint64(value);
				json_builder_add_int_value(builder, property_u64);
			}
			/*
			 * ignore all other types as they are unknown at the
			 * time of writing
			 */
		}

		json_builder_end_object(builder);
	}

	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);

	print_headers("200 OK", "application/json");
	g_print("%s\n", json_generator_to_data(gen, NULL));

	json_node_free(root);
	g_object_unref(builder);
	g_variant_unref(value);
	g_variant_unref(properties);
	g_variant_unref(slot_status_array);

out:
	if (gen)
		g_object_unref(gen);
	g_free(slot_name);
	g_free(key);

	return res;
}

/*
 * Wrapper around fread() that writes upload progress information to status
 * file.
 */
static gint64 fread_chunked(char *ptr, size_t size, FILE *stream, GError **error)
{
	gint64 items_read = 0;
	gint64 bytes_read = 0;
	gint percentage = 0;
	gint last_percentage = -1;

	while (bytes_read < (gint64) size) {
		items_read = fread(ptr + bytes_read, 1, 1024, stream);
		bytes_read += items_read;
		percentage = (bytes_read * 100) / size;

		/* update upload status only if percentage changed */
		if (percentage != last_percentage) {
			last_percentage = percentage;
			if (!write_upload_status(percentage, error)) {
				bytes_read = -1;
				goto out;
			}
		}
	}

out:
	return bytes_read;
}

/*
 * Reads stdin and writes to temporary bundle file.
 */
static gboolean stdin_to_file(GError **error)
{
	gint ret = FALSE;
	gint64 read_len = 0;
	gint64 bytes_read = 0;
	gchar *file_buf = NULL;
	gchar *content_length = g_strdup(g_getenv("CONTENT_LENGTH"));

	if (!content_length) {
		g_set_error_literal(error, CGI_ERROR, CGI_ERROR_LENGTH_REQUIRED, "Please provide a Content-Length header.");
		goto out;
	}

	if (g_file_test(STATUS_FILE_LOCATION, G_FILE_TEST_EXISTS)) {
		g_set_error(error, CGI_ERROR, CGI_ERROR_SERVICE_UNAVAILABLE, "Another install operation is currently running (lock file exists).");
		/* do not clean up the lock file in this case, will reboot shortly! */
		goto out;
	}

	/* upload started */
	if (!write_upload_status(0, error))
		goto out;

	read_len = g_ascii_strtoll(content_length, NULL, 10);
	if (read_len == 0) {
		g_set_error(error, CGI_ERROR, CGI_ERROR_BAD_REQUEST, "Content-Length header invalid.");
		write_upload_status(-1, NULL);
		goto error;
	}

	/* read 'read_len' bytes from stdin ... */
	file_buf = (char *) g_malloc(read_len);
	bytes_read = fread_chunked(file_buf, read_len, stdin, error);
	if (bytes_read == -1 || bytes_read != read_len) {
		if (!error && !*error)
			g_set_error(error, CGI_ERROR, CGI_ERROR_BAD_REQUEST, "Content-Length header incorrect.");
		write_upload_status(-1, NULL);
		goto error;
	}

	if (!g_file_set_contents(BUNDLE_TARGET_LOCATION, file_buf, read_len, error)) {
		write_upload_status(-1, NULL);
		goto error;
	}

	ret = TRUE;

error:
	if (*error)
		/* try to remove status/lock file */
		g_remove(STATUS_FILE_LOCATION);

out:
	g_free(file_buf);
	g_free(content_length);

	return ret;
}

/*
 * Handle CGI env variables and trigger requested operations.
 */
static gint cgi_handler(int argc, char **argv)
{
	gint ret = 1;
	RInstaller *installer;
	gchar *method = g_strdup(g_getenv("REQUEST_METHOD"));
	gchar *query_string = g_strdup(g_getenv("QUERY_STRING"));
	GError *error = NULL;

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES, "de.pengutronix.rauc", "/", NULL, &error);
	if (!installer)
		goto error;

	/*
	 * there is no way to remove stale bundle/status files directly after
	 * install failure, so just do it now
	 */
	try_cleanup_status_on_install_failure(installer);

	if (g_strcmp0("GET", method) == 0) {
		if (g_strcmp0("progress", query_string) == 0) {
			/* ?progress shows progress information */
			if (!progress_status(installer, &error))
				goto error;

		} else if (g_strcmp0("status", query_string) == 0) {
			/* ?status shows slot information */
			if (!slot_status(installer, &error))
				goto error;
		} else {
			g_set_error(&error, CGI_ERROR, CGI_ERROR_BAD_REQUEST, "Resource '%s' unavailable", query_string);
			goto error;
		}

	} else if (g_strcmp0("PUT", method) == 0) {
		/* save stdin to temporary file */
		if (!stdin_to_file(&error))
			goto remove_bundle_on_error;

		/* start rauc install */
		if (!r_installer_call_install_sync(installer, BUNDLE_TARGET_LOCATION, NULL, &error))
			goto remove_bundle_on_error;

		print_headers("200 OK", "text/plain");
		g_print("Upload and install trigger executed successfully.\n");

	} else {
		g_set_error(&error, CGI_ERROR, CGI_ERROR_METHOD_NOT_ALLOWED, "Unsupported method '%s'", method);
		goto error;
	}

	ret = 0;

remove_bundle_on_error:
	/* try to remove bundle */
	if (error)
		g_remove(BUNDLE_TARGET_LOCATION);

error:
	if (error) {
		switch (error->code) {
			case CGI_ERROR_METHOD_NOT_ALLOWED:
				print_headers("405 Method Not Allowed", "text/plain");
				break;
			case CGI_ERROR_BAD_REQUEST:
				print_headers("400 Bad Request", "text/plain");
				break;
			case CGI_ERROR_LENGTH_REQUIRED:
				print_headers("411 Length Required", "text/plain");
				break;
			case CGI_ERROR_SERVICE_UNAVAILABLE:
				print_headers("503 Service Unavailable", "text/plain");
				break;
			default:
				print_headers("500 Internal Server Error", "text/plain");
		}
		g_printerr("%s\n", error->message);
		g_error_free(error);
	}

	g_free(method);
	g_free(query_string);
	g_clear_pointer(&installer, g_object_unref);

	return ret;
}

int main(int argc, char **argv)
{
	return cgi_handler(argc, argv);
}
