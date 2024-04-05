#include <errno.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib-unix.h>
#if ENABLE_JSON
#include <json-glib/json-glib.h>
#include <json-glib/json-gobject.h>
#endif
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "bundle.h"
#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "event_log.h"
#include "install.h"
#include "rauc-installer-generated.h"
#include "service.h"
#include "signature.h"
#include "status_file.h"
#include "update_handler.h"
#include "utils.h"
#include "mark.h"

GMainLoop *r_loop = NULL;
int r_exit_status = 0;

gboolean install_ignore_compatible, install_progressbar = FALSE;
gboolean trust_environment = FALSE;
gboolean verification_disabled = FALSE;
gboolean no_check_time = FALSE;
gboolean info_dumpcert = FALSE;
gboolean info_dumprecipients = FALSE;
gboolean status_detailed = FALSE;
gchar *output_format = NULL;
gchar *keypath = NULL;
gchar *certpath = NULL;
gchar **intermediate = NULL;
gchar *signing_keyring = NULL;
gchar *mksquashfs_args = NULL;
gchar *casync_args = NULL;
gchar **convert_ignore_images = NULL;
gchar **recipients = NULL;
gchar *handler_args = NULL;
gchar *bootslot = NULL;
gchar *installation_txn = NULL;
gboolean utf8_supported = FALSE;
RaucBundleAccessArgs access_args = {0};

static gchar* make_progress_line(gint percentage)
{
	struct winsize w;
	GString *printbuf = NULL;
	gint pbar_len = 0;

	g_return_val_if_fail(percentage <= 100, NULL);

	/* obtain terminal window parameters */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
		g_warning("Unable to obtain window parameters: %s", strerror(errno));
		/* default to 80 */
		w.ws_col = 80;
	}
	pbar_len = w.ws_col - 1 - 1 - 5;

	printbuf = g_string_sized_new(w.ws_col);

	g_string_append_c(printbuf, '[');
	for (int i = 0; i < pbar_len; i++) {
		g_string_append_c(printbuf, i > pbar_len * percentage / 100 ? ' ' : '#');
	}
	g_string_append_c(printbuf, ']');
	g_string_append_printf(printbuf, "%3d%%", percentage);

	return g_string_free(printbuf, FALSE);
}

static gboolean install_notify(gpointer data)
{
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	while (!g_queue_is_empty(&args->status_messages)) {
		gchar *msg = g_queue_pop_head(&args->status_messages);
		g_print("%s\n", msg);
		g_free(msg);
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
		gpointer data)
{
	RaucInstallArgs *args = data;
	gint32 percentage, depth;
	const gchar *message;

	if (invalidated && invalidated[0]) {
		g_printerr("RAUC service disappeared\n");
		g_mutex_lock(&args->status_mutex);
		args->status_result = 2;
		g_mutex_unlock(&args->status_mutex);
		args->cleanup(args);
		return;
	}

	g_mutex_lock(&args->status_mutex);
	if (g_variant_lookup(changed, "Operation", "&s", &message)) {
		g_queue_push_tail(&args->status_messages, g_strdup(message));
	} else if (g_variant_lookup(changed, "Progress", "(i&si)", &percentage, &message, &depth)) {
		if (install_progressbar && isatty(STDOUT_FILENO)) {
			g_autofree gchar *progress = make_progress_line(percentage);
			/* This does:
			 * - move to start of line
			 * - clear line
			 * - print 2 lines
			 * - move to previous line
			 */
			g_queue_push_tail(&args->status_messages, g_strdup_printf("\r\033[F\033[J%3"G_GINT32_FORMAT "%% %s\n%s", percentage, message, progress));
		} else {
			g_queue_push_tail(&args->status_messages, g_strdup_printf("%3"G_GINT32_FORMAT "%% %s", percentage, message));
		}
	} else if (g_variant_lookup(changed, "LastError", "&s", &message) && message[0] != '\0') {
		g_queue_push_tail(&args->status_messages, g_strdup_printf("%sLastError: %s", isatty(STDOUT_FILENO) ? "\033[J" : "", message));
	}
	g_mutex_unlock(&args->status_mutex);

	if (!g_queue_is_empty(&args->status_messages)) {
		args->notify(args);
	}
}

static void on_installer_completed(GDBusProxy *proxy, gint result,
		gpointer data)
{
	RaucInstallArgs *args = data;

	g_mutex_lock(&args->status_mutex);
	args->status_result = result;
	g_mutex_unlock(&args->status_mutex);

	if (result >= 0) {
		args->cleanup(args);
	}
}

static gchar *resolve_bundle_path(char *path)
{
	g_autofree gchar *bundlescheme = NULL;
	g_autofree gchar *bundlelocation = NULL;
	GError *error = NULL;

	bundlescheme = g_uri_parse_scheme(path);
	if (bundlescheme == NULL && !g_path_is_absolute(path)) {
		g_autofree gchar *cwd = g_get_current_dir();
		bundlelocation = g_build_filename(cwd, path, NULL);
	} else {
		g_autofree gchar *hostname = NULL;

		if (g_strcmp0(bundlescheme, "file") == 0) {
			bundlelocation = g_filename_from_uri(path, &hostname, &error);
			if (!bundlelocation) {
				g_printerr("Conversion error: %s\n", error->message);
				g_clear_error(&error);
				return NULL;
			}

			if (hostname != NULL) {
				g_printerr("file URI with hostname detected. Did you forget to add a leading / ?\n");
				return NULL;
			}

			/* Clear bundlescheme to trigger local path handling */
			g_clear_pointer(&bundlescheme, g_free);
		} else {
			bundlelocation = g_strdup(path);
		}
	}

	/* If the URI parser returns NULL, assume bundle install with local path */
	if (bundlescheme == NULL) {
		if (!g_file_test(bundlelocation, G_FILE_TEST_EXISTS)) {
			g_printerr("No such file: %s\n", bundlelocation);
			return NULL;
		}
	}

	return g_steal_pointer(&bundlelocation);
}

static void print_progress_callback(gint percentage,
		const gchar *message,
		gint nesting_depth)
{
	g_print("%3"G_GINT32_FORMAT "%% %s\n", percentage, message);
}

static gboolean on_sigint(gpointer user_data)
{
	RaucInstallArgs *args = user_data;

	g_mutex_lock(&args->status_mutex);
	args->status_result = 3;
	g_mutex_unlock(&args->status_mutex);

	args->cleanup(args);
	return G_SOURCE_REMOVE;
}

static gboolean install_start(int argc, char **argv)
{
	GBusType bus_type = (!g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session"))
	                    ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;
	RInstaller *installer = NULL;
	RaucInstallArgs *args = NULL;
	GError *error = NULL;
	g_autofree gchar *bundlelocation = NULL;

	g_debug("install started");

	r_exit_status = 1;

	if (argc < 3) {
		g_printerr("A bundle path or URL must be provided\n");
		goto out;
	}

	if (argc > 3) {
		g_printerr("Excess argument: %s\n", argv[3]);
		r_exit_status = 1;
		goto out;
	}

	bundlelocation = resolve_bundle_path(argv[2]);
	if (bundlelocation == NULL)
		goto out;
	g_debug("input bundle: %s", bundlelocation);

	args = install_args_new();
	args->name = g_steal_pointer(&bundlelocation);
	args->notify = install_notify;
	args->cleanup = install_cleanup;
	args->status_result = 2;

	args->ignore_compatible = install_ignore_compatible;
	args->transaction = installation_txn;
	if (access_args.tls_cert)
		args->access_args.tls_cert = g_strdup(access_args.tls_cert);
	if (access_args.tls_key)
		args->access_args.tls_key = g_strdup(access_args.tls_key);
	if (access_args.tls_ca)
		args->access_args.tls_ca = g_strdup(access_args.tls_ca);
	if (access_args.tls_no_verify)
		args->access_args.tls_no_verify = access_args.tls_no_verify;
	if (access_args.http_headers)
		args->access_args.http_headers = g_strdupv(access_args.http_headers);

	r_loop = g_main_loop_new(NULL, FALSE);
	if (ENABLE_SERVICE) {
		g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);

		g_unix_signal_add(SIGINT, on_sigint, args);

		g_variant_dict_insert(&dict, "ignore-compatible", "b", args->ignore_compatible);
		if (args->transaction)
			g_variant_dict_insert(&dict, "transaction-id", "s", args->transaction);
		if (args->access_args.tls_cert)
			g_variant_dict_insert(&dict, "tls-cert", "s", args->access_args.tls_cert);
		if (args->access_args.tls_key)
			g_variant_dict_insert(&dict, "tls-key", "s", args->access_args.tls_key);
		if (args->access_args.tls_ca)
			g_variant_dict_insert(&dict, "tls-ca", "s", args->access_args.tls_ca);
		if (args->access_args.tls_no_verify)
			g_variant_dict_insert(&dict, "tls-no-verify", "b", args->access_args.tls_no_verify);
		if (args->access_args.http_headers)
			g_variant_dict_insert(&dict, "http-headers", "^as", args->access_args.http_headers);

		installer = r_installer_proxy_new_for_bus_sync(bus_type,
				G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
				"de.pengutronix.rauc", "/", NULL, &error);
		if (installer == NULL) {
			g_printerr("Error creating proxy: %s\n", error->message);
			g_error_free(error);
			goto out_loop;
		}
		if (g_signal_connect(installer, "g-properties-changed",
				G_CALLBACK(on_installer_changed), args) <= 0) {
			g_printerr("Failed to connect properties-changed signal\n");
			goto out_loop;
		}
		if (g_signal_connect(installer, "completed",
				G_CALLBACK(on_installer_completed), args) <= 0) {
			g_printerr("Failed to connect completed signal\n");
			goto out_loop;
		}
		g_debug("Trying to contact rauc service");
		if (!r_installer_call_install_bundle_sync(
				installer,
				args->name,
				g_variant_dict_end(&dict), /* floating, no unref needed */
				NULL,
				&error)) {
			if (g_dbus_error_is_remote_error(error))
				g_dbus_error_strip_remote_error(error);
			g_printerr("Failed to contact rauc service: %s\n", error->message);
			g_error_free(error);
			goto out_loop;
		}
	} else {
		if (!determine_slot_states(&error)) {
			g_printerr("Failed to determine slot states: %s\n", error->message);
			g_clear_error(&error);
			r_exit_status = 1;
			return TRUE;
		}

		r_context_register_progress_callback(print_progress_callback);
		install_run(args);
	}

	g_main_loop_run(r_loop);


out_loop:
	switch (args->status_result) {
		case 0:
			g_print("Installing `%s` succeeded\n", args->name);
			break;
		case 1:
			g_printerr("Installing `%s` failed\n", args->name);
			break;
		case 2:
			g_printerr("D-Bus error while installing `%s`\n", args->name);
			break;
		case 3:
			g_print("\nCtrl+C pressed. Exiting rauc installation client...\n"
					"Note that this will not abort the installation running in the rauc service!\n");
			break;
		default:
			g_printerr("Installing `%s` failed with unknown exit code: %d\n", args->name, args->status_result);
			break;
	}
	r_exit_status = args->status_result;
	g_clear_pointer(&r_loop, g_main_loop_unref);

	if (installer)
		g_signal_handlers_disconnect_by_data(installer, args);
	g_clear_object(&installer);
	install_args_free(args);

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean bundle_start(int argc, char **argv)
{
	GError *ierror = NULL;
	g_autofree gchar *inpath = NULL;
	g_autofree gchar *outpath = NULL;
	g_autofree gchar *outdir = NULL;
	g_debug("bundle start");

	if (argc < 3) {
		g_printerr("An input directory name must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output bundle name must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_printerr("Cert and key files must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	inpath = resolve_path(NULL, argv[2]);
	outpath = resolve_path(NULL, argv[3]);

	if (!g_file_test(inpath, G_FILE_TEST_IS_DIR)) {
		g_printerr("Input path must point to a directory!\n");
		r_exit_status = 1;
		goto out;
	}

	/* strip trailing slash for comparison */
	if (g_str_has_suffix(inpath, "/")) {
		inpath[strlen(inpath)-1] = '\0';
	}

	outdir = g_path_get_dirname(outpath);
	if (g_str_has_prefix(outdir, inpath)) {
		g_printerr("Bundle path must be located outside input directory!\n");
		r_exit_status = 1;
		goto out;
	}

	g_debug("input directory: %s", inpath);
	g_debug("output bundle: %s", outpath);

	if (!create_bundle(argv[3], argv[2], &ierror)) {
		g_printerr("Failed to create bundle: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

static gboolean write_slot_start(int argc, char **argv)
{
	GError *ierror = NULL;
	g_autoptr(RaucImage) image = g_new0(RaucImage, 1);
	RaucSlot *slot = NULL;
	g_autoptr(GFileInfo) info = NULL;
	g_autoptr(GInputStream) instream = NULL;
	g_autoptr(GFile) imagefile = NULL;
	img_to_slot_handler update_handler = NULL;

	g_debug("write_slot_start");

	if (argc < 3) {
		g_printerr("A target slot name must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An image must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	/* construct RaucImage with required attributes */
	imagefile = g_file_new_for_path(argv[3]);
	instream = (GInputStream*)g_file_read(imagefile, NULL, &ierror);
	if (instream == NULL) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	info = g_file_input_stream_query_info(G_FILE_INPUT_STREAM(instream),
			G_FILE_ATTRIBUTE_STANDARD_SIZE, NULL, &ierror);
	if (info == NULL) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	image->checksum.size = g_file_info_get_size(info);
	image->filename = g_strdup(argv[3]);

	/* retrieve RaucSlot */
	slot = g_hash_table_lookup(r_context()->config->slots, argv[2]);
	if (slot == NULL) {
		g_printerr("No matching slot found for given slot name\n");
		r_exit_status = 1;
		goto out;
	}

	if (slot->readonly) {
		g_printerr("Reject writing to readonly slot\n");
		r_exit_status = 1;
		goto out;
	}

	/* retrieve update handler */
	update_handler = get_update_handler(image, slot, &ierror);
	if (update_handler == NULL) {
		g_printerr("%s\n", ierror->message);
		r_exit_status = 1;
		goto out;
	}

	/* call update handler */
	if (!update_handler(image, slot, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	g_print("Slot written successfully\n");

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean resign_start(int argc, char **argv)
{
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("resign start");

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_printerr("Cert and key files must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (verification_disabled)
		check_bundle_params |= CHECK_BUNDLE_NO_VERIFY;
	if (no_check_time)
		check_bundle_params |= CHECK_BUNDLE_NO_CHECK_TIME;

	if (!check_bundle(argv[2], &bundle, check_bundle_params, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!resign_bundle(bundle, argv[3], &ierror)) {
		g_printerr("Failed to resign bundle: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean replace_signature_start(int argc, char **argv)
{
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("replace signature start");

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An input signature file must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 5) {
		g_printerr("An output bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 5) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	g_debug("input bundle: %s", argv[2]);
	g_debug("input signature: %s", argv[3]);
	g_debug("output file: %s", argv[4]);

	if (verification_disabled)
		check_bundle_params |= CHECK_BUNDLE_NO_VERIFY;
	if (trust_environment)
		check_bundle_params |= CHECK_BUNDLE_TRUST_ENV;

	if (!check_bundle(argv[2], &bundle, check_bundle_params, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!replace_signature(bundle, argv[3], argv[4], check_bundle_params, &ierror)) {
		g_printerr("Failed to replace signature: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean extract_signature_start(int argc, char **argv)
{
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("extract signature start");

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output signature file must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	g_debug("input bundle: %s", argv[2]);
	g_debug("output file: %s", argv[3]);

	if (trust_environment)
		check_bundle_params |= CHECK_BUNDLE_TRUST_ENV;

	if (!check_bundle(argv[2], &bundle, check_bundle_params, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!extract_signature(bundle, argv[3], &ierror)) {
		g_printerr("Failed to extract signature: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

static gboolean extract_start(int argc, char **argv)
{
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("extract start");

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output directory must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	g_debug("input bundle: %s", argv[2]);
	g_debug("output dir: %s", argv[3]);

	if (trust_environment)
		check_bundle_params |= CHECK_BUNDLE_TRUST_ENV;

	if (!check_bundle(argv[2], &bundle, check_bundle_params, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!extract_bundle(bundle, argv[3], &ierror)) {
		g_printerr("Failed to extract bundle: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean convert_start(int argc, char **argv)
{
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("convert start");

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_printerr("Cert and key files must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output bundle name must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	g_debug("input bundle: %s", argv[2]);
	g_debug("output bundle: %s", argv[3]);

	if (verification_disabled)
		check_bundle_params |= CHECK_BUNDLE_NO_VERIFY;
	if (trust_environment)
		check_bundle_params |= CHECK_BUNDLE_TRUST_ENV;

	if (!check_bundle(argv[2], &bundle, check_bundle_params, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!create_casync_bundle(bundle, argv[3], (const gchar**) convert_ignore_images, &ierror)) {
		g_printerr("Failed to create bundle: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	g_print("Bundle written to %s\n", argv[3]);

out:
	return TRUE;
}

G_GNUC_UNUSED
static gboolean encrypt_start(int argc, char **argv)
{
	g_autoptr(RaucBundle) bundle = NULL;
	GError *ierror = NULL;
	g_debug("encrypt start");

	if (r_context()->recipients == NULL) {
		g_printerr("One or multiple recipient certificates must be provided (via --to)\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 3) {
		g_printerr("An input bundle must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc < 4) {
		g_printerr("An output bundle name must be provided\n");
		r_exit_status = 1;
		goto out;
	}

	if (argc > 4) {
		g_printerr("Excess argument: %s\n", argv[4]);
		r_exit_status = 1;
		goto out;
	}

	g_debug("input bundle: %s", argv[2]);
	g_debug("output bundle: %s", argv[3]);

	if (!check_bundle(argv[2], &bundle, CHECK_BUNDLE_DEFAULT, NULL, &ierror)) {
		g_printerr("%s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	if (!encrypt_bundle(bundle, argv[3], &ierror)) {
		g_printerr("Failed to create bundle: %s\n", ierror->message);
		g_clear_error(&ierror);
		r_exit_status = 1;
		goto out;
	}

	g_print("Encrypted bundle written to %s\n", argv[3]);

out:
	return TRUE;
}

/* Definition list for terminal colors */
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define KBLD  "\x1B[1m"

/* Takes a shell variable and its desired argument as input and appends it to
 * the provided text with taking care of correct shell quoting */
static void formatter_shell_append(GString* text, const gchar* varname, const gchar* argument)
{
	g_autofree gchar* quoted = g_shell_quote(argument ?: "");
	g_string_append_printf(text, "%s=%s\n", varname, quoted);
}
/* Same as above, expect that it has a cnt argument to add per-slot-number
 * strings */
static void formatter_shell_append_n(GString* text, const gchar* varname, gint cnt, const gchar* argument)
{
	g_autofree gchar* quoted = g_shell_quote(argument ?: "");
	g_string_append_printf(text, "%s_%d=%s\n", varname, cnt, quoted);
}

static gchar *info_formatter_shell(RaucManifest *manifest)
{
	GString *text = g_string_new(NULL);
	GPtrArray *hooks = NULL;
	gchar *temp_string = NULL;
	gint cnt;

	formatter_shell_append(text, "RAUC_MF_COMPATIBLE", manifest->update_compatible);
	formatter_shell_append(text, "RAUC_MF_VERSION", manifest->update_version);
	formatter_shell_append(text, "RAUC_MF_DESCRIPTION", manifest->update_description);
	formatter_shell_append(text, "RAUC_MF_BUILD", manifest->update_build);
	formatter_shell_append(text, "RAUC_MF_HASH", manifest->hash);
	formatter_shell_append(text, "RAUC_MF_FORMAT", r_manifest_bundle_format_to_str(manifest->bundle_format));
	g_string_append_printf(text, "RAUC_MF_IMAGES=%d\n", g_list_length(manifest->images));

	hooks = g_ptr_array_new();
	if (manifest->hooks.install_check == TRUE) {
		g_ptr_array_add(hooks, g_strdup("install-check"));
	}
	g_ptr_array_add(hooks, NULL);

	temp_string = g_strjoinv(" ", (gchar**) hooks->pdata);
	formatter_shell_append(text, "RAUC_MF_HOOKS", temp_string);
	g_free(temp_string);

	g_ptr_array_unref(hooks);

	if (manifest->meta && g_hash_table_size(manifest->meta)) {
		GHashTableIter iter;
		GHashTable *kvs;
		const gchar *group;

		g_hash_table_iter_init(&iter, manifest->meta);
		while (g_hash_table_iter_next(&iter, (gpointer*)&group, (gpointer*)&kvs)) {
			GHashTableIter kvs_iter;
			const gchar *key, *value;
			g_autofree gchar *env_group = r_prepare_env_key(group, NULL);

			if (!env_group)
				continue;

			g_hash_table_iter_init(&kvs_iter, kvs);
			while (g_hash_table_iter_next(&kvs_iter, (gpointer*)&key, (gpointer*)&value)) {
				g_autofree gchar *env_key = r_prepare_env_key(key, NULL);
				g_autofree gchar *var = NULL;

				if (!env_key)
					continue;

				var = g_strdup_printf("RAUC_META_%s_%s", env_group, env_key);
				formatter_shell_append(text, var, value);
			}
		}
	}

	cnt = 0;
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		formatter_shell_append_n(text, "RAUC_IMAGE_NAME", cnt, img->filename);
		formatter_shell_append_n(text, "RAUC_IMAGE_CLASS", cnt, img->slotclass);
		formatter_shell_append_n(text, "RAUC_IMAGE_VARIANT", cnt, img->variant);
		formatter_shell_append_n(text, "RAUC_IMAGE_DIGEST", cnt, img->checksum.digest);
		g_string_append_printf(text, "RAUC_IMAGE_SIZE_%d=%"G_GOFFSET_FORMAT "\n", cnt, img->checksum.size);

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

		temp_string = g_strjoinv(" ", (gchar**) hooks->pdata);
		formatter_shell_append_n(text, "RAUC_IMAGE_HOOKS", cnt, temp_string);
		g_free(temp_string);

		g_ptr_array_unref(hooks);

		if (img->adaptive) {
			temp_string = g_strjoinv(" ", (gchar**) img->adaptive);
			formatter_shell_append_n(text, "RAUC_IMAGE_ADAPTIVE", cnt, temp_string);
			g_free(temp_string);
		}

		cnt++;
	}

	return g_string_free(text, FALSE);
}

static gchar *info_formatter_readable(RaucManifest *manifest)
{
	GString *text = g_string_new(NULL);
	GPtrArray *hooks = NULL;
	gchar *temp_string = NULL;
	gboolean show_crypt_key = FALSE; /* change to TRUE to display dm-crypt key */
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

	temp_string = g_strjoinv(" ", (gchar**) hooks->pdata);
	g_string_append_printf(text, "Hooks:      \t'%s'\n", temp_string);
	g_free(temp_string);

	g_string_append_printf(text, "Bundle Format: \t%s", r_manifest_bundle_format_to_str(manifest->bundle_format));
	if (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		if (manifest->was_encrypted)
			g_string_append_printf(text, KBLD KGRN " [encrypted CMS]"KNRM);
		else
			g_string_append_printf(text, KBLD KYEL " [unencrypted CMS]"KNRM);
	}
	g_string_append_printf(text, "\n");

	if (manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		g_string_append_printf(text, "  Crypt Key: \t'%s'\n", show_crypt_key ? manifest->bundle_crypt_key : "<hidden>");
	}
	if (manifest->bundle_format == R_MANIFEST_FORMAT_VERITY || manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT) {
		g_string_append_printf(text, "  Verity Salt: \t'%s'\n", manifest->bundle_verity_salt);
		g_string_append_printf(text, "  Verity Hash: \t'%s'\n", manifest->bundle_verity_hash);
		g_string_append_printf(text, "  Verity Size: \t%"G_GUINT64_FORMAT "\n", manifest->bundle_verity_size);
	}
	g_string_append_printf(text, "Manifest Hash:\t'%s'\n\n", manifest->hash);

	g_ptr_array_unref(hooks);

	if (manifest->meta && g_hash_table_size(manifest->meta)) {
		GHashTableIter iter;
		GHashTable *kvs;
		const gchar *group;

		g_string_append_printf(text, "Metadata:\n");

		g_hash_table_iter_init(&iter, manifest->meta);
		while (g_hash_table_iter_next(&iter, (gpointer*)&group, (gpointer*)&kvs)) {
			GHashTableIter kvs_iter;
			const gchar *key, *value;

			g_string_append_printf(text, "\t%s:\n", group);

			g_hash_table_iter_init(&kvs_iter, kvs);
			while (g_hash_table_iter_next(&kvs_iter, (gpointer*)&key, (gpointer*)&value)) {
				g_string_append_printf(text, "\t\t%s: %s\n", key, value);
			}
		}
	}

	cnt = g_list_length(manifest->images);
	g_string_append_printf(text, "\n%d Image%s%s\n", cnt, cnt == 1 ? "" : "s", cnt > 0 ? ":" : "");
	cnt = 1;
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		g_string_append_printf(text, "  "KBLD "[%s]"KNRM "\n", img->slotclass);
		if (img->variant)
			g_string_append_printf(text, "\tVariant:   %s\n", img->variant);
		if (img->filename) {
			g_autofree gchar* formatted_size = g_format_size_full(img->checksum.size, G_FORMAT_SIZE_LONG_FORMAT);
			g_string_append_printf(text, "\tFilename:  %s\n", img->filename);
			g_string_append_printf(text, "\tChecksum:  %s\n", img->checksum.digest);
			g_string_append_printf(text, "\tSize:      %s\n", formatted_size);
		} else {
			g_string_append_printf(text, "\t(no image file)\n");
		}

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

		temp_string = g_strjoinv(" ", (gchar**) hooks->pdata);
		g_string_append_printf(text, "\tHooks:     %s\n", temp_string);
		g_free(temp_string);

		g_ptr_array_unref(hooks);

		if (img->adaptive) {
			temp_string = g_strjoinv(" ", (gchar**) img->adaptive);
			g_string_append_printf(text, "\tAdaptive:  %s\n", temp_string);
			g_free(temp_string);
		}

		cnt++;
	}

	return g_string_free(text, FALSE);
}


#if ENABLE_JSON
/* Takes a GStrv and adds a JSON array to the builder. If the GStrv is NULL, an
 * empty array is added. */
static void strv_to_json_array(JsonBuilder *builder, GStrv strv)
{
	g_return_if_fail(JSON_IS_BUILDER(builder));

	json_builder_begin_array(builder);
	if (strv) {
		for (gchar **m = strv; *m != NULL; m++) {
			json_builder_add_string_value(builder, *m);
		}
	}
	json_builder_end_array(builder);
}
#endif

static gchar* info_formatter_json_base(RaucManifest *manifest, gboolean pretty)
{
#if ENABLE_JSON
	g_autoptr(JsonGenerator) gen = NULL;
	g_autoptr(JsonNode) root = NULL;
	g_autoptr(JsonBuilder) builder = json_builder_new();

	json_builder_begin_object(builder);

	json_builder_set_member_name(builder, "compatible");
	json_builder_add_string_value(builder, manifest->update_compatible);

	json_builder_set_member_name(builder, "version");
	json_builder_add_string_value(builder, manifest->update_version);

	json_builder_set_member_name(builder, "description");
	json_builder_add_string_value(builder, manifest->update_description);

	json_builder_set_member_name(builder, "build");
	json_builder_add_string_value(builder, manifest->update_build);

	json_builder_set_member_name(builder, "format");
	json_builder_add_string_value(builder, r_manifest_bundle_format_to_str(manifest->bundle_format));

	json_builder_set_member_name(builder, "hooks");
	json_builder_begin_array(builder);
	if (manifest->hooks.install_check == TRUE) {
		json_builder_add_string_value(builder, "install-check");
	}
	json_builder_end_array(builder);

	json_builder_set_member_name(builder, "hash");
	json_builder_add_string_value(builder, manifest->hash);

	json_builder_set_member_name(builder, "images");
	json_builder_begin_array(builder);

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;

		json_builder_begin_object(builder);
		json_builder_set_member_name(builder, img->slotclass);
		json_builder_begin_object(builder);
		json_builder_set_member_name(builder, "variant");
		json_builder_add_string_value(builder, img->variant);
		json_builder_set_member_name(builder, "filename");
		json_builder_add_string_value(builder, img->filename);
		json_builder_set_member_name(builder, "checksum");
		json_builder_add_string_value(builder, img->checksum.digest);
		json_builder_set_member_name(builder, "size");
		json_builder_add_int_value(builder, img->checksum.size);
		json_builder_set_member_name(builder, "hooks");
		json_builder_begin_array(builder);
		if (img->hooks.pre_install == TRUE) {
			json_builder_add_string_value(builder, "pre-install");
		}
		if (img->hooks.install == TRUE) {
			json_builder_add_string_value(builder, "install");
		}
		if (img->hooks.post_install == TRUE) {
			json_builder_add_string_value(builder, "post-install");
		}
		json_builder_end_array(builder);
		json_builder_set_member_name(builder, "adaptive");
		strv_to_json_array(builder, img->adaptive);
		json_builder_end_object(builder);
		json_builder_end_object(builder);
	}

	json_builder_end_array(builder);

	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	json_generator_set_pretty(gen, pretty);
	return json_generator_to_data(gen, NULL);
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

static gchar* info_formatter_json_2(RaucManifest *manifest)
{
#if ENABLE_JSON
	g_autoptr(JsonGenerator) gen = json_generator_new();
	g_autoptr(GVariant) dict = r_manifest_to_dict(manifest);
	g_autoptr(JsonNode) root = json_gvariant_serialize(dict);

	json_generator_set_root(gen, root);
	json_generator_set_pretty(gen, TRUE);
	return json_generator_to_data(gen, NULL);
#else
	g_error("json support is disabled");
	return NULL;
#endif
}

static gboolean info_start(int argc, char **argv)
{
	g_autofree gchar *bundlelocation = NULL;
	g_autoptr(RaucManifest) manifest = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	gchar* (*formatter)(RaucManifest *manifest) = NULL;
	gchar *text;
	CheckBundleParams check_bundle_params = CHECK_BUNDLE_DEFAULT;

	if (argc < 3) {
		g_printerr("A bundle path or URL must be provided\n");
		r_exit_status = 1;
		return FALSE;
	}

	if (argc > 3) {
		g_printerr("Excess argument: %s\n", argv[3]);
		r_exit_status = 1;
		goto out;
	}

	if (!output_format || g_strcmp0(output_format, "readable") == 0) {
		formatter = info_formatter_readable;
	} else if (g_strcmp0(output_format, "shell") == 0) {
		formatter = info_formatter_shell;
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json") == 0) {
		formatter = info_formatter_json;
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json-pretty") == 0) {
		formatter = info_formatter_json_pretty;
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json-2") == 0) {
		formatter = info_formatter_json_2;
	} else {
		g_printerr("Unknown output format: '%s'\n", output_format);
		goto out;
	}

	bundlelocation = resolve_bundle_path(argv[2]);
	if (bundlelocation == NULL)
		goto out;
	g_debug("input bundle: %s", bundlelocation);

	if (verification_disabled)
		check_bundle_params |= CHECK_BUNDLE_NO_VERIFY;
	if (no_check_time)
		check_bundle_params |= CHECK_BUNDLE_NO_CHECK_TIME;

	res = check_bundle(bundlelocation, &bundle, check_bundle_params, &access_args, &error);
	if (!res) {
		g_printerr("%s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	if (bundle->manifest) {
		manifest = g_steal_pointer(&bundle->manifest);
	} else {
		res = load_manifest_from_bundle(bundle, &manifest, &error);
		if (!res) {
			g_printerr("%s\n", error->message);
			g_clear_error(&error);
			goto out;
		}
	}

	text = formatter(manifest);
	g_print("%s\n", text);
	g_free(text);

	if (info_dumpcert) {
		text = sigdata_to_string(bundle->sigdata, NULL);
		g_print("%s\n", text);
		g_free(text);
	}

	if (info_dumprecipients) {
		if (!bundle->enveloped_data) {
			g_print("No recipient data to dump (bundle is not encrypted)\n\n");
		} else {
			text = envelopeddata_to_string(bundle->enveloped_data, NULL);
			g_print("%s\n", text);
			g_free(text);
		}
	}

	if (!output_format || g_strcmp0(output_format, "readable") == 0) {
		if (!bundle->verified_chain) {
			g_print("Signature unverified\n");
			goto out;
		}

		text = format_cert_chain(bundle->verified_chain);
		g_print("%s\n", text);
		g_free(text);
	}

out:
	r_exit_status = res ? 0 : 1;
	return TRUE;
}

typedef struct {
	/* Reference to primary slot (must not be freed) */
	RaucSlot *primary;
	gchar *compatible;
	gchar *variant;
	gchar *bootslot;
	GHashTable *slots;
} RaucStatusPrint;

static void free_status_print(RaucStatusPrint *status)
{
	if (!status)
		return;

	g_free(status->compatible);
	g_free(status->variant);
	g_free(status->bootslot);
	if (status->slots)
		g_hash_table_destroy(status->slots);

	g_free(status);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucStatusPrint, free_status_print);

static void r_string_append_slot(GString *text, RaucSlot *slot, RaucStatusPrint *status)
{
	RaucSlotStatus *slot_state = slot->status;

	/* bootname slots get an empty or full dot depending on whether they
	 * are primary or not */
	if (slot->bootname) {
		if (utf8_supported)
			g_string_append_unichar(text, slot == status->primary ? 0x23FA :  0x25CB);
		else
			g_string_append(text, slot == status->primary ? KBLD "x"KNRM :  "o");
	} else {
		g_string_append_c(text, ' ');
	}
	g_string_append_printf(text, "%s%s%s"KBLD "[%s]"KNRM " (%s, %s, %s%s"KNRM ")",
			slot->parent ? "   " : " ",
			slot->state & ST_ACTIVE ? KGRN : "",
			slot->state == ST_BOOTED ? KGRN : "",
			slot->name,
			slot->device,
			slot->type,
			slot->state == ST_BOOTED ? KBLD : "",
			r_slot_slotstate_to_str(slot->state));
	if (slot->bootname)
		g_string_append_printf(text, "\n\tbootname: "KBLU "%s"KNRM, slot->bootname);
	if (slot->description)
		g_string_append_printf(text, "\n\tdescription: %s", slot->description);
	if (slot->mount_point)
		g_string_append_printf(text, "\n\tmounted: %s", slot->mount_point);
	if (slot->bootname)
		g_string_append_printf(text, "\n\tboot status: %s", slot->boot_good ? KGRN "good"KNRM : KRED "bad"KNRM);
	if (status_detailed && slot_state) {
		g_string_append_printf(text, "\n      slot status:");
		g_string_append_printf(text, "\n          bundle:");
		g_string_append_printf(text, "\n              compatible=%s", slot_state->bundle_compatible);
		if (slot_state->bundle_version)
			g_string_append_printf(text, "\n              version=%s", slot_state->bundle_version);
		if (slot_state->bundle_description)
			g_string_append_printf(text, "\n              description=%s", slot_state->bundle_description);
		if (slot_state->bundle_build)
			g_string_append_printf(text, "\n              build=%s", slot_state->bundle_build);
		if (slot_state->bundle_hash)
			g_string_append_printf(text, "\n              hash=%s", slot_state->bundle_hash);
		if (slot_state->checksum.digest && slot_state->checksum.type == G_CHECKSUM_SHA256) {
			g_autofree gchar* formatted_size = g_format_size_full(slot_state->checksum.size, G_FORMAT_SIZE_LONG_FORMAT);
			g_string_append_printf(text, "\n          checksum:");
			g_string_append_printf(text, "\n              sha256=%s", slot_state->checksum.digest);
			g_string_append_printf(text, "\n              size=%s", formatted_size);
		}
		g_string_append_printf(text, "\n          installed:");
		if (slot_state->installed_timestamp) {
			g_string_append_printf(text, "\n              timestamp=%s", slot_state->installed_timestamp);
			g_string_append_printf(text, "\n              count=%u", slot_state->installed_count);
		}
		if (slot_state->installed_txn) {
			g_string_append_printf(text, "\n              transaction=%s", slot_state->installed_txn);
		}
		if (slot_state->activated_timestamp) {
			g_string_append_printf(text, "\n          activated:");
			g_string_append_printf(text, "\n              timestamp=%s", slot_state->activated_timestamp);
			g_string_append_printf(text, "\n              count=%u", slot_state->activated_count);
		}
		if (slot_state->status)
			g_string_append_printf(text, "\n          status=%s", slot_state->status);
	}
	g_string_append_c(text, '\n');
}

static gchar* r_status_formatter_readable(RaucStatusPrint *status)
{
	GString *text = g_string_new(NULL);
	RaucSlot *bootedfrom = NULL;
	g_autofree gchar **slotclasses = NULL;

	g_return_val_if_fail(status, NULL);

	bootedfrom = r_slot_get_booted(status->slots);

	g_string_append(text, "=== System Info ===\n");
	g_string_append_printf(text, "Compatible:  %s\n", status->compatible);
	g_string_append_printf(text, "Variant:     %s\n", status->variant);
	g_string_append_printf(text, "Booted from: %s (%s)\n\n", bootedfrom ? bootedfrom->name : NULL, status->bootslot);

	g_string_append(text, "=== Bootloader ===\n");
	if (!status->primary)
		g_string_append_printf(text, "Activated: none\n\n");
	else
		g_string_append_printf(text, "Activated: %s (%s)\n\n", status->primary->name, status->primary->bootname);

	g_string_append(text, "=== Slot States ===\n");
	slotclasses = r_slot_get_root_classes(status->slots);

	for (gchar **cls = slotclasses; *cls != NULL; cls++) {
		g_autoptr(GList) slots = NULL;

		slots = r_slot_get_all_of_class(status->slots, *cls);

		for (GList *l = slots; l != NULL; l = l->next) {
			RaucSlot *xslot = l->data;

			g_autoptr(GList) children = NULL;

			r_string_append_slot(text, xslot, status);

			children = r_slot_get_all_children(status->slots, xslot);
			for (GList *cl = children; cl != NULL; cl = cl->next) {
				RaucSlot *child_slot = cl->data;

				r_string_append_slot(text, child_slot, status);
			}

			g_string_append(text, "\n");
		}
	}

	return g_string_free(text, FALSE);
}

static gchar* r_status_formatter_shell(RaucStatusPrint *status)
{
	GHashTableIter iter;
	gint slotcnt = 0;
	GString *text = g_string_new(NULL);
	GPtrArray *slotnames, *slotnumbers = NULL;
	gchar* slotstring = NULL;
	RaucSlot *slot = NULL;
	gchar *name;

	g_return_val_if_fail(status, NULL);

	formatter_shell_append(text, "RAUC_SYSTEM_COMPATIBLE", status->compatible);
	formatter_shell_append(text, "RAUC_SYSTEM_VARIANT", status->variant);
	formatter_shell_append(text, "RAUC_SYSTEM_BOOTED_BOOTNAME", status->bootslot);
	formatter_shell_append(text, "RAUC_BOOT_PRIMARY", status->primary ? status->primary->name : NULL);

	slotnames = g_ptr_array_new();
	slotnumbers = g_ptr_array_new_with_free_func(g_free);
	g_hash_table_iter_init(&iter, status->slots);
	while (g_hash_table_iter_next(&iter, (gpointer*) &name, NULL)) {
		g_ptr_array_add(slotnames, name);
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
	g_hash_table_iter_init(&iter, status->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		RaucSlotStatus *slot_state = slot->status;

		slotcnt++;

		formatter_shell_append_n(text, "RAUC_SLOT_STATE", slotcnt, r_slot_slotstate_to_str(slot->state));
		formatter_shell_append_n(text, "RAUC_SLOT_CLASS", slotcnt, slot->sclass);
		formatter_shell_append_n(text, "RAUC_SLOT_DEVICE", slotcnt, slot->device);
		formatter_shell_append_n(text, "RAUC_SLOT_TYPE", slotcnt, slot->type);
		formatter_shell_append_n(text, "RAUC_SLOT_BOOTNAME", slotcnt, slot->bootname);
		formatter_shell_append_n(text, "RAUC_SLOT_PARENT", slotcnt, slot->parent ? slot->parent->name : NULL);
		formatter_shell_append_n(text, "RAUC_SLOT_MOUNTPOINT", slotcnt, slot->mount_point);
		if (slot->bootname)
			formatter_shell_append_n(text, "RAUC_SLOT_BOOT_STATUS", slotcnt, slot->boot_good ? "good" : "bad");
		else
			formatter_shell_append_n(text, "RAUC_SLOT_BOOT_STATUS", slotcnt, NULL);
		if (status_detailed && slot_state) {
			gchar *str;

			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_BUNDLE_COMPATIBLE", slotcnt, slot_state->bundle_compatible);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_BUNDLE_VERSION", slotcnt, slot_state->bundle_version);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_BUNDLE_DESCRIPTION", slotcnt, slot_state->bundle_description);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_BUNDLE_BUILD", slotcnt, slot_state->bundle_build);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_BUNDLE_HASH", slotcnt, slot_state->bundle_hash);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_CHECKSUM_SHA256", slotcnt, slot_state->checksum.digest);
			str = g_strdup_printf("%"G_GOFFSET_FORMAT, slot_state->checksum.size);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_CHECKSUM_SIZE", slotcnt, str);
			g_free(str);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_INSTALLED_TIMESTAMP", slotcnt, slot_state->installed_timestamp);
			str = g_strdup_printf("%u", slot_state->installed_count);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_INSTALLED_COUNT", slotcnt, str);
			g_free(str);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_ACTIVATED_TIMESTAMP", slotcnt, slot_state->activated_timestamp);
			str = g_strdup_printf("%u", slot_state->activated_count);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_ACTIVATED_COUNT", slotcnt, str);
			g_free(str);
			formatter_shell_append_n(text, "RAUC_SLOT_STATUS_STATUS", slotcnt, slot_state->status);
		}
	}

	return g_string_free(text, FALSE);
}

static gchar* r_status_formatter_json(RaucStatusPrint *status, gboolean pretty)
{
#if ENABLE_JSON
	g_autoptr(JsonGenerator) gen = NULL;
	g_autoptr(JsonNode) root = NULL;
	GHashTableIter iter;
	g_autoptr(JsonBuilder) builder = json_builder_new();
	RaucSlot *slot = NULL;

	g_return_val_if_fail(status, NULL);

	json_builder_begin_object(builder);

	json_builder_set_member_name(builder, "compatible");
	json_builder_add_string_value(builder, status->compatible);

	json_builder_set_member_name(builder, "variant");
	json_builder_add_string_value(builder, status->variant);

	json_builder_set_member_name(builder, "booted");
	json_builder_add_string_value(builder, status->bootslot);

	json_builder_set_member_name(builder, "boot_primary");
	json_builder_add_string_value(builder, status->primary ? status->primary->name : NULL);

	json_builder_set_member_name(builder, "slots");
	json_builder_begin_array(builder);

	g_hash_table_iter_init(&iter, status->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		RaucSlotStatus *slot_state = slot->status;

		json_builder_begin_object(builder);
		json_builder_set_member_name(builder, slot->name);
		json_builder_begin_object(builder);
		json_builder_set_member_name(builder, "class");
		json_builder_add_string_value(builder, slot->sclass);
		json_builder_set_member_name(builder, "device");
		json_builder_add_string_value(builder, slot->device);
		json_builder_set_member_name(builder, "type");
		json_builder_add_string_value(builder, slot->type);
		json_builder_set_member_name(builder, "bootname");
		json_builder_add_string_value(builder, slot->bootname);
		json_builder_set_member_name(builder, "state");
		json_builder_add_string_value(builder, r_slot_slotstate_to_str(slot->state));
		json_builder_set_member_name(builder, "parent");
		json_builder_add_string_value(builder, slot->parent ? slot->parent->name : NULL);
		json_builder_set_member_name(builder, "mountpoint");
		json_builder_add_string_value(builder, slot->mount_point);
		json_builder_set_member_name(builder, "boot_status");
		if (slot->bootname)
			json_builder_add_string_value(builder, slot->boot_good ? "good" : "bad");
		else
			json_builder_add_string_value(builder, NULL);
		if (status_detailed && slot_state) {
			json_builder_set_member_name(builder, "slot_status");
			json_builder_begin_object(builder);     /* slot_status */
			json_builder_set_member_name(builder, "bundle");
			json_builder_begin_object(builder);             /* bundle */
			json_builder_set_member_name(builder, "compatible");
			json_builder_add_string_value(builder, slot_state->bundle_compatible);
			if (slot_state->bundle_version) {
				json_builder_set_member_name(builder, "version");
				json_builder_add_string_value(builder, slot_state->bundle_version);
			}
			if (slot_state->bundle_description) {
				json_builder_set_member_name(builder, "description");
				json_builder_add_string_value(builder, slot_state->bundle_description);
			}
			if (slot_state->bundle_build) {
				json_builder_set_member_name(builder, "build");
				json_builder_add_string_value(builder, slot_state->bundle_build);
			}
			if (slot_state->bundle_hash) {
				json_builder_set_member_name(builder, "hash");
				json_builder_add_string_value(builder, slot_state->bundle_hash);
			}
			json_builder_end_object(builder);               /* bundle */
			if (slot_state->checksum.digest && slot_state->checksum.type == G_CHECKSUM_SHA256) {
				json_builder_set_member_name(builder, "checksum");
				json_builder_begin_object(builder);     /* checksum */
				json_builder_set_member_name(builder, "sha256");
				json_builder_add_string_value(builder, slot_state->checksum.digest);
				json_builder_set_member_name(builder, "size");
				json_builder_add_int_value(builder, slot_state->checksum.size);
				json_builder_end_object(builder);       /* checksum */
			}
			if (slot_state->installed_timestamp) {
				json_builder_set_member_name(builder, "installed");
				json_builder_begin_object(builder);     /* installed */
				json_builder_set_member_name(builder, "timestamp");
				json_builder_add_string_value(builder, slot_state->installed_timestamp);
				json_builder_set_member_name(builder, "count");
				json_builder_add_int_value(builder, slot_state->installed_count);
				json_builder_end_object(builder);       /* installed */
			}
			if (slot_state->activated_timestamp) {
				json_builder_set_member_name(builder, "activated");
				json_builder_begin_object(builder);     /* activated */
				json_builder_set_member_name(builder, "timestamp");
				json_builder_add_string_value(builder, slot_state->activated_timestamp);
				json_builder_set_member_name(builder, "count");
				json_builder_add_int_value(builder, slot_state->activated_count);
				json_builder_end_object(builder);       /* activated */
			}
			if (slot_state->status) {
				json_builder_set_member_name(builder, "status");
				json_builder_add_string_value(builder, slot_state->status);
			}
			json_builder_end_object(builder);       /* slot_status */
		}
		json_builder_end_object(builder);
		json_builder_end_object(builder);
	}

	json_builder_end_array(builder);

	json_builder_end_object(builder);

	gen = json_generator_new();
	root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	json_generator_set_pretty(gen, pretty);
	return json_generator_to_data(gen, NULL);
#else
	g_error("json support is disabled");
	return NULL;
#endif
}

static RaucSlotStatus* r_variant_get_slot_state(GVariant *vardict)
{
	RaucSlotStatus *slot_state = g_new0(RaucSlotStatus, 1);
	g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(vardict);

	g_variant_dict_lookup(&dict, "bundle.compatible", "s", &slot_state->bundle_compatible);
	g_variant_dict_lookup(&dict, "bundle.version", "s", &slot_state->bundle_version);
	g_variant_dict_lookup(&dict, "bundle.description", "s", &slot_state->bundle_description);
	g_variant_dict_lookup(&dict, "bundle.build", "s", &slot_state->bundle_build);
	g_variant_dict_lookup(&dict, "bundle.hash", "s", &slot_state->bundle_hash);
	g_variant_dict_lookup(&dict, "status", "s", &slot_state->status);
	if (g_variant_dict_lookup(&dict, "sha256", "s", &slot_state->checksum.digest))
		slot_state->checksum.type = G_CHECKSUM_SHA256;
	g_variant_dict_lookup(&dict, "size", "t", &slot_state->checksum.size);
	g_variant_dict_lookup(&dict, "installed.transaction", "s", &slot_state->installed_txn);
	g_variant_dict_lookup(&dict, "installed.timestamp", "s", &slot_state->installed_timestamp);
	g_variant_dict_lookup(&dict, "installed.count", "u", &slot_state->installed_count);
	g_variant_dict_lookup(&dict, "activated.timestamp", "s", &slot_state->activated_timestamp);
	g_variant_dict_lookup(&dict, "activated.count", "u", &slot_state->activated_count);

	return slot_state;
}

/*
 * Performs a D-Bus call to obtain information of all slots exposed.
 *
 * @param[out] Slots Returns a newly allocated GHashTable containing slot information
 *              [transfer full]
 * @param error Return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
static gboolean retrieve_slot_states_via_dbus(GHashTable **slots, GError **error)
{
	GBusType bus_type = (!g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session"))
	                    ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;
	GError *ierror = NULL;
	RInstaller *proxy = NULL;
	GVariant *slot_status_array, *vardict;
	GVariantIter *viter;
	GHashTableIter hiter;
	RaucSlot *iterslot;
	gchar *slot_name;

	g_return_val_if_fail(slots != NULL && *slots == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	*slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);

	proxy = r_installer_proxy_new_for_bus_sync(bus_type,
			G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
			"de.pengutronix.rauc", "/", NULL, &ierror);
	if (proxy == NULL) {
		if (g_dbus_error_is_remote_error(ierror))
			g_dbus_error_strip_remote_error(ierror);
		g_set_error(error,
				G_IO_ERROR,
				G_IO_ERROR_FAILED,
				"error creating proxy: %s", ierror->message);
		g_error_free(ierror);
		return FALSE;
	}

	g_debug("Trying to contact rauc service");
	if (!r_installer_call_get_slot_status_sync(proxy, &slot_status_array, NULL, &ierror)) {
		if (g_dbus_error_is_remote_error(ierror))
			g_dbus_error_strip_remote_error(ierror);
		g_set_error(error,
				G_IO_ERROR,
				G_IO_ERROR_FAILED,
				"error calling D-Bus method \"GetSlotStatus\": %s", ierror->message);
		g_error_free(ierror);
		g_object_unref(proxy);
		return FALSE;
	}

	g_variant_get(slot_status_array, "a(sa{sv})", &viter);
	while (g_variant_iter_loop(viter, "(s@a{sv})", &slot_name, &vardict)) {
		RaucSlot *slot = NULL;
		GVariantDict dict;
		g_autofree gchar *parent = NULL;
		g_autofree gchar *state = NULL;
		g_autofree gchar *boot_good = NULL;
		g_autofree gchar *sclass = NULL;

		/* if already existing, skip */
		if (g_hash_table_lookup(*slots, slot_name)) {
			g_warning("slot %s already exists", slot_name);
			continue;
		}

		/* Create slot struct and fill up with information */
		slot = g_new0(RaucSlot, 1);
		slot->name = g_intern_string(slot_name);
		g_variant_dict_init(&dict, vardict);
		g_variant_dict_lookup(&dict, "class", "s", &sclass);
		slot->sclass = g_intern_string(sclass);
		g_variant_dict_lookup(&dict, "device", "s", &slot->device);
		g_variant_dict_lookup(&dict, "type", "s", &slot->type);
		g_variant_dict_lookup(&dict, "bootname", "s", &slot->bootname);
		g_variant_dict_lookup(&dict, "state", "s", &state);
		slot->state = r_slot_str_to_slotstate(state);
		g_variant_dict_lookup(&dict, "description", "s", &slot->description);
		g_variant_dict_lookup(&dict, "parent", "s", &parent);
		if (parent) {
			/* we add a dummy slot with only a name for now that we
			 * can replace with a pointer to the real one
			 * afterwards */
			slot->parent = g_new0(RaucSlot, 1);
			slot->parent->name = g_intern_string(parent);
		}
		g_variant_dict_lookup(&dict, "mountpoint", "s", &slot->mount_point);
		g_variant_dict_lookup(&dict, "boot-status", "s", &boot_good);
		if (g_strcmp0(boot_good, "good") == 0) {
			slot->boot_good = TRUE;
		} else {
			slot->boot_good = FALSE;
		}

		if (status_detailed) {
			slot->status = r_variant_get_slot_state(vardict);
		}
		g_hash_table_insert(*slots, (gchar*)slot->name, slot);
		g_variant_dict_clear(&dict);
	}

	/* Now we replace the dummy parent slots with the pointer to the real
	 * parent slots */
	g_hash_table_iter_init(&hiter, *slots);
	while (g_hash_table_iter_next(&hiter, (gpointer*) &slot_name, (gpointer*) &iterslot)) {
		RaucSlot *parent_slot;
		if (iterslot->parent) {
			parent_slot = g_hash_table_lookup(*slots, iterslot->parent->name);
			g_assert_nonnull(parent_slot); /* A valid serialization should not run into this case! */
			g_clear_pointer(&iterslot->parent, r_slot_free);
			iterslot->parent = parent_slot;
		}
	}

	g_variant_iter_free(viter);
	g_variant_unref(slot_status_array);
	g_object_unref(proxy);

	return TRUE;
}

/*
 * Performs a D-Bus call to obtain general status information such as
 * Compatible, Variant, etc.
 *
 * @param[out] status_print Return a newly allocated RaucStatusPrint instance
 *              [transfer full]
 * @param error Return location for a GError
 *
 * @return TRUE if succeeded, FALSE if failed
 */
static gboolean retrieve_status_via_dbus(RaucStatusPrint **status_print, GError **error)
{
	GBusType bus_type = (!g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session"))
	                    ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;
	GError *ierror = NULL;
	RInstaller *proxy;
	g_autoptr(RaucStatusPrint) istatus = NULL;
	g_autofree gchar *primary = NULL;

	g_return_val_if_fail(status_print != NULL && *status_print == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	istatus = g_new0(RaucStatusPrint, 1);

	proxy = r_installer_proxy_new_for_bus_sync(bus_type,
			G_DBUS_PROXY_FLAGS_NONE,
			"de.pengutronix.rauc", "/", NULL, &ierror);
	if (proxy == NULL) {
		g_set_error(error,
				G_IO_ERROR,
				G_IO_ERROR_FAILED,
				"error creating proxy: %s", ierror->message);
		g_error_free(ierror);
		return FALSE;
	}

	if (!r_installer_call_get_primary_sync(proxy, &primary, NULL, &ierror)) {
		if (g_dbus_error_is_remote_error(ierror))
			g_dbus_error_strip_remote_error(ierror);
		g_warning("%s", ierror->message);
		g_clear_error(&ierror);
	}

	istatus->variant = r_installer_dup_variant(proxy);
	istatus->compatible = r_installer_dup_compatible(proxy);
	istatus->bootslot = r_installer_dup_boot_slot(proxy);

	/* Obtain configured slots and their state */
	if (!retrieve_slot_states_via_dbus(&istatus->slots, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Finally, we get the right primary slot reference from the list */
	if (primary)
		istatus->primary = g_hash_table_lookup(istatus->slots, primary);

	*status_print = g_steal_pointer(&istatus);

	return TRUE;
}

static gboolean print_status(RaucStatusPrint *status_print)
{
	g_autofree gchar *text = NULL;

	if (!output_format || g_strcmp0(output_format, "readable") == 0) {
		text = r_status_formatter_readable(status_print);
	} else if (g_strcmp0(output_format, "shell") == 0) {
		text = r_status_formatter_shell(status_print);
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json") == 0) {
		text = r_status_formatter_json(status_print, FALSE);
	} else if (ENABLE_JSON && g_strcmp0(output_format, "json-pretty") == 0) {
		text = r_status_formatter_json(status_print, TRUE);
	} else {
		g_printerr("Unknown output format: '%s'\n", output_format);
		return FALSE;
	}

	g_print("%s\n", text);

	return TRUE;
}

static gboolean status_start(int argc, char **argv)
{
	GBusType bus_type = (!g_strcmp0(g_getenv("DBUS_STARTER_BUS_TYPE"), "session"))
	                    ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;
	g_autofree gchar *slot_name = NULL;
	g_autofree gchar *message = NULL;
	const gchar *state = NULL;
	const gchar *slot_identifier = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(RaucStatusPrint) status_print = NULL;

	g_debug("status start");
	r_exit_status = 0;

	if (!ENABLE_SERVICE) {
		res = determine_slot_states(&ierror);
		if (!res) {
			g_printerr("Failed to determine slot states: %s\n", ierror->message);
			g_clear_error(&ierror);
			r_exit_status = 1;
			return TRUE;
		}

		res = determine_boot_states(&ierror);
		if (!res) {
			g_printerr("Failed to determine boot states: %s\n", ierror->message);
			g_clear_error(&ierror);
		}

		if (status_detailed) {
			GHashTableIter iter;
			RaucSlot *slot;

			g_hash_table_iter_init(&iter, r_context()->config->slots);
			while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot))
				r_slot_status_load(slot);
		}

		status_print = g_new0(RaucStatusPrint, 1);

		status_print->primary = r_boot_get_primary(&ierror);
		if (!status_print->primary) {
			g_printerr("Failed getting primary slot: %s\n", ierror->message);
			g_clear_error(&ierror);
		}

		status_print->compatible = r_context()->config->system_compatible;
		status_print->variant = r_context()->config->system_variant;
		status_print->bootslot = r_context()->bootslot;
		status_print->slots = r_context()->config->slots;
	} else {
		if (!retrieve_status_via_dbus(&status_print, &ierror)) {
			g_printerr("Error retrieving slot status via D-Bus: %s\n",
					ierror->message);
			g_error_free(ierror);
			r_exit_status = 1;
			return TRUE;
		}
	}

	if (argc < 3) {
		if (!print_status(status_print)) {
			r_exit_status = 1;
		}
		return TRUE;
	} else if (argc == 3) {
		slot_identifier = "booted";
	} else if (argc == 4) {
		slot_identifier = argv[3];
	} else { /* argc > 4 */
		g_printerr("Too many arguments\n");
		r_exit_status = 1;
		return TRUE;
	}

	if (g_strcmp0(argv[2], "mark-good") == 0) {
		state = "good";
	} else if (g_strcmp0(argv[2], "mark-bad") == 0) {
		state = "bad";
	} else if (g_strcmp0(argv[2], "mark-active") == 0) {
		state = "active";
	} else {
		g_printerr("unknown subcommand %s\n", argv[2]);
		r_exit_status = 1;
		return TRUE;
	}

	if (ENABLE_SERVICE) {
		g_autoptr(RInstaller) proxy = NULL;

		proxy = r_installer_proxy_new_for_bus_sync(bus_type,
				G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
				"de.pengutronix.rauc", "/", NULL, &ierror);
		if (proxy == NULL) {
			if (g_dbus_error_is_remote_error(ierror))
				g_dbus_error_strip_remote_error(ierror);
			g_printerr("rauc mark: error creating proxy: %s\n", ierror->message);
			g_error_free(ierror);
			r_exit_status = 1;
			return TRUE;
		}
		g_debug("Trying to contact rauc service");
		if (!r_installer_call_mark_sync(proxy, state, slot_identifier,
				&slot_name, &message, NULL, &ierror)) {
			if (g_dbus_error_is_remote_error(ierror))
				g_dbus_error_strip_remote_error(ierror);
			g_printerr("rauc mark: %s\n", ierror->message);
			g_error_free(ierror);
			r_exit_status = 1;
			return TRUE;
		}
	} else {
		r_exit_status = mark_run(state, slot_identifier, NULL, &message) ? 0 : 1;
		if (r_exit_status)
			g_printerr("rauc mark: %s\n", message);
		return TRUE;
	}

	if (message)
		g_print("rauc status: %s\n", message);

	return TRUE;
}

#define MESSAGE_ID_BOOTED "e60e0addd3454cb8b796eae0d497af96"
#define MESSAGE_ID_BOOTED_EXTERNAL "dd237efdad1945d9b1e471bc2b994532"

static void r_event_log_booted(const RaucSlot *booted_slot)
{
	g_autofree gchar *message = NULL;
	GLogField fields[] = {
		{"MESSAGE", NULL, -1 },
		{"MESSAGE_ID", MESSAGE_ID_BOOTED, -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "boot", -1},
		{"SLOT_NAME", NULL, -1},
		{"SLOT_BOOTNAME", NULL, -1},
		{"BOOT_ID", NULL, -1},
		{"BUNDLE_HASH", NULL, -1},
	};

	g_return_if_fail(booted_slot);

	message = g_strdup_printf("Booted into %s (%s)", booted_slot->name, booted_slot->bootname);
	fields[0].value = message;
	fields[4].value = booted_slot->name;
	fields[5].value = booted_slot->bootname;
	fields[6].value = r_context()->boot_id;
	if (booted_slot->status && booted_slot->status->bundle_hash) {
		fields[5].value = booted_slot->status->bundle_hash;
	} else {
		fields[5].value = "unknown";
	}
	g_log_structured_array(G_LOG_LEVEL_MESSAGE, fields, G_N_ELEMENTS(fields));
}

static void r_event_log_booted_external(void)
{
	g_autofree gchar *message = NULL;
	GLogField fields[] = {
		{"MESSAGE", NULL, -1 },
		{"MESSAGE_ID", MESSAGE_ID_BOOTED_EXTERNAL, -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "boot", -1},
		{"BOOT_ID", NULL, -1},
	};

	message = g_strdup_printf("Booted from external source");
	fields[0].value = message;
	fields[4].value = r_context()->boot_id;
	g_log_structured_array(G_LOG_LEVEL_MESSAGE, fields, G_N_ELEMENTS(fields));
}

G_GNUC_UNUSED
static void create_run_links(void)
{
	g_autoptr(GError) ierror = NULL;
	GHashTableIter iter;
	RaucSlot *slot;

	if (g_mkdir_with_parents("/run/rauc/slots/active", 0755) != 0) {
		g_warning("Failed to create /run/rauc/slots/active");
		return;
	}

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		g_autofree gchar* path = NULL;

		if (!(slot->state & ST_ACTIVE))
			continue;

		path = g_build_filename("/run/rauc/slots/active", slot->sclass, NULL);

		if (!r_update_symlink(slot->device, path, &ierror)) {
			g_warning("Failed to create symlink for active slot: %s", ierror->message);
		}
	}
}

G_GNUC_UNUSED
static gboolean service_start(int argc, char **argv)
{
	g_autoptr(GError) ierror = NULL;

	g_debug("service start");

	if (!determine_slot_states(&ierror)) {
		g_printerr("Failed to determine slot states: %s\n", ierror->message);
		r_exit_status = 1;
		return TRUE;
	}

	create_run_links();

	if (r_context()->system_status) {
		/* Boot ID-based system reboot vs service restart detection */
		if (g_strcmp0(r_context()->system_status->boot_id, r_context()->boot_id) == 0) {
			r_event_log_message(R_EVENT_LOG_TYPE_SERVICE, "Service restarted");
		} else {
			if (g_strcmp0(r_context()->bootslot, "_external_") == 0) {
				r_event_log_booted_external();
			} else {
				RaucSlot *booted_slot = r_slot_get_booted(r_context()->config->slots);

				r_slot_status_load(booted_slot);

				r_event_log_booted(booted_slot);
			}

			/* update boot ID */
			g_free(r_context()->system_status->boot_id);
			r_context()->system_status->boot_id = g_strdup(r_context()->boot_id);

			if (!r_system_status_save(&ierror)) {
				g_warning("Failed to save system status: %s", ierror->message);
				g_clear_error(&ierror);
			}
		}
	} else {
		r_event_log_message(R_EVENT_LOG_TYPE_SERVICE, "Service started");
	}

	r_exit_status = r_service_run() ? 0 : 1;

	return TRUE;
}

static gboolean mount_start(int argc, char **argv)
{
	g_autofree gchar *bundlelocation = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	GError *error = NULL;
	gboolean res = FALSE;

	if (argc < 3) {
		g_printerr("A bundle path or URL must be provided\n");
		goto out;
	}

	if (argc > 3) {
		g_printerr("Excess argument: %s\n", argv[3]);
		goto out;
	}

	bundlelocation = resolve_bundle_path(argv[2]);
	if (bundlelocation == NULL)
		goto out; /* an error message was already printed by resolve_bundle_path */
	g_debug("input bundle: %s", bundlelocation);

	res = check_bundle(bundlelocation, &bundle, CHECK_BUNDLE_DEFAULT, NULL, &error);
	if (!res) {
		g_printerr("%s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	g_debug("bundle payload size: %"G_GOFFSET_FORMAT, bundle->size);

	res = mount_bundle(bundle, &error);
	if (!res) {
		g_printerr("%s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	g_print("Mounted bundle at %s. Use 'umount %s' to unmount.\n", bundle->mount_point, bundle->mount_point);

	/* The device mapper target and loopback devices are configured to remove
	 * themselves on close. They are kept active by the mounted filesystem and
	 * are automatically cleaned up when the user performs a normal unmount.
	 * To avoid running the g_autoptr cleanup for the bundle, we use exit(0)
	 * here.
	 **/
	exit(0);

out:
	r_exit_status = 1;
	return FALSE;
}

static gboolean unknown_start(int argc, char **argv)
{
	g_debug("unknown start");

	return TRUE;
}

typedef enum  {
	UNKNOWN = 0,
	INSTALL,
	BUNDLE,
	RESIGN,
	REPLACE_SIG,
	EXTRACT_SIG,
	EXTRACT,
	CONVERT,
	ENCRYPT,
	STATUS,
	INFO,
	WRITE_SLOT,
	SERVICE,
	MOUNT,
} RaucCommandType;

typedef struct {
	const RaucCommandType type;
	const gchar* name;
	const gchar* usage;
	const gchar* summary;
	gboolean (*cmd_handler)(int argc, char **argv);
	GOptionGroup* options;
	RContextConfigMode configmode;
	gboolean while_busy;
} RaucCommand;

static GOptionEntry entries_install[] = {
	{"ignore-compatible", '\0', 0, G_OPTION_ARG_NONE, &install_ignore_compatible, "disable compatible check", NULL},
	{"transaction-id", '\0', 0, G_OPTION_ARG_STRING, &installation_txn, "custom transaction id", "UUID"},
#if ENABLE_SERVICE == 1
	{"progress", '\0', 0, G_OPTION_ARG_NONE, &install_progressbar, "show progress bar", NULL},
#else
	{"handler-args", '\0', 0, G_OPTION_ARG_STRING, &handler_args, "extra arguments for full custom handler", "ARGS"},
	{"override-boot-slot", '\0', 0, G_OPTION_ARG_STRING, &bootslot, "override auto-detection of booted slot", "BOOTNAME"},
#endif
	{0}
};

static GOptionEntry entries_bundle[] = {
	{"signing-keyring", '\0', 0, G_OPTION_ARG_FILENAME, &signing_keyring, "verification keyring file", "PEMFILE"},
	{"mksquashfs-args", '\0', 0, G_OPTION_ARG_STRING, &mksquashfs_args, "mksquashfs extra args", "ARGS"},
	{0}
};

static GOptionEntry entries_resign[] = {
	{"no-verify", '\0', 0, G_OPTION_ARG_NONE, &verification_disabled, "disable bundle verification", NULL},
	{"no-check-time", '\0', 0, G_OPTION_ARG_NONE, &no_check_time, "don't check validity period of certificates against current time", NULL},
	{"signing-keyring", '\0', 0, G_OPTION_ARG_FILENAME, &signing_keyring, "verification keyring file", "PEMFILE"},
	{0}
};

static GOptionEntry entries_replace[] = {
	{"trust-environment", '\0', 0, G_OPTION_ARG_NONE, &trust_environment, "trust environment and skip bundle access checks", NULL},
	{"no-verify", '\0', 0, G_OPTION_ARG_NONE, &verification_disabled, "disable bundle verification", NULL},
	{"signing-keyring", '\0', 0, G_OPTION_ARG_FILENAME, &signing_keyring, "verification keyring file", "PEMFILE"},
	{0}
};

static GOptionEntry entries_convert[] = {
	{"trust-environment", '\0', 0, G_OPTION_ARG_NONE, &trust_environment, "trust environment and skip bundle access checks", NULL},
	{"no-verify", '\0', 0, G_OPTION_ARG_NONE, &verification_disabled, "disable bundle verification", NULL},
	{"signing-keyring", '\0', 0, G_OPTION_ARG_FILENAME, &signing_keyring, "verification keyring file", "PEMFILE"},
	{"mksquashfs-args", '\0', 0, G_OPTION_ARG_STRING, &mksquashfs_args, "mksquashfs extra args", "ARGS"},
	{"casync-args", '\0', 0, G_OPTION_ARG_STRING, &casync_args, "casync extra args", "ARGS"},
	{"ignore-image", '\0', 0, G_OPTION_ARG_STRING_ARRAY, &convert_ignore_images, "ignore image during conversion", "SLOTCLASS"},
	{0}
};

static GOptionEntry entries_extract_signature[] = {
	{"key", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME, &keypath, "decryption key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"trust-environment", '\0', 0, G_OPTION_ARG_NONE, &trust_environment, "trust environment and skip bundle access checks", NULL},
	{0}
};

static GOptionEntry entries_extract[] = {
	{"key", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME, &keypath, "decryption key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"trust-environment", '\0', 0, G_OPTION_ARG_NONE, &trust_environment, "trust environment and skip bundle access checks", NULL},
	{0}
};

static GOptionEntry entries_info[] = {
	{"no-verify", '\0', 0, G_OPTION_ARG_NONE, &verification_disabled, "disable bundle verification", NULL},
	{"no-check-time", '\0', 0, G_OPTION_ARG_NONE, &no_check_time, "don't check validity period of certificates against current time", NULL},
	{"key", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME, &keypath, "decryption key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"output-format", '\0', 0, G_OPTION_ARG_STRING, &output_format, "output format (readable, shell, json, json-pretty, json-2)", "FORMAT"},
	{"dump-cert", '\0', 0, G_OPTION_ARG_NONE, &info_dumpcert, "dump certificate", NULL},
	{"dump-recipients", '\0', 0, G_OPTION_ARG_NONE, &info_dumprecipients, "dump recipients", NULL},
	{0}
};

static GOptionEntry entries_status[] = {
	{"detailed", '\0', 0, G_OPTION_ARG_NONE, &status_detailed, "show more status details", NULL},
	{"output-format", '\0', 0, G_OPTION_ARG_STRING, &output_format, "output format (readable, shell, json, json-pretty)", "FORMAT"},
#if ENABLE_SERVICE == 0
	{"override-boot-slot", '\0', 0, G_OPTION_ARG_STRING, &bootslot, "override auto-detection of booted slot", "BOOTNAME"},
#endif
	{0}
};

static GOptionEntry entries_service[] = {
	{"handler-args", '\0', 0, G_OPTION_ARG_STRING, &handler_args, "extra arguments for full custom handler", "ARGS"},
	{"override-boot-slot", '\0', 0, G_OPTION_ARG_STRING, &bootslot, "override auto-detection of booted slot", "BOOTNAME"},
	{0}
};

static GOptionEntry entries_signing[] = {
	{"cert", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME, &certpath, "signing cert file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"key", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME, &keypath, "signing key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"intermediate", '\0', G_OPTION_FLAG_NOALIAS, G_OPTION_ARG_FILENAME_ARRAY, &intermediate, "intermediate CA file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{0}
};

static GOptionEntry entries_bundle_access[] = {
	{"tls-cert", '\0', 0, G_OPTION_ARG_STRING, &access_args.tls_cert, "TLS client certificate file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"tls-key", '\0', 0, G_OPTION_ARG_STRING, &access_args.tls_key, "TLS client key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
	{"tls-ca", '\0', 0, G_OPTION_ARG_FILENAME, &access_args.tls_ca, "TLS CA file", "PEMFILE"},
	{"tls-no-verify", '\0', 0, G_OPTION_ARG_NONE, &access_args.tls_no_verify, "do not verify TLS server certificate", NULL},
	{"http-header", 'H', 0, G_OPTION_ARG_STRING_ARRAY, &access_args.http_headers, "HTTP request header (multiple uses supported)", "'HEADER: VALUE'"},
	{0}
};

static GOptionEntry entries_encryption[] = {
	{"to", '\0', 0, G_OPTION_ARG_FILENAME_ARRAY, &recipients, "recipient cert(s)", "PEMFILE"},
	{0}
};

static GOptionGroup *install_group;
static GOptionGroup *bundle_group;
static GOptionGroup *resign_group;
static GOptionGroup *replace_group;
static GOptionGroup *convert_group;
static GOptionGroup *encrypt_group;
static GOptionGroup *extract_signature_group;
static GOptionGroup *extract_group;
static GOptionGroup *info_group;
static GOptionGroup *status_group;
static GOptionGroup *service_group;

static void create_option_groups(void)
{
	install_group = g_option_group_new("install", "Install options:", "help dummy", NULL, NULL);
	g_option_group_add_entries(install_group, entries_install);
	if (ENABLE_STREAMING)
		g_option_group_add_entries(install_group, entries_bundle_access);

	if (ENABLE_CREATE) {
		bundle_group = g_option_group_new("bundle", "Bundle options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(bundle_group, entries_bundle);
		g_option_group_add_entries(bundle_group, entries_signing);

		resign_group = g_option_group_new("resign", "Resign options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(resign_group, entries_resign);
		g_option_group_add_entries(resign_group, entries_signing);

		replace_group = g_option_group_new("replace-signature", "Replace signature options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(replace_group, entries_replace);

		convert_group = g_option_group_new("convert", "Convert options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(convert_group, entries_convert);
		g_option_group_add_entries(convert_group, entries_signing);

		encrypt_group = g_option_group_new("encrypt", "Encryption options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(encrypt_group, entries_encryption);

		extract_signature_group = g_option_group_new("extract", "Extract signature options:", "help dummy", NULL, NULL);
		g_option_group_add_entries(extract_signature_group, entries_extract_signature);
	}

	extract_group = g_option_group_new("extract", "Extract options:", "help dummy", NULL, NULL);
	g_option_group_add_entries(extract_group, entries_extract);

	info_group = g_option_group_new("info", "Info options:", "help dummy", NULL, NULL);
	g_option_group_add_entries(info_group, entries_info);
	if (ENABLE_STREAMING)
		g_option_group_add_entries(info_group, entries_bundle_access);

	status_group = g_option_group_new("status", "Status options:", "help dummy", NULL, NULL);
	g_option_group_add_entries(status_group, entries_status);

	service_group = g_option_group_new("service", "Service options:", "help dummy", NULL, NULL);
	g_option_group_add_entries(service_group, entries_service);
}

static void cmdline_handler(int argc, char **argv)
{
	gboolean help = FALSE, debug = FALSE, version = FALSE;
	g_autofree gchar *confpath = NULL, *keyring = NULL, *mount = NULL;
	char *cmdarg = NULL;
	g_autoptr(GOptionContext) context = NULL;
	GOptionEntry entries[] = {
		{"conf", 'c', 0, G_OPTION_ARG_FILENAME, &confpath, "config file", "FILENAME"},
		/* NOTE: cert and key kept for backwards-compatibility, but made invisible */
		{"cert", '\0', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &certpath, "cert file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
		{"key", '\0', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &keypath, "key file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
		{"keyring", '\0', 0, G_OPTION_ARG_FILENAME, &keyring, "keyring file", "PEMFILE"},
		{"intermediate", '\0', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME_ARRAY, &intermediate, "intermediate CA file or PKCS#11 URL", "PEMFILE|PKCS11-URL"},
		{"mount", '\0', 0, G_OPTION_ARG_FILENAME, &mount, "mount prefix", "PATH"},
		{"debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "enable debug output", NULL},
		{"version", '\0', 0, G_OPTION_ARG_NONE, &version, "display version", NULL},
		{"help", 'h', 0, G_OPTION_ARG_NONE, &help, "display help and exit", NULL},
		{0}
	};

	GError *error = NULL;
	g_autofree gchar *text = NULL;

	RaucCommand rcommands[] = {
		{UNKNOWN, "help", "<COMMAND>",
		 "Print help",
		 unknown_start, NULL, R_CONTEXT_CONFIG_MODE_NONE, TRUE},
		{INSTALL, "install", "install <BUNDLE>",
		 "Install a bundle",
		 install_start, install_group, R_CONTEXT_CONFIG_MODE_REQUIRED, FALSE},
#if ENABLE_CREATE == 1
		{BUNDLE, "bundle", "bundle <INPUTDIR> <BUNDLENAME>",
		 "Create a bundle from a content directory",
		 bundle_start, bundle_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
		{RESIGN, "resign", "resign <INBUNDLE> <OUTBUNDLE>",
		 "Resign an already signed bundle",
		 resign_start, resign_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
		{CONVERT, "convert", "convert <INBUNDLE> <OUTBUNDLE>",
		 "Convert to casync index bundle and store",
		 convert_start, convert_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
		{ENCRYPT, "encrypt", "encrypt <INBUNDLE> <OUTBUNDLE>", "Encrypt a crypt bundle",
		 encrypt_start, encrypt_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
		{REPLACE_SIG, "replace-signature", "replace-signature <INBUMDLE> <INPUTSIG> <OUTBUNDLE>",
		 "Replaces the signature of an already signed bundle",
		 replace_signature_start, replace_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
		{EXTRACT_SIG, "extract-signature", "extract-signature <BUNDLENAME> <OUTPUTSIG>",
		 "Extract the bundle signature",
		 extract_signature_start, extract_signature_group, R_CONTEXT_CONFIG_MODE_NONE, FALSE},
#endif
		{EXTRACT, "extract", "extract <BUNDLENAME> <OUTPUTDIR>",
		 "Extract the bundle content",
		 extract_start, extract_group, R_CONTEXT_CONFIG_MODE_AUTO, FALSE},
		{INFO, "info", "info <BUNDLE>",
		 "Print bundle info",
		 info_start, info_group, R_CONTEXT_CONFIG_MODE_AUTO, FALSE},
		{STATUS, "status", "status",
		 "Show system status\n\n"
		 "List of status commands (default slot is the currently booted slot):\n"
		 "  mark-good [booted | other | <SLOT_NAME>] \tMark the slot as good\n"
		 "  mark-bad [booted | other | <SLOT_NAME>] \tMark the slot as bad\n"
		 "  mark-active [booted | other | <SLOT_NAME>] \tMark the slot as active",
		 status_start, status_group, R_CONTEXT_CONFIG_MODE_REQUIRED, TRUE},
		{WRITE_SLOT, "write-slot", "write-slot <SLOTNAME> <IMAGE>",
		 "Write image to slot and bypass all update logic",
		 write_slot_start, NULL, R_CONTEXT_CONFIG_MODE_REQUIRED, FALSE},
#if ENABLE_SERVICE == 1
		{SERVICE, "service", "service",
		 "Start RAUC service",
		 service_start, service_group, R_CONTEXT_CONFIG_MODE_REQUIRED, TRUE},
#endif
		{MOUNT, "mount", "mount <BUNDLENAME>",
		 "Mount a bundle (for development purposes)",
		 mount_start, NULL, R_CONTEXT_CONFIG_MODE_REQUIRED, TRUE},
		{0}
	};
	RaucCommand *rc;
	RaucCommand *rcommand = NULL;

	context = g_option_context_new("<COMMAND>");
	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_set_ignore_unknown_options(context, TRUE);
	g_option_context_add_main_entries(context, entries, NULL);
	g_option_context_set_description(context,
			"Command-specific help:\n"
			"  rauc <COMMAND> --help\n"
			"\n"
			"List of rauc bundle handling commands:\n"
#if ENABLE_CREATE == 1
			"  bundle\t\tCreate a bundle\n"
			"  resign\t\tResign an already signed bundle\n"
			"  convert\t\tConvert classic to casync bundle\n"
			"  encrypt\t\tEncrypt a crypt bundle\n"
			"  replace-signature\tReplaces the signature of an already signed bundle\n"
			"  extract-signature\tExtract the bundle signature\n"
#endif
			"  extract\t\tExtract the bundle content\n"
			"  info\t\t\tShow bundle information\n"
			"\n"
			"List of rauc target commands:\n"
#if ENABLE_SERVICE == 1
			"  service\t\tStart RAUC service\n"
#endif
			"  install\t\tInstall a bundle\n"
			"  status\t\tShow status\n"
			"  mount\t\t\tMount a bundle\n"
			"  write-slot\t\tWrite image to slot and bypass all update logic\n"
			"\n"
			"Environment variables:\n"
			"  RAUC_KEY_PASSPHRASE Passphrase to use for accessing key files (signing only)\n"
			"  RAUC_PKCS11_MODULE  Library filename for PKCS#11 module (signing only)\n"
			"  RAUC_PKCS11_PIN     PIN to use for accessing PKCS#11 keys (signing only)");

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_printerr("%s\n", error->message);
		g_error_free(error);
		r_exit_status = 1;
		return;
	}

	if (debug) {
		const gchar *domains = g_getenv("G_MESSAGES_DEBUG");
		if (!domains) {
			g_assert(g_setenv("G_MESSAGES_DEBUG", G_LOG_DOMAIN, TRUE));
		} else if (!g_str_equal(domains, "all")) {
			gchar *newdomains = g_strdup_printf("%s %s", domains, G_LOG_DOMAIN);
			g_setenv("G_MESSAGES_DEBUG", newdomains, TRUE);
			g_free(newdomains);
		}
		domains = g_getenv("G_MESSAGES_DEBUG");
		g_message("Debug log domains: '%s'", domains);
		g_debug(PACKAGE_VERSION
				" create=" G_STRINGIFY(ENABLE_CREATE)
				" emmc-boot=" G_STRINGIFY(ENABLE_EMMC_BOOT_SUPPORT)
				" gpt=" G_STRINGIFY(ENABLE_GPT)
				" json=" G_STRINGIFY(ENABLE_JSON)
				" network=" G_STRINGIFY(ENABLE_NETWORK)
				" service=" G_STRINGIFY(ENABLE_SERVICE)
				" streaming=" G_STRINGIFY(ENABLE_STREAMING)
				);
	}

	/* get first parameter without dashes */
	for (gint i = 1; i <= argc; i++) {
		if (argv[i] && !g_str_has_prefix(argv[i], "-")) {
			cmdarg = argv[i];
			break;
		}
	}

	if (cmdarg == NULL) {
		if (version) {
			g_print(PACKAGE_STRING "\n");
			return;
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
		g_print("Invalid command '%s' given\n", cmdarg);
		r_exit_status = 1;
		goto print_help;
	}

	/* re-setup option context for showing command-specific help */
	g_clear_pointer(&context, g_option_context_free);
	context = g_option_context_new(rcommand->usage);
	if (rcommand->summary)
		g_option_context_set_summary(context, rcommand->summary);
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
		r_context_conf()->configmode = rcommand->configmode;
		if (ENABLE_SERVICE) {
			/* these commands are handled by the service and need no client config */
			if (rcommand->type == INSTALL ||
			    rcommand->type == STATUS)
				r_context_conf()->configmode = R_CONTEXT_CONFIG_MODE_NONE;
		}
		if (confpath)
			r_context_conf()->configpath = confpath;
		if (certpath)
			r_context_conf()->certpath = certpath;
		if (keypath) {
			/* 'key' means encryption key for 'info', 'extract' or 'extract-signature',
			 * signing key otherwise */
			if (rcommand->type == INFO || rcommand->type == EXTRACT || rcommand->type == EXTRACT_SIG)
				r_context_conf()->encryption_key = keypath;
			else
				r_context_conf()->keypath = keypath;
		}
		if (keyring)
			r_context_conf()->keyringpath = keyring;
		if (signing_keyring)
			r_context_conf()->signing_keyringpath = signing_keyring;
		if (mksquashfs_args)
			r_context_conf()->mksquashfs_args = mksquashfs_args;
		if (casync_args)
			r_context_conf()->casync_args = casync_args;
		if (recipients)
			r_context_conf()->recipients = recipients;
		if (intermediate)
			r_context_conf()->intermediatepaths = intermediate;
		if (mount)
			r_context_conf()->mountprefix = mount;
		if (bootslot)
			r_context_conf()->bootslot = bootslot;
		if (handler_args)
			r_context_conf()->handlerextra = handler_args;
	} else {
		if (confpath != NULL ||
		    certpath != NULL ||
		    keypath != NULL) {
			g_printerr("rauc busy, cannot reconfigure\n");
			r_exit_status = 1;
			return;
		}
	}

	if (r_context_get_busy() && !rcommand->while_busy) {
		g_printerr("rauc busy: cannot run %s\n", rcommand->name);
		r_exit_status = 1;
		return;
	}

	if (!r_context_configure(&error)) {
		g_printerr("Failed to initialize context: %s\n", error->message);
		g_clear_error(&error);
		r_exit_status = 1;
		return;
	}

	/* real commands are handled here */
	if (rcommand->cmd_handler) {
		rcommand->cmd_handler(argc, argv);
	}
	return;

print_help:
	text = g_option_context_get_help(context, FALSE, NULL);
	g_print("%s", text);
}

int main(int argc, char **argv)
{
	GLogLevelFlags fatal_mask;

#if GLIB_CHECK_VERSION(2, 68, 0)
	/* To use this function, without bumping the maximum GLib allowed version,
	 * we temporarily disable the deprecation warnings */
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_log_writer_default_set_use_stderr(TRUE);
	G_GNUC_END_IGNORE_DEPRECATIONS
#endif

	fatal_mask = g_log_set_always_fatal(G_LOG_FATAL_MASK);
	fatal_mask |= G_LOG_LEVEL_CRITICAL;
	g_log_set_always_fatal(fatal_mask);

	/* set up structured logging */
	g_log_set_writer_func(r_event_log_writer, NULL, NULL);

	/* disable remote VFS */
	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	/* Locale needs to support UTF-8, try and flag if unsupported */
	setlocale(LC_ALL, "");
	if (g_get_charset(NULL))
		utf8_supported = TRUE;

	if (ENABLE_STREAMING && g_getenv("RAUC_NBD_SERVER")) {
		GError *ierror = NULL;
		pthread_setname_np(pthread_self(), "rauc-nbd");
		if (r_nbd_run_server(RAUC_SOCKET_FD, &ierror)) {
			return 0;
		} else {
			if (ierror) {
				g_message("nbd server failed with: %s", ierror->message);
			} else {
				g_message("nbd server failed");
			}
			return 1;
		}
	}

	create_option_groups();
	cmdline_handler(argc, argv);

	return r_exit_status;
}
