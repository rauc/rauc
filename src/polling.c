#include <glib.h>
#include <stdio.h>

#include "polling.h"
#include "bundle.h"
#include "config_file.h"
#include "context.h"
#include "install.h"
#include "manifest.h"
#include "service.h"
#include "utils.h"

G_DEFINE_QUARK(r-polling-error-quark, r_polling_error)

RPoller *r_poller = NULL;

typedef struct {
	gint64 next_poll_time; /* CLOCK_BOOTTIME */
	gboolean installation_running;

	guint64 attempt_count;
	guint64 recent_error_count; /* since last success */
	gint64 last_attempt_time; /* CLOCK_BOOTTIME */
	gint64 last_success_time; /* CLOCK_BOOTTIME */
	gchar *last_error_message;
	gboolean update_available;
	gchar *summary;
	gchar *attempted_hash; /* manifest hash of the attempted update */

	/* from the last successful attempt */
	RaucManifest *manifest;
	guint64 bundle_size;
	gchar *bundle_effective_url;
	guint64 bundle_modified_time;
	gchar *bundle_etag;

	/* from the last installation */
	gboolean must_reboot;
} RPollingContext;

typedef enum {
	POLLING_DELAY_NORMAL = 0,
	POLLING_DELAY_SHORT,
	POLLING_DELAY_INITIAL,
} RPollingDelay;

static void polling_context_clear_manifest(RPollingContext *polling_context)
{
	g_return_if_fail(polling_context);

	g_clear_pointer(&polling_context->manifest, free_manifest);
	g_clear_pointer(&polling_context->bundle_effective_url, g_free);
	g_clear_pointer(&polling_context->bundle_etag, g_free);
}

static void polling_reschedule(RPollingContext *polling_context, RPollingDelay delay)
{
	g_return_if_fail(polling_context);

	gint64 delay_ms = 0;
	g_autofree gchar *delay_type = NULL;

	switch (delay) {
		case POLLING_DELAY_NORMAL:
			if (!polling_context->recent_error_count) {
				delay_type = g_strdup_printf("normal delay");
			} else {
				delay_type = g_strdup_printf("backoff due to %"G_GUINT64_FORMAT " recent error(s)",
						polling_context->recent_error_count);
			}
			delay_ms = r_context()->config->polling_interval_ms * (polling_context->recent_error_count+1);
			delay_ms = MIN(delay_ms, r_context()->config->polling_max_interval_ms);
			break;
		case POLLING_DELAY_SHORT:
			delay_type = g_strdup("short delay");
			delay_ms = 30 * 1000;
			break;
		case POLLING_DELAY_INITIAL:
			delay_type = g_strdup("initial delay");
			delay_ms = r_context()->config->polling_interval_ms * g_random_double_range(0.1, 0.9);
			break;
		default:
			g_assert_not_reached();
	}

	if (r_context()->mock.polling_speedup)
		delay_ms = delay_ms / r_context()->mock.polling_speedup;

	gint64 next = r_get_boottime() + delay_ms * 1000;
	polling_context->next_poll_time = next;
	r_poller_set_next_poll(r_poller, next);

	g_autofree gchar *duration_str = r_format_duration(delay_ms / 1000);
	g_message("scheduled next poll in no less than %s (%s)", duration_str, delay_type);
}

static gboolean polling_fetch(RPollingContext *polling_context, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(polling_context, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* fetch manifest */
	g_auto(RaucBundleAccessArgs) access_args = {0};
	access_args.http_info_headers = assemble_info_headers(NULL);
	if (polling_context->bundle_etag) {
		g_ptr_array_add(access_args.http_info_headers, g_strdup_printf("If-None-Match: %s", polling_context->bundle_etag));
	}

	g_autoptr(RaucBundle) bundle = NULL;
	if (!check_bundle(r_context()->config->polling_url, &bundle, CHECK_BUNDLE_DEFAULT, &access_args, &ierror)) {
		if (g_error_matches(ierror, R_NBD_ERROR, R_NBD_ERROR_NO_CONTENT)) {
			g_clear_error(&ierror);
			g_message("polling: no bundle available");
			polling_context_clear_manifest(polling_context);
			return TRUE;
		} else if (g_error_matches(ierror, R_NBD_ERROR, R_NBD_ERROR_NOT_MODIFIED)) {
			g_clear_error(&ierror);
			g_message("polling: bundle not modified");
			return TRUE;
		} else {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	if (!bundle->manifest) {
		/* As we can only stream verity bundles, we should always have a manifest. */
		g_message("polling failed: no manifest found");
		g_set_error_literal(
				error,
				R_POLLING_ERROR, R_POLLING_ERROR_INVALID_BUNDLE,
				"polled bundle has no manifest");
		return FALSE;
	}

	g_clear_pointer(&polling_context->manifest, free_manifest);
	polling_context->manifest = g_steal_pointer(&bundle->manifest);

	g_assert(bundle->nbd_srv);
	polling_context->bundle_size = bundle->nbd_srv->data_size;
	polling_context->bundle_modified_time = bundle->nbd_srv->modified_time;
	r_replace_strdup(&polling_context->bundle_effective_url, bundle->nbd_srv->effective_url);
	r_replace_strdup(&polling_context->bundle_etag, bundle->nbd_srv->etag);

	return TRUE;
}

static gboolean polling_check_candidate_criteria(RPollingContext *polling_context, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(polling_context, FALSE);
	g_return_val_if_fail(polling_context->manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->polling_candidate_criteria;
	g_assert(criteria);
	const gchar *system_ver = r_context()->system_version;
	g_assert(system_ver);
	const gchar *update_ver = polling_context->manifest->update_version;
	g_assert(update_ver);

	if (g_strv_contains(criteria, "higher-semver")) {
		if (!r_semver_less_equal(update_ver, system_ver, &ierror)) {
			if (ierror) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
			r_replace_strdup(&polling_context->summary, "update candidate found: higher semantic version");
			return TRUE;
		}
	}

	if (g_strv_contains(criteria, "different-version")) {
		if (g_strcmp0(r_context()->system_version, polling_context->manifest->update_version) != 0) {
			r_replace_strdup(&polling_context->summary, "update candidate found: different version");
			return TRUE;
		}
	}

	r_replace_strdup(&polling_context->summary, "no update candidate available");
	return FALSE;
}

static gboolean polling_check_install_criteria(RPollingContext *polling_context, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(polling_context, FALSE);
	g_return_val_if_fail(polling_context->manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->polling_install_criteria;
	if (!criteria) {
		g_debug("polling: no installation criteria");
		return FALSE;
	}

	const gchar *system_ver = r_context()->system_version;
	g_assert(system_ver);
	const gchar *update_ver = polling_context->manifest->update_version;
	g_assert(update_ver);

	if (g_strv_contains(criteria, "higher-semver")) {
		if (!r_semver_less_equal(update_ver, system_ver, &ierror)) {
			if (ierror) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
			g_message("polling: automatic installation: higher semantic version");
			return TRUE;
		}
	}

	if (g_strv_contains(criteria, "different-version")) {
		if (g_strcmp0(r_context()->system_version, polling_context->manifest->update_version) != 0) {
			g_message("polling: automatic installation: different version");
			return TRUE;
		}
	}

	if (g_strv_contains(criteria, "always")) {
		g_message("polling: automatic installation");
		return TRUE;
	}

	return FALSE;
}

static gboolean polling_check_reboot_criteria(const RaucInstallArgs *install_args)
{
	g_return_val_if_fail(install_args, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->polling_reboot_criteria;
	if (!criteria)
		return FALSE;

	if (g_strv_contains(criteria, "failed-update")) {
		if (install_args->status_result != 0) {
			g_message("polling: installation failed, triggering reboot");
			return TRUE;
		}
	} else {
		if (install_args->status_result != 0) {
			g_message("polling: installation failed, suppressing reboot");
			return FALSE;
		}
	}

	if (g_strv_contains(criteria, "updated-slots")) {
		if (install_args->updated_slots)
			return TRUE;
	}

	if (g_strv_contains(criteria, "updated-artifacts")) {
		if (install_args->updated_artifacts)
			return TRUE;
	}

	return FALSE;
}

static gboolean polling_install_cleanup(gpointer data)
{
	g_return_val_if_fail(data, G_SOURCE_REMOVE);

	RaucInstallArgs *args = data;
	RPollingContext *polling_context = args->data;

	g_return_val_if_fail(polling_context, G_SOURCE_REMOVE);

	polling_context->installation_running = FALSE;

	g_mutex_lock(&args->status_mutex);
	if (args->status_result == 0) {
		g_message("polling: installation of `%s` succeeded", args->name);
	} else {
		g_message("polling: installation of `%s` failed: %d", args->name, args->status_result);
	}
	/* TODO expose error via d-bus? */
	r_installer_emit_completed(r_installer, args->status_result);
	r_installer_set_operation(r_installer, "idle");
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
	if (polling_check_reboot_criteria(args)) {
		polling_context->must_reboot = TRUE;
	}
	g_mutex_unlock(&args->status_mutex);

	install_args_free(args);

	polling_reschedule(polling_context, POLLING_DELAY_SHORT);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_poller));

	return G_SOURCE_REMOVE;
}

/* This starts an installation in the background. On completion, the
 * polling_install_cleanup callback is run.
 **/
static void polling_trigger_install(RPollingContext *polling_context, GError **error)
{
	RaucInstallArgs *args = install_args_new();

	g_return_if_fail(polling_context);
	g_return_if_fail(polling_context->manifest);
	g_return_if_fail(polling_context->manifest->hash);
	g_return_if_fail(error == NULL || *error == NULL);

	args->name = g_strdup(r_context()->config->polling_url);
	args->cleanup = polling_install_cleanup;
	args->data = polling_context;
	/* lock bundle via manifest hash */
	args->require_manifest_hash = g_strdup(polling_context->manifest->hash);

	r_installer_set_operation(r_installer, "installing");
	install_run(args);
	args = NULL; /* now owned by installer thread */
	polling_context->installation_running = TRUE;
}

static gboolean polling_reboot(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *cmd = r_context()->config->polling_reboot_cmd;
	g_assert(cmd);

	g_auto(GStrv) argvp = NULL;
	if (!g_shell_parse_argv(cmd, NULL, &argvp, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);
	r_ptr_array_addv(args, argvp, TRUE);
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run reboot command ('%s'): ",
				cmd
				);
		return FALSE;
	}

	return TRUE;
}

static gboolean polling_step(RPollingContext *polling_context, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(polling_context, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_clear_pointer(&polling_context->summary, g_free);
	polling_context->update_available = FALSE;

	if (!polling_fetch(polling_context, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	} else if (!polling_context->manifest) {
		/* no error, but no manifest (e.g. HTTP 204) */
		r_replace_strdup(&polling_context->summary, "no update bundle available");
		return TRUE;
	}

	gboolean candidate = polling_check_candidate_criteria(polling_context, &ierror);
	if (ierror) {
		g_propagate_prefixed_error(error, ierror, "candidate criteria check failed: ");
		return FALSE;
	} else if (!candidate) {
		g_message("polling: bundle is not a candidate");
		return TRUE;
	}
	polling_context->update_available = TRUE;

	gboolean install = polling_check_install_criteria(polling_context, &ierror);
	if (ierror) {
		g_propagate_prefixed_error(error, ierror, "installation criteria check failed: ");
		return FALSE;
	} else if (!install) {
		g_message("polling: candidate needs to be explicitly confirmed");
		return TRUE;
	}

	/* skip attempt if manifest hash is the same */
	if (g_strcmp0(polling_context->manifest->hash, polling_context->attempted_hash) == 0) {
		g_message("polling: manifest is unchanged, skipping installation");
		return TRUE;
	}

	g_message("polling: starting installation of version '%s'", polling_context->manifest->update_version);
	r_replace_strdup(&polling_context->attempted_hash, polling_context->manifest->hash);
	polling_trigger_install(polling_context, &ierror);

	return TRUE;
}

static void polling_update_status(RPollingContext *polling_context)
{
	g_return_if_fail(polling_context);

	g_auto(GVariantBuilder) builder = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(&builder, "{sv}", "attempt-count", g_variant_new_uint64(polling_context->attempt_count));
	g_variant_builder_add(&builder, "{sv}", "recent-error-count", g_variant_new_uint64(polling_context->recent_error_count));

	g_variant_builder_add(&builder, "{sv}", "last-attempt-time", g_variant_new_uint64(polling_context->last_attempt_time));
	g_variant_builder_add(&builder, "{sv}", "last-success-time", g_variant_new_uint64(polling_context->last_success_time));
	if (polling_context->last_error_message)
		g_variant_builder_add(&builder, "{sv}", "last-error-message", g_variant_new_string(polling_context->last_error_message));
	g_variant_builder_add(&builder, "{sv}", "update-available", g_variant_new_boolean(polling_context->update_available));
	if (polling_context->summary)
		g_variant_builder_add(&builder, "{sv}", "summary", g_variant_new_string(polling_context->summary));
	if (polling_context->attempted_hash)
		g_variant_builder_add(&builder, "{sv}", "attempted-hash", g_variant_new_string(polling_context->attempted_hash));

	if (polling_context->manifest) {
		/* manifest dict */
		g_variant_builder_add(&builder, "{sv}", "manifest", r_manifest_to_dict(polling_context->manifest));

		/* bundle dict */
		g_variant_builder_open(&builder, G_VARIANT_TYPE("{sv}"));
		g_variant_builder_add(&builder, "s", "bundle");
		g_variant_builder_open(&builder, G_VARIANT_TYPE("v"));
		g_variant_builder_open(&builder, G_VARIANT_TYPE("a{sv}"));
		if (polling_context->bundle_size)
			g_variant_builder_add(&builder, "{sv}", "size", g_variant_new_uint64(polling_context->bundle_size));
		if (polling_context->bundle_effective_url)
			g_variant_builder_add(&builder, "{sv}", "effective-url", g_variant_new_string(polling_context->bundle_effective_url));
		if (polling_context->bundle_modified_time)
			g_variant_builder_add(&builder, "{sv}", "modified-time", g_variant_new_uint64(polling_context->bundle_modified_time));
		if (polling_context->bundle_etag)
			g_variant_builder_add(&builder, "{sv}", "etag", g_variant_new_string(polling_context->bundle_etag));
		g_variant_builder_close(&builder); /* inner a{sv} */
		g_variant_builder_close(&builder); /* inner v */
		g_variant_builder_close(&builder); /* outer {sv} */
	}

	r_poller_set_status(r_poller, g_variant_builder_end(&builder));
}

static gboolean on_handle_poll(RPoller *interface, GDBusMethodInvocation *invocation)
{
	RPollingContext *polling_context = (RPollingContext *)g_object_get_data(G_OBJECT(interface), "r-poll");
	g_assert(polling_context);

	polling_reschedule(polling_context, POLLING_DELAY_SHORT);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_poller));
	r_poller_complete_poll(interface, invocation);

	return TRUE;
}

static gboolean polling_context_dispatch(gpointer user_data)
{
	g_return_val_if_fail(user_data, G_SOURCE_REMOVE);

	RPollingContext *polling_context = user_data;
	g_autoptr(GError) ierror = NULL;
	gint64 now_boottime = r_get_boottime();

	/* We keep the timeout in CLOCK_BOOTTIME, so that time spent in suspend
	 * doesn't delay execution of the next polling attempt.
	 * As the GLib event loop uses CLOCK_MONOTONIC, we need to keep manage our
	 * own timeout and check it regularly.
	 **/
	if (now_boottime < polling_context->next_poll_time) {
		return G_SOURCE_CONTINUE;
	}

	/* check for running installation */
	if (polling_context->installation_running) {
		return G_SOURCE_CONTINUE;
	}

	/* check busy state */
	if (r_context_get_busy()) {
		g_debug("context busy, will try again later");
		polling_reschedule(polling_context, POLLING_DELAY_SHORT);
		return G_SOURCE_CONTINUE;
	}

	/* check if the booted slot was marked good */
	if (!r_service_booted_slot_is_good) {
		g_debug("booted slot not marked good yet, will try again later");
		polling_reschedule(polling_context, POLLING_DELAY_SHORT);
		return G_SOURCE_CONTINUE;
	}

	/* check inhibit */
	for (gchar **p = r_context()->config->polling_inhibit_files; p && *p; p++) {
		if (g_file_test(*p, G_FILE_TEST_EXISTS)) {
			g_debug("inhibited by %s, will try again later", *p);
			polling_reschedule(polling_context, POLLING_DELAY_SHORT);
			return G_SOURCE_CONTINUE;
		}
	}

	/* check if we need to reboot */
	if (polling_context->must_reboot) {
		if (!polling_reboot(&ierror)) {
			g_message("reboot failed: %s", ierror->message);
			polling_reschedule(polling_context, POLLING_DELAY_SHORT);
			return G_SOURCE_CONTINUE;
		}

		/* after triggering a reboot, we stop polling */
		r_poller_set_next_poll(r_poller, 0);
		return G_SOURCE_REMOVE;
	}

	/* poll once */
	polling_context->last_attempt_time = now_boottime;
	polling_context->attempt_count += 1;
	/* TODO add some headers? recent errors? */
	if (!polling_step(polling_context, &ierror)) {
		g_message("polling failed: %s", ierror->message);
		r_replace_strdup(&polling_context->last_error_message, ierror->message);
		polling_context->recent_error_count += 1;
	} else {
		g_clear_pointer(&polling_context->last_error_message, g_free);
		polling_context->last_success_time = r_get_boottime();
		polling_context->recent_error_count = 0;
	}

	polling_update_status(polling_context);

	if (!polling_context->installation_running) {
		/* schedule next poll */
		polling_reschedule(polling_context, POLLING_DELAY_NORMAL);
	}

	return G_SOURCE_CONTINUE;
}

static void polling_context_finalize(gpointer user_data)
{
	g_return_if_fail(user_data);

	g_clear_pointer(&r_poller, g_object_unref);

	RPollingContext *polling_context = user_data;
	g_clear_pointer(&polling_context->last_error_message, g_free);
	g_clear_pointer(&polling_context->summary, g_free);
	g_clear_pointer(&polling_context->attempted_hash, g_free);
	polling_context_clear_manifest(polling_context);
	g_free(polling_context);
}

void r_polling_on_bus_acquired(GDBusConnection *connection)
{
	GError *ierror = NULL;

	if (!r_context()->config->polling_url) {
		return;
	}

	g_assert(r_poller);

	g_signal_connect(r_poller, "handle-poll",
			G_CALLBACK(on_handle_poll),
			NULL);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(r_poller),
			connection,
			"/",
			&ierror)) {
		g_error("Failed to export interface: %s", ierror->message);
		g_error_free(ierror);
	}
}

gboolean r_polling_setup(GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!r_context()->config->polling_url) {
		g_set_error_literal(
				error,
				R_POLLING_ERROR, R_POLLING_ERROR_DISABLED,
				"polling disabled (due to unset URL)");
		return FALSE;
	}

	if (!r_context()->system_version) {
		g_set_error_literal(
				error,
				R_POLLING_ERROR, R_POLLING_ERROR_CONFIG,
				"system version not provided via system-info handler");
		return FALSE;
	}

	guint interval = 10;
	if (r_context()->mock.polling_speedup)
		interval = interval / r_context()->mock.polling_speedup;

	g_assert(r_poller == NULL);
	r_poller = r_poller_skeleton_new();
	RPollingContext *polling_context = g_new0(RPollingContext, 1);
	g_timeout_add_seconds_full(
			G_PRIORITY_LOW,
			interval,
			polling_context_dispatch,
			polling_context,
			polling_context_finalize);

	g_object_set_data(G_OBJECT(r_poller), "r-poll", polling_context);

	polling_update_status(polling_context);
	polling_reschedule(polling_context, POLLING_DELAY_INITIAL);

	g_message("polling enabled");

	return TRUE;
};

const gchar * const r_polling_supported_candidate_criteria[] = {
	"higher-semver",
	"different-version",
	NULL
};
const gchar * const r_polling_default_candidate_criteria[] = {
	"higher-semver",
	NULL
};
const gchar * const r_polling_supported_install_criteria[] = {
	"always",
	"higher-semver",
	"different-version",
	NULL
};
const gchar * const r_polling_supported_reboot_criteria[] = {
	"updated-slots",
	"updated-artifacts",
	"failed-update",
	NULL
};
