#include <glib.h>
#include <stdio.h>

#include "poll.h"
#include "bundle.h"
#include "config_file.h"
#include "context.h"
#include "install.h"
#include "manifest.h"
#include "service.h"
#include "utils.h"

RPoller *r_poller = NULL;

typedef struct {
	GSource source;

	gboolean installation_running;

	guint64 attempt_count;
	guint64 recent_error_count; /* since last success */
	gint64 last_attempt_time; /* monotonic */
	gint64 last_success_time; /* monotonic */
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
} RPollSource;

typedef enum {
	POLL_DELAY_NORMAL = 0,
	POLL_DELAY_SHORT,
	POLL_DELAY_NOW,
	POLL_DELAY_INITIAL,
} RPollDelay;

static void poll_reschedule(RPollSource *poll_source, RPollDelay delay)
{
	g_return_if_fail(poll_source);

	gint64 delay_ms = 0;

	switch (delay) {
		case POLL_DELAY_NORMAL:
			delay_ms = r_context()->config->poll_interval_ms * (poll_source->recent_error_count+1);
			delay_ms = MIN(delay_ms, r_context()->config->poll_max_interval_ms);
			break;
		case POLL_DELAY_SHORT:
			delay_ms = 15 * 1000;
			break;
		case POLL_DELAY_NOW:
			delay_ms = 2 * 1000;
			break;
		case POLL_DELAY_INITIAL:
			delay_ms = r_context()->config->poll_interval_ms * g_random_double_range(0.1, 0.9);
			break;
		default:
			g_assert_not_reached();
	}

	//g_message("delay_ms=%"G_GINT64_FORMAT, delay_ms);
	if (r_context()->mock.poll_speedup)
		delay_ms = delay_ms / r_context()->mock.poll_speedup;
	//g_message("speedup delay_ms=%"G_GINT64_FORMAT, delay_ms);

	gint64 next = g_get_monotonic_time() + delay_ms * 1000;
	r_poller_set_next_poll(r_poller, next);
	//g_message("now=%"G_GINT64_FORMAT" next poll=%"G_GINT64_FORMAT, g_get_monotonic_time(), next);
	g_source_set_ready_time(&poll_source->source, next);

	g_autofree gchar *duration_str = r_format_duration(delay_ms / 1000);
	g_message("scheduled next poll in: %s", duration_str);
}

static gboolean poll_fetch(RPollSource *poll_source, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(poll_source, FALSE);

	/* fetch manifest */
	g_auto(RaucBundleAccessArgs) access_args = {0};
	access_args.http_info_headers = assemble_info_headers(NULL);
	if (poll_source->bundle_etag) {
		g_ptr_array_add(access_args.http_info_headers, g_strdup_printf("If-None-Match: %s", poll_source->bundle_etag));
	}

	g_autoptr(RaucBundle) bundle = NULL;
	if (!check_bundle(r_context()->config->poll_source, &bundle, CHECK_BUNDLE_DEFAULT, &access_args, &ierror)) {
		if (g_error_matches(ierror, R_NBD_ERROR, R_NBD_ERROR_NO_CONTENT)) {
			g_message("polling: no bundle available");
			/* TODO update summary? */
			return TRUE; /* FIXME should this be an error? */
		} else if (g_error_matches(ierror, R_NBD_ERROR, R_NBD_ERROR_NOT_MODIFIED)) {
			g_message("polling: bundle not modified");
			/* TODO update summary? */
			return TRUE;
		} else {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	if (!bundle->manifest) {
		g_message("polling failed: no manifest found");
		return FALSE;
	}

	g_clear_pointer(&poll_source->manifest, free_manifest);
	poll_source->manifest = g_steal_pointer(&bundle->manifest);

	g_assert(bundle->nbd_srv);
	poll_source->bundle_size = bundle->nbd_srv->data_size;
	poll_source->bundle_modified_time = bundle->nbd_srv->modified_time;
	r_replace_strdup(&poll_source->bundle_effective_url, bundle->nbd_srv->effective_url);
	r_replace_strdup(&poll_source->bundle_etag, bundle->nbd_srv->etag);

	return TRUE;
}

static gboolean poll_check_candidate_criteria(RPollSource *poll_source, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(poll_source, FALSE);
	g_return_val_if_fail(poll_source->manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->poll_candidate_criteria;
	g_assert(criteria);
	const gchar *system_ver = r_context()->system_version;
	g_assert(system_ver);
	const gchar *update_ver = poll_source->manifest->update_version;
	g_assert(update_ver);

	if (g_strv_contains(criteria, "higher-semver")) {
		if (!r_semver_less_equal(update_ver, system_ver, &ierror)) {
			if (ierror) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
			r_replace_strdup(&poll_source->summary, "update candidate found: higher semantic version");
			return TRUE;
		}
	}

	if (g_strv_contains(criteria, "different-version")) {
		if (g_strcmp0(r_context()->system_version, poll_source->manifest->update_version) != 0) {
			r_replace_strdup(&poll_source->summary, "update candidate found: different version");
			return TRUE;
		}
	}

	r_replace_strdup(&poll_source->summary, "no update candidate available");
	return FALSE;
}

static gboolean poll_check_install_criteria(RPollSource *poll_source, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(poll_source, FALSE);
	g_return_val_if_fail(poll_source->manifest, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->poll_install_criteria;
	if (!criteria) {
		g_debug("polling: no installation criteria");
		return FALSE;
	}

	const gchar *system_ver = r_context()->system_version;
	g_assert(system_ver);
	const gchar *update_ver = poll_source->manifest->update_version;
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
		if (g_strcmp0(r_context()->system_version, poll_source->manifest->update_version) != 0) {
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

static gboolean poll_check_reboot_criteria(const RaucInstallArgs *install_args)
{
	g_return_val_if_fail(install_args, FALSE);

	const gchar *const *criteria = (const gchar *const *)r_context()->config->poll_reboot_criteria;
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

static gboolean poll_install_cleanup(gpointer data)
{
	g_return_val_if_fail(data, G_SOURCE_REMOVE);

	RaucInstallArgs *args = data;
	RPollSource *poll_source = args->data;

	g_return_val_if_fail(poll_source, G_SOURCE_REMOVE);

	poll_source->installation_running = FALSE;

	g_mutex_lock(&args->status_mutex);
	if (args->status_result == 0) {
		g_message("polling: installation of `%s` succeeded", args->name);
	} else {
		g_message("polling: installation of `%s` failed: %d", args->name, args->status_result);
	}
	/* TODO expose error? */
	r_installer_emit_completed(r_installer, args->status_result);
	r_installer_set_operation(r_installer, "idle");
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_installer));
	if (poll_check_reboot_criteria(args)) {
		poll_source->must_reboot = TRUE;
	}
	g_mutex_unlock(&args->status_mutex);

	install_args_free(args);

	poll_reschedule(poll_source, POLL_DELAY_SHORT);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_poller));

	return G_SOURCE_REMOVE;
}

static gboolean poll_install(RPollSource *poll_source, GError **error)
{
	RaucInstallArgs *args = install_args_new();
	g_autofree gchar *message = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(poll_source, FALSE);
	g_return_val_if_fail(poll_source->manifest, FALSE);
	g_return_val_if_fail(poll_source->manifest->hash, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	args->name = g_strdup(r_context()->config->poll_source);
	args->cleanup = poll_install_cleanup;
	args->data = poll_source;
	/* lock bundle via manifest hash */
	args->require_manifest_hash = g_strdup(poll_source->manifest->hash);

	r_installer_set_operation(r_installer, "installing");
	res = install_run(args);
	if (!res) {
		args->status_result = 1;
		goto out;
	}
	args = NULL;
	poll_source->installation_running = TRUE;

out:
	g_clear_pointer(&args, install_args_free);
	if (!res) {
		r_installer_set_operation(r_installer, "idle");
	}

	return TRUE;
}

static gboolean poll_reboot(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	const gchar *cmd = r_context()->config->poll_reboot_cmd;
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

static gboolean poll_step(RPollSource *poll_source, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(poll_source, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!poll_fetch(poll_source, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_clear_pointer(&poll_source->summary, g_free);
	poll_source->update_available = FALSE;
	gboolean candidate = poll_check_candidate_criteria(poll_source, &ierror);
	if (ierror) {
		g_propagate_prefixed_error(error, ierror, "candidate criteria check failed: ");
		return FALSE;
	} else if (!candidate) {
		return TRUE;
	}
	poll_source->update_available = TRUE;

	gboolean install = poll_check_install_criteria(poll_source, &ierror);
	if (ierror) {
		g_propagate_prefixed_error(error, ierror, "installation criteria check failed: ");
		return FALSE;
	} else if (!install) {
		g_message("polling: candidate needs to be explicitly confirmed");
		return TRUE;
	}

	/* skip attempt if manifest hash is the same */
	if (g_strcmp0(poll_source->manifest->hash, poll_source->attempted_hash) == 0) {
		g_message("polling: manifest is unchanged, skipping installation");
		return TRUE;
	}

	g_message("polling: starting installation of version '%s'", poll_source->manifest->update_version);
	r_replace_strdup(&poll_source->attempted_hash, poll_source->manifest->hash);
	if (!poll_install(poll_source, &ierror)) {
		return FALSE;
	}

	return TRUE;
}

static void poll_update_status(RPollSource *poll_source)
{
	g_return_if_fail(poll_source);

	g_auto(GVariantBuilder) builder = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(&builder, "{sv}", "attempt-count", g_variant_new_uint64(poll_source->attempt_count));
	g_variant_builder_add(&builder, "{sv}", "recent-error-count", g_variant_new_uint64(poll_source->recent_error_count));

	g_variant_builder_add(&builder, "{sv}", "last-attempt-time", g_variant_new_uint64(poll_source->last_attempt_time));
	g_variant_builder_add(&builder, "{sv}", "last-success-time", g_variant_new_uint64(poll_source->last_success_time));
	if (poll_source->last_error_message)
		g_variant_builder_add(&builder, "{sv}", "last-error-message", g_variant_new_string(poll_source->last_error_message));
	g_variant_builder_add(&builder, "{sv}", "update-available", g_variant_new_boolean(poll_source->update_available));
	if (poll_source->summary)
		g_variant_builder_add(&builder, "{sv}", "summary", g_variant_new_string(poll_source->summary));
	if (poll_source->attempted_hash)
		g_variant_builder_add(&builder, "{sv}", "attempted-hash", g_variant_new_string(poll_source->attempted_hash));

	if (poll_source->manifest) {
		/* manifest dict */
		g_variant_builder_add(&builder, "{sv}", "manifest", r_manifest_to_dict(poll_source->manifest));

		/* bundle dict */
		g_variant_builder_open(&builder, G_VARIANT_TYPE("{sv}"));
		g_variant_builder_add(&builder, "s", "bundle");
		g_variant_builder_open(&builder, G_VARIANT_TYPE("v"));
		g_variant_builder_open(&builder, G_VARIANT_TYPE("a{sv}"));
		if (poll_source->bundle_size)
			g_variant_builder_add(&builder, "{sv}", "size", g_variant_new_uint64(poll_source->bundle_size));
		if (poll_source->bundle_effective_url)
			g_variant_builder_add(&builder, "{sv}", "effective-url", g_variant_new_string(poll_source->bundle_effective_url));
		if (poll_source->bundle_modified_time)
			g_variant_builder_add(&builder, "{sv}", "modified-time", g_variant_new_uint64(poll_source->bundle_modified_time));
		if (poll_source->bundle_etag)
			g_variant_builder_add(&builder, "{sv}", "etag", g_variant_new_string(poll_source->bundle_etag));
		g_variant_builder_close(&builder); /* inner a{sv} */
		g_variant_builder_close(&builder); /* inner v */
		g_variant_builder_close(&builder); /* outer {sv} */
	}

	r_poller_set_status(r_poller, g_variant_builder_end(&builder));
}

static gboolean on_handle_poll(RPoller *interface, GDBusMethodInvocation *invocation)
{
	RPollSource *poll_source = (RPollSource *)g_object_get_data(G_OBJECT(interface), "r-poll");
	g_assert(poll_source);

	poll_reschedule(poll_source, POLL_DELAY_NOW);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(r_poller));
	r_poller_complete_poll(interface, invocation);

	return TRUE;
}

static gboolean poll_source_dispatch(GSource *source, GSourceFunc _callback, gpointer _user_data)
{
	g_return_val_if_fail(source, G_SOURCE_REMOVE);

	RPollSource *poll_source = (void *)source;
	g_autoptr(GError) ierror = NULL;

	/* check busy state */
	if (r_context_get_busy()) {
		g_debug("context busy, will try again later");
		poll_reschedule(poll_source, POLL_DELAY_SHORT);
		return G_SOURCE_CONTINUE;
	}

	/* check inhibit */
	for (gchar **p = r_context()->config->poll_inhibit_files; p && *p; p++) {
		if (g_file_test(*p, G_FILE_TEST_EXISTS)) {
			g_debug("inhibited by %s", *p);
			poll_reschedule(poll_source, POLL_DELAY_SHORT);
			return G_SOURCE_CONTINUE;
		}
	}

	/* check if we need to reboot */
	if (poll_source->must_reboot) {
		if (!poll_reboot(&ierror)) {
			g_message("reboot failed: %s", ierror->message);
			poll_reschedule(poll_source, POLL_DELAY_SHORT);
			return G_SOURCE_CONTINUE;
		}

		/* after triggering a reboot, we stop polling */
		return G_SOURCE_REMOVE;
	}

	/* poll once */
	poll_source->last_attempt_time = g_get_monotonic_time();
	poll_source->attempt_count += 1;
	/* TODO add some headers? recent errors? */
	if (!poll_step(poll_source, &ierror)) {
		g_message("polling failed: %s", ierror->message);
		r_replace_strdup(&poll_source->last_error_message, ierror->message);
		poll_source->recent_error_count += 1;
	} else {
		g_clear_pointer(&poll_source->last_error_message, g_free);
		poll_source->last_success_time = g_get_monotonic_time();
		poll_source->recent_error_count = 0;
	}

	poll_update_status(poll_source);

	if (poll_source->installation_running) {
		/* wait until the installation has completed */
		g_source_set_ready_time(&poll_source->source, -1);
	} else {
		/* schedule next poll */
		poll_reschedule(poll_source, POLL_DELAY_NORMAL);
	}

	return G_SOURCE_CONTINUE;
}

static void poll_source_finalize(GSource *source)
{
	g_return_if_fail(source);

	g_clear_pointer(&r_poller, g_object_unref);

	RPollSource *poll_source = (void *)source;
	g_clear_pointer(&poll_source->last_error_message, g_free);
	g_clear_pointer(&poll_source->manifest, free_manifest);
	g_clear_pointer(&poll_source->summary, g_free);
	g_clear_pointer(&poll_source->attempted_hash, g_free);
	g_clear_pointer(&poll_source->bundle_effective_url, g_free);
	g_clear_pointer(&poll_source->bundle_etag, g_free);
}

static GSourceFuncs source_funcs = {
	.dispatch = poll_source_dispatch,
	.finalize = poll_source_finalize,
};

void r_poll_on_bus_acquired(GDBusConnection *connection)
{
	GError *ierror = NULL;

	if (!r_context()->config->poll_source) {
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
	g_message("poller skeleton set up");
}

GSource *r_poll_setup(void)
{
	if (!r_context()->config->poll_source) {
		return NULL;
	}

	r_poller = r_poller_skeleton_new();

	GSource *source = g_source_new(&source_funcs, sizeof(RPollSource));
	RPollSource *poll_source = (void *)source;
	g_object_set_data(G_OBJECT(r_poller), "r-poll", poll_source);

	poll_update_status(poll_source);
	poll_reschedule(poll_source, POLL_DELAY_INITIAL);
	g_source_attach(source, NULL);

	g_message("polling enabled");

	return source;
}
