#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <bundle.h>
#include <context.h>
#include <install.h>
#include <manifest.h>
#include <mount.h>
#include <utils.h>

#include "../rauc-installer-generated.h"

#include "common.h"
#include "install-fixtures.h"

typedef struct {
	GTestDBus *dbus;
	gchar *tmpdir;
} ServiceFixture;

GMainLoop *testloop = NULL;
RInstaller *installer = NULL;

static void service_install_fixture_set_up(ServiceFixture *fixture, gconstpointer user_data)
{
	g_autofree gchar *contents = NULL;
	g_autofree gchar *filename = NULL;

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL,
			&(ManifestTestOptions) {
		.custom_handler = FALSE,
		.hooks = FALSE,
	});

	/* Write a D-Bus service file with current tmpdir */
	contents = g_strdup_printf("\
[D-BUS Service]\n\
Name=de.pengutronix.rauc\n\
Exec="TEST_SERVICES "/rauc -c %s/system.conf --mount=%s/mount --override-boot-slot=system0 service\n", fixture->tmpdir, fixture->tmpdir),
	filename = write_tmp_file(fixture->tmpdir, "de.pengutronix.rauc.service", contents, NULL);
	(void)filename;

	fixture->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_add_service_dir(fixture->dbus, fixture->tmpdir);
	g_test_dbus_up(fixture->dbus);
}
static void service_info_fixture_set_up(ServiceFixture *fixture, gconstpointer user_data)
{
	g_autofree gchar *filename = NULL;

	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	/* Write a D-Bus service file with current tmpdir */
	filename = write_tmp_file(fixture->tmpdir, "de.pengutronix.rauc.service", "\
[D-BUS Service]\n\
Name=de.pengutronix.rauc\n\
Exec="TEST_SERVICES "/rauc -c test/test.conf --override-boot-slot=system0 service\n", NULL);
	(void)filename;

	fixture->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_add_service_dir(fixture->dbus, fixture->tmpdir);
	g_test_dbus_up(fixture->dbus);
}

static void service_fixture_tear_down(ServiceFixture *fixture, gconstpointer user_data)
{
	GError *error = NULL;
	gboolean ret = FALSE;

	g_test_dbus_down(fixture->dbus);
	g_object_unref(fixture->dbus);

	test_umount(fixture->tmpdir, "slot");
	test_umount(fixture->tmpdir, "bootloader");

	ret = rm_tree(fixture->tmpdir, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	g_free(fixture->tmpdir);
}

static void on_installer_changed(GDBusProxy *proxy, GVariant *changed,
		const gchar* const *invalidated,
		gpointer data)
{
	GQueue *args = data;
	gchar *msg;
	GVariant *var;
	gint32 percentage, depth;
	const gchar *message = NULL;

	if (g_variant_lookup(changed, "Operation", "s", &msg)) {
		g_message("Operation: %s", msg);
	}
	if (g_variant_lookup(changed, "Progress", "(isi)", &percentage, &message, &depth)) {
		gint32 cmp_percentage, cmp_depth;
		const gchar *cmp_message;

		var = g_queue_pop_head(args);
		cmp_percentage = g_variant_get_int32(g_variant_get_child_value(var, 0));
		cmp_message = g_variant_get_string(g_variant_get_child_value(var, 1), NULL);
		cmp_depth = g_variant_get_int32(g_variant_get_child_value(var, 2));
		g_message("Progress changed: %03d, %s, %d", percentage, message, depth);
		g_assert_cmpint(percentage, ==, cmp_percentage);
		g_assert_cmpstr(message, ==, cmp_message);
		g_assert_cmpint(depth, ==, cmp_depth);
	}
}

static void on_installer_completed(GDBusProxy *proxy, gint result,
		gpointer data)
{
	const gchar *last_error = NULL;
	last_error = r_installer_get_last_error(installer);
	g_assert_cmpstr(last_error, ==, "");
	g_assert_cmpint(result, ==, 0);
	g_main_loop_quit(testloop);
}

static void on_installer_completed_failed(GDBusProxy *proxy, gint result,
		gpointer data)
{
	const gchar *last_error = NULL;
	last_error = r_installer_get_last_error(installer);
	g_assert_cmpstr(last_error, !=, "");
	g_assert_cmpint(result, !=, 0);
	g_main_loop_quit(testloop);
}

static void assert_progress(GVariant *progress, gint32 percentage, const gchar *message, gint32 depth)
{
	gint32 comp_percentage, comp_depth;
	const gchar *comp_message = NULL;
	GVariant *gv = NULL;

	g_assert(g_variant_n_children(progress) == 3);
	gv = g_variant_get_child_value(progress, 0);
	comp_percentage = g_variant_get_int32(gv);
	g_assert_cmpint(percentage, ==, comp_percentage);
	g_variant_unref(gv);

	gv = g_variant_get_child_value(progress, 1);
	comp_message = g_variant_get_string(gv, NULL);
	g_assert_cmpstr(message, ==, comp_message);
	g_variant_unref(gv);

	gv = g_variant_get_child_value(progress, 2);
	comp_depth = g_variant_get_int32(gv);
	g_assert_cmpint(depth, ==, comp_depth);
	g_variant_unref(gv);
}

static void service_test_install(ServiceFixture *fixture, gconstpointer user_data, gboolean deprecated)
{
	GQueue *args = g_queue_new();
	const gchar *operation = NULL, *last_error = NULL;
	GVariant *progress = NULL;
	const gchar *compatible = NULL;
	const gchar *variant = NULL;
	const gchar *bootslot = NULL;
	gchar *bundlepath;
	GError *error = NULL;
	gboolean ret = FALSE;

	if (!ENABLE_SERVICE) {
		g_test_skip("Test requires RAUC being configured with \"--enable-service\".");
		return;
	}

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	testloop = g_main_loop_new(NULL, FALSE);

	/* Pre-set progress check queue */
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",   0, "Installing", 1));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",   0, "Determining slot states", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  10, "Determining slot states done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  10, "Checking bundle", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  10, "Verifying signature", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Verifying signature done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Checking bundle done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Checking manifest contents", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  30, "Checking manifest contents done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  30, "Determining target install group", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Determining target install group done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Updating slots", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Checking slot rootfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  43, "Checking slot rootfs.1 done.", 3));
	for (gint32 i = 43; i<= 69; i++)
		g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", i, "Copying image to rootfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  70, "Copying image to rootfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  70, "Checking slot appfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  73, "Checking slot appfs.1 done.", 3));
	for (gint32 i = 73; i<= 99; i++)
		g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", i, "Copying image to appfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  99, "Copying image to appfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  99, "Updating slots done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", 100, "Installing done.", 1));

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
			"de.pengutronix.rauc", "/", NULL, &error);

	g_assert_no_error(error);
	g_assert_nonnull(installer);

	/* connect signals to test callbacks */
	g_assert_cmpint(g_signal_connect(installer, "g-properties-changed",
			G_CALLBACK(on_installer_changed), args), !=, 0);
	g_assert_cmpint(g_signal_connect(installer, "completed",
			G_CALLBACK(on_installer_completed), NULL), !=, 0);

	/* initial operation must be 'idle', initial last_error must be empty */
	operation = r_installer_get_operation(installer);
	g_assert_cmpstr(operation, ==, "idle");
	last_error = r_installer_get_last_error(installer);
	g_assert_cmpstr(last_error, ==, "");

	progress = r_installer_get_progress(installer);
	assert_progress(progress, 0, "", 0);

	compatible = r_installer_get_compatible(installer);
	g_assert_cmpstr(compatible, ==, "Test Config");
	variant = r_installer_get_variant(installer);
	g_assert_cmpstr(variant, ==, "test-variant-x");
	bootslot = r_installer_get_boot_slot(installer);
	g_assert_cmpstr(bootslot, ==, "system0");

	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	/* Actually install bundle */
	if (deprecated) {
		ret = r_installer_call_install_sync(
				installer,
				bundlepath,
				NULL,
				&error);
	} else {
		g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);
		ret = r_installer_call_install_bundle_sync(
				installer,
				bundlepath,
				g_variant_dict_end(&dict), /* floating, no unref needed */
				NULL,
				&error);
	}
	g_assert_no_error(error);
	g_assert_true(ret);

	g_main_loop_run(testloop);

	g_clear_object(&installer);
}

static void service_test_install_bundle(ServiceFixture *fixture, gconstpointer user_data)
{
	service_test_install(fixture, user_data, FALSE);
}

static void service_test_install_api(ServiceFixture *fixture, gconstpointer user_data)
{
	GError *error = NULL;
	gboolean ret = FALSE;
	g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);

	if (!ENABLE_SERVICE) {
		g_test_skip("Test requires RAUC being configured with \"--enable-service\".");
		return;
	}

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	testloop = g_main_loop_new(NULL, FALSE);

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
			"de.pengutronix.rauc", "/", NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(installer);

	g_assert_cmpint(g_signal_connect(installer, "completed",
			G_CALLBACK(on_installer_completed_failed), NULL), !=, 0);

	/* Test with invalid key */
	g_variant_dict_insert(&dict, "invalid-key", "b", TRUE);

	ret = r_installer_call_install_bundle_sync(
			installer,
			g_strdup("dummy path"),
			g_variant_dict_end(&dict), /* floating, no unref needed */
			NULL,
			&error);

	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_FAILED_HANDLED);
	g_assert_false(ret);
	g_clear_error(&error);

	/* Test with valid key but invalid type */
	g_variant_dict_init(&dict, NULL);
	g_variant_dict_insert(&dict, "ignore-compatible", "s", "buhlean");

	ret = r_installer_call_install_bundle_sync(
			installer,
			g_strdup("dummy path"),
			g_variant_dict_end(&dict), /* floating, no unref needed */
			NULL,
			&error);

	g_assert_error(error, G_IO_ERROR, G_IO_ERROR_FAILED_HANDLED);
	g_assert_false(ret);
	g_clear_error(&error);

	/* Test with valid key and valid type */
	g_variant_dict_init(&dict, NULL);
	g_variant_dict_insert(&dict, "ignore-compatible", "b", TRUE);

	ret = r_installer_call_install_bundle_sync(
			installer,
			g_strdup("dummy path"),
			g_variant_dict_end(&dict), /* floating, no unref needed */
			NULL,
			&error);
	/* (actual installation will fail as 'dummy path' does not exist) */
	g_assert_no_error(error);
	g_assert_true(ret);

	g_main_loop_run(testloop);

	g_clear_object(&installer);
}

static void service_test_install_deprecated(ServiceFixture *fixture, gconstpointer user_data)
{
	service_test_install(fixture, user_data, TRUE);
}

static void service_test_info(ServiceFixture *fixture, gconstpointer user_data, gboolean deprecated)
{
	GError *error = NULL;
	g_autofree gchar *compatible = NULL;
	g_autofree gchar *version = NULL;
	g_autofree gchar *bundlepath = NULL;

	if (!ENABLE_SERVICE) {
		g_test_skip("Test requires RAUC being configured with \"--enable-service\".");
		return;
	}

	bundlepath = g_build_filename(fixture->tmpdir, "good-bundle.raucb", NULL);
	g_assert_true(test_copy_file("test", "good-bundle.raucb", fixture->tmpdir, "good-bundle.raucb"));

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_NONE,
			"de.pengutronix.rauc",
			"/",
			NULL,
			&error);
	g_assert_no_error(error);

	if (installer == NULL) {
		g_error("failed to install proxy");
		goto out;
	}

	if (deprecated) {
		r_installer_call_info_sync(installer,
				bundlepath,
				&compatible,
				&version,
				NULL,
				&error);
	} else {
		g_autoptr(GVariant) info = NULL;
		g_autoptr(GVariant) bundle_update = NULL;
		g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);
		r_installer_call_inspect_bundle_sync(installer,
				bundlepath,
				g_variant_dict_end(&dict), /* floating, no unref needed */
				&info,
				NULL,
				&error);
		g_assert_nonnull(info);
		g_variant_lookup(info, "update", "v", &bundle_update);
		g_assert_nonnull(bundle_update);
		g_variant_lookup(bundle_update, "compatible", "s", &compatible);
		g_variant_lookup(bundle_update, "version", "s", &version);
	}
	g_assert_no_error(error);
	g_assert_cmpstr(compatible, ==, "Test Config");
	g_assert_cmpstr(version, ==, "2011.03-2");

out:
	g_clear_object(&installer);
}

static void service_test_info_bundle(ServiceFixture *fixture, gconstpointer user_data)
{
	service_test_info(fixture, user_data, FALSE);
}

static void service_test_info_deprecated(ServiceFixture *fixture, gconstpointer user_data)
{
	service_test_info(fixture, user_data, TRUE);
}

static void service_test_slot_status(ServiceFixture *fixture, gconstpointer user_data)
{
	GError *error = NULL;
	GVariant *slot_status_array = NULL;

	if (!ENABLE_SERVICE) {
		g_test_skip("Test requires RAUC being configured with \"--enable-service\".");
		return;
	}

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_NONE,
			"de.pengutronix.rauc",
			"/",
			NULL,
			&error);
	g_assert_no_error(error);

	if (installer == NULL) {
		g_error("failed to install proxy");
		goto out;
	}

	r_installer_call_get_slot_status_sync(installer,
			&slot_status_array,
			NULL,
			&error);
	g_assert_no_error(error);
	g_assert_nonnull(slot_status_array);
	g_assert_cmpint(g_variant_n_children(slot_status_array), ==, 6);

out:
	g_clear_object(&installer);
	g_variant_unref(slot_status_array);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/service/install-bundle", ServiceFixture, NULL,
			service_install_fixture_set_up, service_test_install_bundle,
			service_fixture_tear_down);

	g_test_add("/service/install-deprecated", ServiceFixture, NULL,
			service_install_fixture_set_up, service_test_install_deprecated,
			service_fixture_tear_down);

	g_test_add("/service/install-api", ServiceFixture, NULL,
			service_install_fixture_set_up, service_test_install_api,
			service_fixture_tear_down);

	g_test_add("/service/info-bundle", ServiceFixture, NULL,
			service_info_fixture_set_up, service_test_info_bundle,
			service_fixture_tear_down);

	g_test_add("/service/info-deprecated", ServiceFixture, NULL,
			service_info_fixture_set_up, service_test_info_deprecated,
			service_fixture_tear_down);

	g_test_add("/service/slot-status", ServiceFixture, NULL,
			service_info_fixture_set_up, service_test_slot_status,
			service_fixture_tear_down);

	return g_test_run();
}
