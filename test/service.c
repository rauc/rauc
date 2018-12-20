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
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	fixture_helper_set_up_system(fixture->tmpdir, NULL);
	fixture_helper_set_up_bundle(fixture->tmpdir, NULL, FALSE, FALSE);

	/* Write a D-Bus service file with current tmpdir */
	write_tmp_file(fixture->tmpdir, "de.pengutronix.rauc.service", g_strdup_printf("\
[D-BUS Service]\n\
Name=de.pengutronix.rauc\n\
Exec="TEST_SERVICES "/rauc -c %s/system.conf --mount=%s/mount --override-boot-slot=system0 service\n", fixture->tmpdir, fixture->tmpdir), NULL);

	fixture->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_add_service_dir(fixture->dbus, fixture->tmpdir);
	g_test_dbus_up(fixture->dbus);
}
static void service_info_fixture_set_up(ServiceFixture *fixture, gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	/* Write a D-Bus service file with current tmpdir */
	write_tmp_file(fixture->tmpdir, "de.pengutronix.rauc.service", "\
[D-BUS Service]\n\
Name=de.pengutronix.rauc\n\
Exec="TEST_SERVICES "/rauc -c test/test.conf service\n", NULL);

	fixture->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_add_service_dir(fixture->dbus, fixture->tmpdir);
	g_test_dbus_up(fixture->dbus);
}

static void service_fixture_tear_down(ServiceFixture *fixture, gconstpointer user_data)
{
	g_test_dbus_down(fixture->dbus);
	g_object_unref(fixture->dbus);
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

static void service_test_install(ServiceFixture *fixture, gconstpointer user_data)
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
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Determining slot states done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Checking bundle", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  20, "Verifying signature", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Verifying signature done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Checking bundle done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  40, "Loading manifest file", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  60, "Loading manifest file done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  60, "Determining target install group", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  80, "Determining target install group done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  80, "Updating slots", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  80, "Checking slot rootfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  85, "Checking slot rootfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  85, "Copying image to rootfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  90, "Copying image to rootfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  90, "Checking slot appfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  95, "Checking slot appfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)",  95, "Copying image to appfs.1", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", 100, "Copying image to appfs.1 done.", 3));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", 100, "Updating slots done.", 2));
	g_queue_push_tail(args, (gpointer*)g_variant_new("(isi)", 100, "Installing done.", 1));

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
			"de.pengutronix.rauc", "/", NULL, NULL);

	g_assert_nonnull(installer);

	/* connect signals to test callbacks */
	g_assert_cmpint(g_signal_connect(installer, "g-properties-changed",
			G_CALLBACK(on_installer_changed), args), !=, 0);
	g_assert_cmpint(g_signal_connect(installer, "completed",
			G_CALLBACK(on_installer_completed), args), !=, 0);

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
	g_assert_cmpstr(variant, ==, "Default Variant");
	bootslot = r_installer_get_boot_slot(installer);
	g_assert_cmpstr(bootslot, ==, "system0");

	r_context();

	bundlepath = g_build_filename(fixture->tmpdir, "bundle.raucb", NULL);
	g_assert_nonnull(bundlepath);

	/* Actually install bundle */
	ret = r_installer_call_install_sync(installer, bundlepath, NULL,
			&error);
	g_assert_no_error(error);
	g_assert_true(ret);

	g_main_loop_run(testloop);

	g_clear_pointer(&installer, g_object_unref);
}

static void service_test_info(ServiceFixture *fixture, gconstpointer user_data)
{
	GError *error = NULL;
	gchar *compatible;
	gchar *version;

	if (!ENABLE_SERVICE) {
		g_test_skip("Test requires RAUC being configured with \"--enable-service\".");
		return;
	}

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
			G_DBUS_PROXY_FLAGS_NONE,
			"de.pengutronix.rauc",
			"/",
			NULL,
			NULL);

	if (installer == NULL) {
		g_error("failed to install proxy");
		goto out;
	}

	r_installer_call_info_sync(installer,
			"test/good-bundle.raucb",
			&compatible,
			&version,
			NULL,
			&error);
	g_assert_no_error(error);
	g_assert_cmpstr(compatible, ==, "Test Config");
	g_assert_cmpstr(version, ==, "2011.03-2");

out:
	g_clear_pointer(&installer, g_object_unref);
	g_free(compatible);
	g_free(version);
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
			NULL);

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
	g_assert_cmpint(g_variant_n_children(slot_status_array), ==, 5);

out:
	g_clear_pointer(&installer, g_object_unref);
	g_variant_unref(slot_status_array);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/service/install", ServiceFixture, NULL,
			service_install_fixture_set_up, service_test_install,
			service_fixture_tear_down);

	g_test_add("/service/info", ServiceFixture, NULL,
			service_info_fixture_set_up, service_test_info,
			service_fixture_tear_down);

	g_test_add("/service/slot-status", ServiceFixture, NULL,
			service_info_fixture_set_up, service_test_slot_status,
			service_fixture_tear_down);

	return g_test_run();
}
