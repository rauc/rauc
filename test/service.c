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

typedef struct {
	GTestDBus *dbus;
} ServiceFixture;

static void service_fixture_set_up(ServiceFixture *fixture, gconstpointer user_data)
{
	fixture->dbus = g_test_dbus_new(G_TEST_DBUS_NONE);
	g_test_dbus_add_service_dir(fixture->dbus, TEST_SERVICES);
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
}

static void on_installer_completed(GDBusProxy *proxy, gint result,
                                   gpointer data)
{
}

static void service_test_status(ServiceFixture *fixture, gconstpointer user_data)
{
	RInstaller *installer = NULL;

	installer = r_installer_proxy_new_for_bus_sync(G_BUS_TYPE_SESSION,
		G_DBUS_PROXY_FLAGS_GET_INVALIDATED_PROPERTIES,
		"de.pengutronix.rauc", "/", NULL, NULL);
	if (g_signal_connect(installer, "g-properties-changed",
			     G_CALLBACK(on_installer_changed), NULL) <= 0) {
		g_error("failed to connect properties-changed signal");
		goto out;
	}
	if (g_signal_connect(installer, "completed",
			     G_CALLBACK(on_installer_completed), NULL) <= 0) {
		g_error("failed to connect completed signal");
		goto out;
	}
out:
	g_clear_pointer(&installer, g_object_unref);
}

static void service_test_info(ServiceFixture *fixture, gconstpointer user_data)
{
	RInstaller *installer = NULL;
	GError *error = NULL;
	gchar *compatible;
	gchar *version;

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

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/service/status", ServiceFixture, NULL,
		   service_fixture_set_up, service_test_status,
		   service_fixture_tear_down);

	g_test_add("/service/info", ServiceFixture, NULL,
		   service_fixture_set_up, service_test_info,
		   service_fixture_tear_down);

	return g_test_run();
}
