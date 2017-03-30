#pragma once

#include <glib.h>

#define SLOT_SIZE (10*1024*1024)

typedef struct {
	gchar *tmpdir;
} InstallFixture;

void set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data,
		const gchar* manifest_content,
		gboolean handler,
		gboolean hook);

void install_fixture_set_up(InstallFixture *fixture,
		gconstpointer user_data);

void install_fixture_set_up_user(InstallFixture *fixture,
		gconstpointer user_data);
