#pragma once

#include <glib.h>

#define SLOT_SIZE (10*1024*1024)

typedef struct {
	gchar *tmpdir;
} InstallFixture;

void fixture_helper_set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data,
		const gchar* manifest_content,
		gboolean handler,
		gboolean hook);

void fixture_helper_set_up_system(InstallFixture *fixture,
		gconstpointer user_data);

void fixture_helper_fixture_set_up_system_user(InstallFixture *fixture,
		gconstpointer user_data);
