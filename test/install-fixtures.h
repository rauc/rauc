#pragma once

#include <glib.h>

#define SLOT_SIZE (10*1024*1024)

typedef struct {
	gchar *tmpdir;
} InstallFixture;

/**
 * Fixture helper to create a bundle for testing.
 *
 * @param fixture the test fixture
 * @param user_data the test fixture user data
 * @param manifest_content String containing the entire manifest
 * @param handler If true, the custom handler script
 *        test/install-content/custom_handler.sh will be added to the bundle
 * @param hook If true, the hook script
 *        test/install-content/hook.sh will be added to the bundle
 */
void fixture_helper_set_up_bundle(InstallFixture *fixture,
		gconstpointer user_data,
		const gchar* manifest_content,
		gboolean handler,
		gboolean hook);

/**
 * Fixture helper to set up a fake target system for testing.
 *
 * The same as fixture_helper_fixture_set_up_system_user() with user-writable
 * slots and a mounted pseudo-active slot.
 *
 * @param fixture the test fixture
 * @param user_data the test fixture user data
 */
void fixture_helper_set_up_system(InstallFixture *fixture,
		gconstpointer user_data);

/**
 * Fixture helper to set up a fake target system for testing.
 *
 * @param fixture the test fixture
 * @param user_data the test fixture user data
 */
void fixture_helper_fixture_set_up_system_user(InstallFixture *fixture,
		gconstpointer user_data);
