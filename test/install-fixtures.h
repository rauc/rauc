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
 * @param manifest_content String containing the entire manifest
 * @param handler If true, the custom handler script
 *        test/install-content/custom_handler.sh will be added to the bundle
 * @param hook If true, the hook script
 *        test/install-content/hook.sh will be added to the bundle
 */
void fixture_helper_set_up_bundle(gchar *tmpdir,
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
 * @param configname the system.conf template to use or NULL for default
 */
void fixture_helper_set_up_system(gchar *tmpdir,
		const gchar *configname);

/**
 * Fixture helper to set up a fake target system for testing.
 *
 * @param fixture the test fixture
 * @param user_data the test fixture user data
 * @param configname the system.conf template to use or NULL for default
 */
void fixture_helper_fixture_set_up_system_user(gchar *tmpdir,
		const gchar *configname);
