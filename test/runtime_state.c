#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <runtime_state.h>
#include <slot.h>

typedef struct {
	gchar *tmpdir;
	gchar *path;
} RuntimeStateFixture;

static void runtime_state_fixture_set_up(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-runtime-state-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	fixture->path = g_build_filename(fixture->tmpdir, "runtime-state.conf", NULL);
}

static void runtime_state_fixture_tear_down(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	r_runtime_state_cleanup();

	if (fixture->path)
		g_unlink(fixture->path);
	g_autofree gchar *broken = g_strconcat(fixture->path, ".broken", NULL);
	g_unlink(broken);

	g_rmdir(fixture->tmpdir);
	g_clear_pointer(&fixture->tmpdir, g_free);
	g_clear_pointer(&fixture->path, g_free);
}

static RaucSlot *make_slot(const gchar *name)
{
	RaucSlot *slot = g_new0(RaucSlot, 1);
	slot->name = g_intern_string(name);
	return slot;
}

static void runtime_state_test_init_missing(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	GError *ierror = NULL;
	g_autoptr(RaucSlot) slot = make_slot("rootfs.0");
	g_autofree gchar *value = NULL;

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);

	g_assert_false(r_runtime_state_slot_get(slot, "any-key", &value));
	g_assert_null(value);
}

static void runtime_state_test_set_get(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	GError *ierror = NULL;
	g_autoptr(RaucSlot) slot = make_slot("rootfs.0");
	g_autofree gchar *value = NULL;

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);

	r_runtime_state_slot_set(slot, "good-region", "primary");

	g_assert_true(r_runtime_state_slot_get(slot, "good-region", &value));
	g_assert_cmpstr(value, ==, "primary");
}

static void runtime_state_test_commit_persistence(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	GError *ierror = NULL;
	g_autoptr(RaucSlot) slot = make_slot("bootloader.0");
	g_autofree gchar *value = NULL;

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);
	r_runtime_state_slot_set(slot, "good-region", "secondary");
	g_assert_true(r_runtime_state_commit(&ierror));
	g_assert_no_error(ierror);
	g_assert_true(g_file_test(fixture->path, G_FILE_TEST_EXISTS));

	r_runtime_state_cleanup();

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);
	g_assert_true(r_runtime_state_slot_get(slot, "good-region", &value));
	g_assert_cmpstr(value, ==, "secondary");
}

static void runtime_state_test_set_null_removes(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	GError *ierror = NULL;
	g_autoptr(RaucSlot) slot = make_slot("rootfs.0");
	g_autofree gchar *value = NULL;

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);
	r_runtime_state_slot_set(slot, "good-region", "primary");
	g_assert_true(r_runtime_state_slot_get(slot, "good-region", &value));
	g_clear_pointer(&value, g_free);

	r_runtime_state_slot_set(slot, "good-region", NULL);
	g_assert_false(r_runtime_state_slot_get(slot, "good-region", &value));
	g_assert_null(value);
}

static void runtime_state_test_corrupt_file(RuntimeStateFixture *fixture, gconstpointer user_data)
{
	GError *ierror = NULL;
	g_autoptr(RaucSlot) slot = make_slot("rootfs.0");
	g_autofree gchar *value = NULL;
	g_autofree gchar *broken = g_strconcat(fixture->path, ".broken", NULL);

	g_assert_true(g_file_set_contents(fixture->path, "this is not a keyfile\n", -1, NULL));

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Failed to load runtime state*");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
			"Will move runtime state file*");

	g_assert_true(r_runtime_state_init(fixture->path, &ierror));
	g_assert_no_error(ierror);

	g_test_assert_expected_messages();

	g_assert_true(g_file_test(broken, G_FILE_TEST_EXISTS));
	g_assert_false(g_file_test(fixture->path, G_FILE_TEST_EXISTS));

	g_assert_false(r_runtime_state_slot_get(slot, "good-region", &value));
	g_assert_null(value);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/runtime-state/init-missing", RuntimeStateFixture, NULL,
			runtime_state_fixture_set_up,
			runtime_state_test_init_missing,
			runtime_state_fixture_tear_down);
	g_test_add("/runtime-state/set-get", RuntimeStateFixture, NULL,
			runtime_state_fixture_set_up,
			runtime_state_test_set_get,
			runtime_state_fixture_tear_down);
	g_test_add("/runtime-state/commit-persistence", RuntimeStateFixture, NULL,
			runtime_state_fixture_set_up,
			runtime_state_test_commit_persistence,
			runtime_state_fixture_tear_down);
	g_test_add("/runtime-state/set-null-removes", RuntimeStateFixture, NULL,
			runtime_state_fixture_set_up,
			runtime_state_test_set_null_removes,
			runtime_state_fixture_tear_down);
	g_test_add("/runtime-state/corrupt-file", RuntimeStateFixture, NULL,
			runtime_state_fixture_set_up,
			runtime_state_test_corrupt_file,
			runtime_state_fixture_tear_down);

	return g_test_run();
}
