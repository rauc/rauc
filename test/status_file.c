#include <glib.h>
#include <locale.h>

#include "common.h"
#include "context.h"
#include "config.h"
#include "status_file.h"

typedef struct {
	gchar *tmpdir;
} StatusFileFixture;

static void status_file_fixture_set_up_global(StatusFileFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-conf_file-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	replace_strdup(&r_context_conf()->configpath, "test/test-global.conf");
	r_context();
}

static void status_file_fixture_tear_down(StatusFileFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
	r_context_clean();
}


static void status_file_test_read_slot_status(void)
{
	GError *ierror = NULL;
	gboolean res;
	RaucSlotStatus *ss = g_new0(RaucSlotStatus, 1);
	res = read_slot_status("test/rootfs.raucs", ss, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27");

	r_slot_free_status(ss);
}


static void status_file_test_write_slot_status(void)
{
	RaucSlotStatus *ss = g_new0(RaucSlotStatus, 1);

	ss->status = g_strdup("ok");
	ss->checksum.type = G_CHECKSUM_SHA256;
	ss->checksum.digest = g_strdup("dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	g_assert_true(write_slot_status("test/savedslot.raucs", ss, NULL));

	r_slot_free_status(ss);
	ss = g_new0(RaucSlotStatus, 1);

	g_assert_true(read_slot_status("test/savedslot.raucs", ss, NULL));

	g_assert_nonnull(ss);
	g_assert_cmpstr(ss->status, ==, "ok");
	g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
	g_assert_cmpstr(ss->checksum.digest, ==,
			"dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");

	r_slot_free_status(ss);
}

static void status_file_test_global_slot_status(StatusFileFixture *fixture,
		gconstpointer user_data)
{
	GHashTable *slots = r_context()->config->slots;
	GHashTableIter iter;
	GError *ierror = NULL;
	RaucSlot *slot;
	gboolean res;

	g_assert_nonnull(r_context()->config->statusfile_path);

	/* Set status for all slots */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (slot->status)
			r_slot_free_status(slot->status);

		g_debug("Set default status for slot %s.", slot->name);
		slot->status = g_new0(RaucSlotStatus, 1);
		slot->status->status = g_strdup("ok");
		slot->status->checksum.type = G_CHECKSUM_SHA256;
		slot->status->checksum.digest = g_strdup("dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");
	}

	/* Save status for all slots */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		res = save_slot_status(slot, &ierror);
		g_assert_no_error(ierror);
		g_assert_true(res);
	}

	/* Clear status for all slots */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (slot->status)
			r_slot_free_status(slot->status);

		slot->status = NULL;
	}

	/* Check status for all slots */
	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		load_slot_status(slot);
		g_assert_nonnull(slot->status);
		g_assert_cmpstr(slot->status->status, ==, "ok");
		g_assert_cmpint(slot->status->checksum.type, ==, G_CHECKSUM_SHA256);
		g_assert_cmpstr(slot->status->checksum.digest, ==,
				"dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551");
	}
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/status-file/read-slot-status", status_file_test_read_slot_status);
	g_test_add_func("/status-file/write-read-slot-status", status_file_test_write_slot_status);
	g_test_add("/status-file/global-slot-staus", StatusFileFixture, NULL,
			status_file_fixture_set_up_global, status_file_test_global_slot_status,
			status_file_fixture_tear_down);

	return g_test_run();
}
