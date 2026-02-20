#include <locale.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include "update_handler.h"
#include "manifest.h"
#include "common.h"
#include "context.h"
#include "mount.h"
#include "utils.h"
#include "stats.h"

typedef struct {
	gchar *tmpdir;
} UpdateHandlerFixture;

typedef enum {
	TEST_UPDATE_HANDLER_DEFAULT                                       = 0,
	TEST_UPDATE_HANDLER_EXPECT_FAIL                                   = BIT(0),
	TEST_UPDATE_HANDLER_NO_IMAGE_FILE                                 = BIT(1),
	TEST_UPDATE_HANDLER_NO_TARGET_DEV                                 = BIT(2),
	TEST_UPDATE_HANDLER_HOOKS                                         = BIT(3),
	TEST_UPDATE_HANDLER_PRE_HOOK                                      = BIT(4),
	TEST_UPDATE_HANDLER_POST_HOOK                                     = BIT(5),
	TEST_UPDATE_HANDLER_INSTALL_HOOK                                  = BIT(6),
	TEST_UPDATE_HANDLER_NO_HOOK_FILE                                  = BIT(7),
	TEST_UPDATE_HANDLER_HOOK_FAIL                                     = BIT(8),
	TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX                       = BIT(9),
	TEST_UPDATE_HANDLER_IMAGE_TOO_LARGE                               = BIT(10),
} TestUpdateHandlerParams;

typedef struct {
	// slot type to test for (extension)
	const gchar *slottype;
	// image type to test for (extension)
	const gchar *imagetype;
	// whether test is expected to be successful
	TestUpdateHandlerParams params;

	GQuark err_domain;
	gint err_code;
} UpdateHandlerTestPair;

/* Test update_handler/get_handler/<combination>:
 *
 * Allows to test several source image / slot type combinations to either have
 * a valid handler or not */
static void test_get_update_handler(UpdateHandlerFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucImage) image = NULL;
	g_autoptr(RaucSlot) targetslot = NULL;
	img_to_slot_handler handler;
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair *) user_data;
	GError *ierror = NULL;

	image = r_new_image();
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strconcat("rootfs.", test_pair->imagetype, NULL);
	image->type = g_strdup(derive_image_type_from_filename_pattern(image->filename));

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_intern_string("rootfs.0");
	targetslot->sclass = g_intern_string("rootfs");
	targetslot->device = g_strdup("/dev/null");
	targetslot->type = g_strdup(test_pair->slottype);

	handler = get_update_handler(image, targetslot, &ierror);
	if (test_pair->params & TEST_UPDATE_HANDLER_EXPECT_FAIL) {
		g_assert_error(ierror, R_UPDATE_ERROR, R_UPDATE_ERROR_NO_HANDLER);
		g_assert_null(handler);
		g_clear_error(&ierror);
	} else {
		g_assert_no_error(ierror);
		g_assert_nonnull(handler);
	}
}

/* Test update_handler/get_custom_handler:
 *
 * Tests for get_update_handler() returning hook script handler if 'install'
 * hook is registered for image.
 */
static void test_get_custom_update_handler(UpdateHandlerFixture *fixture, gconstpointer user_data)
{
	g_autoptr(RaucImage) image = NULL;
	g_autoptr(RaucSlot) targetslot = NULL;
	img_to_slot_handler handler;
	GError *ierror = NULL;

	image = r_new_image();
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup("rootfs.custom");
	image->hooks.install = TRUE;
	image->type = g_strdup(derive_image_type_from_filename_pattern(image->filename));

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_intern_string("rootfs.0");
	targetslot->sclass = g_intern_string("rootfs");
	targetslot->device = g_strdup("/dev/null");
	targetslot->type = g_strdup("nand");

	handler = get_update_handler(image, targetslot, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(handler);
}

#define SLOT_SIZE (10*1024*1024)
#define IMAGE_SIZE (10*1024*1024)
#define FILE_SIZE (10*1024)

static void update_handler_fixture_set_up(UpdateHandlerFixture *fixture,
		gconstpointer user_data)
{
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair *) user_data;
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_TARGET_DEV)) {
		g_assert(test_prepare_dummy_file(fixture->tmpdir, "rootfs-0",
				SLOT_SIZE, "/dev/zero") == 0);
		if (g_strcmp0(test_pair->slottype, "ext4") == 0) {
			g_assert(test_make_filesystem(fixture->tmpdir, "rootfs-0"));
		}
	}

	if ((test_pair->params & TEST_UPDATE_HANDLER_IMAGE_TOO_LARGE) &&
	    (test_pair->params & TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX)) {
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
				"Checking image type for slot type: *");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
				"Found handler for image type * and slot type *");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
				"Selected adaptive update method *");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
				"Building new hash index for *");
		g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
				"Continuing after adaptive mode error: Slot * is too small for image *");
	}
}

static void update_handler_fixture_tear_down(UpdateHandlerFixture *fixture,
		gconstpointer user_data)
{
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair *) user_data;
	if (!fixture->tmpdir)
		return;

	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_TARGET_DEV)) {
		g_assert(test_remove(fixture->tmpdir, "rootfs-0") == 0);
	}
	if (test_pair->params & TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX) {
		test_rm_tree(fixture->tmpdir, "rootfs-0-datadir");
	}
	g_assert(test_rmdir(fixture->tmpdir, "") == 0);

	g_clear_pointer(&fixture->tmpdir, g_free);

	if (!g_test_failed()) {
		g_test_assert_expected_messages();
	}
}

static gboolean tar_image(const gchar *dest, const gchar *dir, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("cf"));
	g_ptr_array_add(args, g_strdup(dest));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(dir));
	g_ptr_array_add(args, g_strdup("."));
	g_ptr_array_add(args, NULL);

	sproc = g_subprocess_newv((const gchar * const *)args->pdata,
			G_SUBPROCESS_FLAGS_NONE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start tar compress: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run tar compress: ");
		goto out;
	}

out:
	g_ptr_array_unref(args);
	g_clear_object(&sproc);
	return res;
}

static gboolean casync_blob_image(const gchar *idxpath, const gchar *contentpath, const gchar *store, GError **error)
{
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(5, g_free);

	g_ptr_array_add(args, g_strdup("casync"));
	g_ptr_array_add(args, g_strdup("make"));
	g_ptr_array_add(args, g_strdup("--with=unix"));
	g_ptr_array_add(args, g_strdup(idxpath));
	g_ptr_array_add(args, g_strdup(contentpath));
	g_ptr_array_add(args, g_strdup("--store"));
	g_ptr_array_add(args, g_strdup(store));
	g_ptr_array_add(args, NULL);

	sproc = r_subprocess_newv(args, G_SUBPROCESS_FLAGS_STDOUT_SILENCE, &ierror);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start casync: ");
		goto out;
	}

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to run casync: ");
		goto out;
	}

out:
	g_ptr_array_unref(args);
	g_clear_object(&sproc);
	return res;
}

/**
 * Create dummy archive.
 *
 * @path where to build
 * @path destination name
 * @filename name of dummy file in archive
 */
static gboolean test_prepare_dummy_archive(const gchar *path, const gchar *archname, const gchar *filename)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar *archpath = NULL, *contentpath = NULL;

	archpath = g_build_filename(path, archname, NULL);
	contentpath = g_build_filename(path, "content", NULL);

	g_assert(g_mkdir(contentpath, 0777) == 0);
	g_assert(test_prepare_dummy_file(contentpath, filename,
			FILE_SIZE, "/dev/zero") == 0);

	/* tar file to pseudo image */
	res = tar_image(archpath, contentpath, &ierror);
	if (!res) {
		g_warning("%s", ierror->message);
		goto out;
	}

	g_assert(test_remove(contentpath, filename) == 0);
	g_assert(g_rmdir(contentpath) == 0);

	res = TRUE;
out:
	g_clear_pointer(&contentpath, g_free);
	g_clear_pointer(&archpath, g_free);
	return res;
}

static gchar *test_prepare_dummy_caibx(const gchar *path, const gchar *archname)
{
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *idxpath = NULL, *storepath = NULL;
	g_autofree gchar *pathname = NULL;

	idxpath = g_build_filename(path, archname, NULL);
	storepath = g_build_filename(path, "out.castr", NULL);
	pathname = write_random_file(path, "tmp.img", IMAGE_SIZE, 0xe92001ca);
	g_assert_nonnull(pathname);

	if (!casync_blob_image(idxpath, pathname, storepath, &ierror)) {
		g_warning("%s", ierror->message);
		return NULL;
	}

	g_assert(test_remove(path, "tmp.img") == 0);
	return g_steal_pointer(&storepath);
}

static gchar *test_prepare_dummy_caidx(const gchar *path, const gchar *archname)
{
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *idxpath = NULL, *storepath = NULL;
	g_autofree gchar *contentpath = NULL;

	idxpath = g_build_filename(path, archname, NULL);
	storepath = g_build_filename(path, "out.castr", NULL);

	contentpath = g_build_filename(path, "content", NULL);

	g_assert(g_mkdir(contentpath, 0777) == 0);
	g_assert(test_prepare_dummy_file(contentpath, "testfile.txt",
			FILE_SIZE, "/dev/zero") == 0);

	if (!casync_blob_image(idxpath, contentpath, storepath, &ierror)) {
		g_warning("%s", ierror->message);
		return NULL;
	}

	g_assert(test_remove(contentpath, "testfile.txt") == 0);
	g_assert(g_rmdir(contentpath) == 0);
	return g_steal_pointer(&storepath);
}

static void test_update_handler(UpdateHandlerFixture *fixture,
		gconstpointer user_data)
{
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair *) user_data;
	g_autofree gchar *slotpath = NULL;
	g_autofree gchar *imagename = NULL;
	g_autofree gchar *imagepath = NULL;
	g_autofree gchar *mountprefix = NULL;
	g_autofree gchar *hookpath = NULL;
	goffset image_size;
	g_autoptr(RaucImage) image = NULL;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	g_test_message("installing '%s' image to '%s' slot", test_pair->imagetype, test_pair->slottype);

	/* prepare image and slot information */
	image_size = IMAGE_SIZE;
	imagename = g_strconcat("image.", test_pair->imagetype, NULL);
	if (g_strcmp0(test_pair->slottype, "ubivol") == 0 ||
	    g_strcmp0(test_pair->slottype, "ubifs") == 0) {
		slotpath = g_strdup(g_getenv("RAUC_TEST_MTD_UBIVOL"));
		if (!slotpath) {
			g_test_message("no UBI volume for testing found (define RAUC_TEST_MTD_UBIVOL)");
			g_test_skip("RAUC_TEST_MTD_UBIVOL undefined");
			return;
		}
	} else if (g_strcmp0(test_pair->slottype, "nand") == 0) {
		slotpath = g_strdup(g_getenv("RAUC_TEST_MTD_NAND"));
		if (!slotpath) {
			g_test_message("no MTD NAND device for testing found (define RAUC_TEST_MTD_NAND)");
			g_test_skip("RAUC_TEST_MTD_NAND undefined");
			return;
		}
	} else if (g_strcmp0(test_pair->slottype, "nor") == 0) {
		slotpath = g_strdup(g_getenv("RAUC_TEST_MTD_NOR"));
		if (!slotpath) {
			g_test_message("no MTD NOR device for testing found (define RAUC_TEST_MTD_NOR)");
			g_test_skip("RAUC_TEST_MTD_NOR undefined");
			return;
		}
	} else {
		if (test_pair->params & TEST_UPDATE_HANDLER_IMAGE_TOO_LARGE) {
			/* Try to use loop block device for this test. */
			slotpath = g_strdup(g_getenv("RAUC_TEST_BLOCK_LOOP"));
			if (!slotpath) {
				g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
				g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
				return;
			}
			image_size = 65*1024*1024; /* loop dev is only 64 MiB */
		} else {
			slotpath = g_build_filename(fixture->tmpdir, "rootfs-0", NULL);
		}
	}
	imagepath = g_build_filename(fixture->tmpdir, imagename, NULL);

	/* skip casync checks if casync is not available */
	if ((g_strcmp0(test_pair->imagetype, "img.caibx") == 0) || (g_strcmp0(test_pair->imagetype, "caidx") == 0)) {
		if (!g_getenv("RAUC_TEST_CASYNC")) {
			g_test_skip("RAUC_TEST_CASYNC undefined");
			return;
		}
	}

	/* create source image */
	image = r_new_image();
	image->slotclass = g_strdup("rootfs");
	if (g_strcmp0(test_pair->imagetype, "emptyfs") == 0) {
		/* For emptyfs, don't set a filename since no file exists */
		image->filename = NULL;
		image->type = g_strdup("emptyfs");
	} else {
		image->filename = g_strdup(imagepath);
		image->type = g_strdup(derive_image_type_from_filename_pattern(image->filename));
	}
	image->checksum.size = image_size;
	image->checksum.digest = g_strdup("0xdeadbeef");
	if (test_pair->params & TEST_UPDATE_HANDLER_HOOKS) {
		const gchar *hook_content_success = "#!/bin/sh\nexit 0";
		const gchar *hook_content_fail = "#!/bin/sh\nexit 1";
		const gchar *hook_content = (test_pair->params & TEST_UPDATE_HANDLER_HOOK_FAIL) ? hook_content_fail : hook_content_success;
		hookpath = g_build_filename(fixture->tmpdir, "hook.sh", NULL);
		image->hooks.pre_install = (test_pair->params & TEST_UPDATE_HANDLER_PRE_HOOK);
		image->hooks.install = (test_pair->params & TEST_UPDATE_HANDLER_INSTALL_HOOK);
		image->hooks.post_install = (test_pair->params & TEST_UPDATE_HANDLER_POST_HOOK);
		if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_HOOK_FILE)) {
			g_autofree gchar *tmp_filename = NULL;
			tmp_filename = write_tmp_file(fixture->tmpdir, "hook.sh", hook_content, NULL);
			g_assert_nonnull(tmp_filename);
			test_do_chmod(tmp_filename);
		}
	}
	if (test_pair->params & TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX) {
		image->adaptive = g_strsplit("block-hash-index", " ", 0);
	}

	if (test_pair->params & TEST_UPDATE_HANDLER_NO_IMAGE_FILE) {
		goto no_image;
	}

	if (g_strcmp0(test_pair->imagetype, "img") == 0) {
		g_autofree gchar *pathname = write_random_file(fixture->tmpdir, "image.img", image_size, 0x2abff992);
		g_assert_nonnull(pathname);
	} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
		g_assert(test_prepare_dummy_file(fixture->tmpdir, "image.ext4", image_size, "/dev/zero") == 0);
		g_assert(test_make_filesystem(fixture->tmpdir, "image.ext4"));
	} else if (g_strcmp0(test_pair->imagetype, "tar") == 0) {
		g_assert_true(test_prepare_dummy_archive(fixture->tmpdir, "image.tar", "testfile.txt"));
	} else if (g_strcmp0(test_pair->imagetype, "img.caibx") == 0) {
		gchar *storepath = test_prepare_dummy_caibx(fixture->tmpdir, "image.img.caibx");
		g_assert_nonnull(storepath);

		r_context_conf()->install_info->mounted_bundle = g_new0(RaucBundle, 1);
		r_context_conf()->install_info->mounted_bundle->storepath = storepath;
	} else if (g_strcmp0(test_pair->imagetype, "caidx") == 0) {
		gchar *storepath = test_prepare_dummy_caidx(fixture->tmpdir, "image.caidx");
		g_assert_nonnull(storepath);

		r_context_conf()->install_info->mounted_bundle = g_new0(RaucBundle, 1);
		r_context_conf()->install_info->mounted_bundle->storepath = storepath;
	} else if (g_strcmp0(test_pair->imagetype, "emptyfs") != 0) {
		/* No image file is needed emptyfs, so we just want to avoid dropping out here */
		g_assert_not_reached();
	}

no_image:
	/* create target slot */
	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_intern_string("rootfs.0");
	targetslot->sclass = g_intern_string("rootfs");
	targetslot->device = g_strdup(slotpath);
	targetslot->type = g_strdup(test_pair->slottype);
	targetslot->state = ST_INACTIVE;
	if (test_pair->params & TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX) {
		targetslot->data_directory = g_build_filename(fixture->tmpdir, "rootfs-0-datadir", NULL);
	}

	/* Set mount path to current temp dir */
	mountprefix = g_build_filename(fixture->tmpdir, "testmount", NULL);
	g_assert_nonnull(mountprefix);
	r_context_conf()->mountprefix = mountprefix;
	r_context();
	g_assert(g_mkdir(mountprefix, 0777) == 0);

	/* get handler for this */
	handler = get_update_handler(image, targetslot, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(handler);

	/* Run to perform an update */
	r_test_stats_start();
	res = handler(image, targetslot, hookpath, &ierror);
	r_test_stats_stop();

	if (test_pair->params & TEST_UPDATE_HANDLER_EXPECT_FAIL) {
		g_assert_error(ierror, test_pair->err_domain, test_pair->err_code);
		g_assert_false(res);
		g_clear_error(&ierror);
		goto out;
	} else {
		g_assert_no_error(ierror);
		g_assert_true(res);
	}

	/* If the custom update handler ran, skip default write tests */
	if (test_pair->params & TEST_UPDATE_HANDLER_INSTALL_HOOK) {
		goto out;
	}

	/* Sanity check updated slot */
	if (g_strcmp0(test_pair->imagetype, "img") == 0) {
		g_assert_cmpint(get_file_size(imagepath, NULL), ==, image_size);
	} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
		g_assert_cmpint(get_file_size(imagepath, NULL), ==, image_size);
		g_assert(test_mount(slotpath, mountprefix));
		g_assert(r_umount(slotpath, NULL));
	} else if (g_strcmp0(test_pair->imagetype, "emptyfs") == 0) {
		/* Verify emptyfs created an empty ext4 filesystem */
		g_assert(test_mount(slotpath, mountprefix));

		/* Check that only lost+found directory exists (standard for empty ext4) */
		g_autoptr(GDir) dir = NULL;
		GError *dir_error = NULL;
		const gchar *entry;
		gint entry_count = 0;
		gboolean found_lost_found = FALSE;

		dir = g_dir_open(mountprefix, 0, &dir_error);
		g_assert_no_error(dir_error);
		g_assert_nonnull(dir);

		while ((entry = g_dir_read_name(dir)) != NULL) {
			entry_count++;
			if (g_strcmp0(entry, "lost+found") == 0) {
				found_lost_found = TRUE;
			}
		}

		/* Empty ext4 should only contain lost+found directory */
		g_assert_cmpint(entry_count, ==, 1);
		g_assert_true(found_lost_found);

		/* Verify lost+found is empty */
		g_autofree gchar *lost_found_path = g_build_filename(mountprefix, "lost+found", NULL);
		g_autoptr(GDir) lost_found_dir = g_dir_open(lost_found_path, 0, &dir_error);
		g_assert_no_error(dir_error);
		g_assert_nonnull(lost_found_dir);
		g_assert_null(g_dir_read_name(lost_found_dir));

		/* Close directory handles before unmounting */
		g_clear_pointer(&lost_found_dir, g_dir_close);
		g_clear_pointer(&dir, g_dir_close);

		g_assert(r_umount(slotpath, NULL));
	} else if ((g_strcmp0(test_pair->imagetype, "tar") == 0) || ((g_strcmp0(test_pair->imagetype, "caidx") == 0))) {
		g_autofree gchar *testpath = g_build_filename(mountprefix, "testfile.txt", NULL);
		g_assert(test_mount(slotpath, mountprefix));
		g_assert_true(g_file_test(testpath, G_FILE_TEST_IS_REGULAR));
		g_assert(r_umount(slotpath, NULL));
	}

	/* check statistics */
	if (test_pair->params & TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX) {
		RaucStats *stats;
		guint64 count_zero = 0;
		guint64 sum_zero = 0;
		guint64 count_target_written = 0;
		guint64 sum_target_written = 0;
		guint64 count_target = 0;
		guint64 sum_target = 0;
		guint64 count_source = 0;
		guint64 sum_source = 0;

		stats = r_test_stats_next();
		g_assert_nonnull(stats);
		g_assert_cmpstr(stats->label, ==, "zero chunk");
		count_zero = stats->count;
		sum_zero = stats->sum;
		r_stats_free(stats);

		stats = r_test_stats_next();
		g_assert_nonnull(stats);
		g_assert_cmpstr(stats->label, ==, "target_slot_written (reusing source_image)");;
		count_target_written = stats->count;
		sum_target_written = stats->sum;
		r_stats_free(stats);

		stats = r_test_stats_next();
		g_assert_nonnull(stats);
		g_assert_cmpstr(stats->label, ==, "target_slot");
		count_target = stats->count;
		sum_target = stats->sum;
		r_stats_free(stats);

		stats = r_test_stats_next();
		g_assert_nonnull(stats);
		g_assert_cmpstr(stats->label, ==, "source_image");
		count_source = stats->count;
		sum_source = stats->sum;
		r_stats_free(stats);

		/* all non-zero chunks must result in a lookup in target_slot_written */
		g_assert_cmpint(count_zero + count_target_written, ==, IMAGE_SIZE/4096);

		/* sum of all found chunks must equal total number of chunks */
		g_assert_cmpint(sum_zero + sum_target_written + sum_target + sum_source, ==, IMAGE_SIZE/4096);

		if (g_strcmp0(test_pair->imagetype, "img") == 0) {
			/* for random data it is *very* unlikely:
			 * - to find zero chunks
			 * - to find reusable chunks */
			g_assert_cmpint(sum_zero, ==, 0);
			g_assert_cmpint(sum_target_written, ==, 0);
			g_assert_cmpint(sum_target, ==, 0);
			g_assert_cmpint(sum_source, ==, IMAGE_SIZE/4096);
		} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
			/* for a generated ext4, actual values seem to depend on
			 * used mkfs configuration. We use minimal values here
			 * that have proven to be valid on all test systems.
			 */
			g_assert_cmpint(sum_zero, >=, IMAGE_SIZE/4096 - 37);
			g_assert_cmpint(sum_target_written, >=, 0);
			g_assert_cmpint(sum_target, ==, 0);
			g_assert_cmpint(sum_source, <=, 37);
		}

		/* Number of total lookups must not increase in lookup order */
		g_assert_cmpint(count_target_written, <=, IMAGE_SIZE/4096);
		g_assert_cmpint(count_target, <=, count_target_written);
		g_assert_cmpint(count_source, <=, count_target);
	}
	g_assert_null(r_test_stats_next());

out:
	/* clean up source image if it was generated */
	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_IMAGE_FILE)) {
		if (g_strcmp0(test_pair->imagetype, "img") == 0) {
			g_assert(g_remove(imagepath) == 0);
		} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
			g_assert(g_remove(imagepath) == 0);
		} else if (g_strcmp0(test_pair->imagetype, "tar") == 0) {
			g_assert(test_remove(fixture->tmpdir, "image.tar") == 0);
		} else if (g_strcmp0(test_pair->imagetype, "img.caibx") == 0) {
			g_assert(test_remove(fixture->tmpdir, "image.img.caibx") == 0);
			g_assert_true(rm_tree(r_context()->install_info->mounted_bundle->storepath, NULL));
			free_bundle(r_context_conf()->install_info->mounted_bundle);
		} else if (g_strcmp0(test_pair->imagetype, "caidx") == 0) {
			g_assert(test_remove(fixture->tmpdir, "image.caidx") == 0);
			g_assert_true(rm_tree(r_context()->install_info->mounted_bundle->storepath, NULL));
			free_bundle(r_context_conf()->install_info->mounted_bundle);
		}
	}

	/* clean up hook script if it was generated */
	if ((test_pair->params & TEST_UPDATE_HANDLER_HOOKS) &&
	    !(test_pair->params & TEST_UPDATE_HANDLER_NO_HOOK_FILE)) {
		g_assert(g_remove(hookpath) == 0);
	}

	g_assert(g_rmdir(mountprefix) == 0);

	r_slot_free(targetslot);
}

int main(int argc, char *argv[])
{
	UpdateHandlerTestPair testpair_matrix[] = {
		{"ext4", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubifs", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubifs", "ext4", TEST_UPDATE_HANDLER_EXPECT_FAIL, 0, 0},

		{"raw", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		{"ext4", "tar", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"raw", "img", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"raw", "ext4", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},

		{"ext4", "tar", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},
		{"raw", "ext4", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_NO_HOOK_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT},

		/* vfat tests */
		{"vfat", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "tar", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"vfat", "tar", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		/* ubifs tests */
		{"ubifs", "tar", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubifs", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubivol", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		/* nand tests */
		{"nand", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		/* nor tests */
		{"nor", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		/* adaptive tests */
		{"raw", "img", TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX, 0, 0},
		{"ext4", "img", TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX, 0, 0},

		/* casync blob index tests */
		{"ext4", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"raw", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		/* casync directory index tests */
		{"ext4", "caidx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "caidx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		/* image too large */
		{"ext4", "ext4", TEST_UPDATE_HANDLER_IMAGE_TOO_LARGE | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_ADAPTIVE_BLOCK_HASH_IDX | TEST_UPDATE_HANDLER_IMAGE_TOO_LARGE | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},

		{"nor", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"nand", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"jffs2", "img.caibx", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"jffs2", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		/* empty filesystem test (no image included) */
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "emptyfs", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{0}
	};
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	g_test_add("/update_handler/get_handler/tar_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[0],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/ext4_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[1],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/tar_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[2],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/fail/ext4_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[3],
			NULL,
			test_get_update_handler,
			NULL);

	g_test_add("/update_handler/get_custom_handler",
			UpdateHandlerFixture,
			NULL,
			NULL,
			test_get_custom_update_handler,
			NULL);

	g_test_add("/update_handler/update_handler/img_to_raw",
			UpdateHandlerFixture,
			&testpair_matrix[4],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[5],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[6],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw",
			UpdateHandlerFixture,
			&testpair_matrix[7],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/no-image",
			UpdateHandlerFixture,
			&testpair_matrix[8],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/no-image",
			UpdateHandlerFixture,
			&testpair_matrix[9],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/no-image",
			UpdateHandlerFixture,
			&testpair_matrix[10],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/no-image",
			UpdateHandlerFixture,
			&testpair_matrix[11],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[12],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[13],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[14],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[15],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[16],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[17],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[18],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[19],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[20],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[21],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[22],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[23],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[24],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[25],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[26],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[27],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[28],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[29],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[30],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[31],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[32],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[33],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[34],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[35],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/tar_to_ext4/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[36],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_raw/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[37],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_raw/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[38],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/ext4_to_ext4/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[39],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/update_handler/ext4_to_ext4/hooks/no-file",
			UpdateHandlerFixture,
			&testpair_matrix[40],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	/* vfat tests */
	g_test_add("/update_handler/get_handler/tar_to_vfat",
			UpdateHandlerFixture,
			&testpair_matrix[41],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/update_handler/tar_to_vfat",
			UpdateHandlerFixture,
			&testpair_matrix[42],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/no-image",
			UpdateHandlerFixture,
			&testpair_matrix[43],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[44],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[45],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[46],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[47],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[48],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[49],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/tar_to_vfat/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[50],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	/* ubifs tests */
	g_test_add("/update_handler/update_handler/tar_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[51],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[52],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/img_to_ubivol",
			UpdateHandlerFixture,
			&testpair_matrix[53],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	/* nand tests */
	g_test_add("/update_handler/update_handler/img_to_nand",
			UpdateHandlerFixture,
			&testpair_matrix[54],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	/* nor tests */
	g_test_add("/update_handler/update_handler/img_to_nor",
			UpdateHandlerFixture,
			&testpair_matrix[55],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	/* adaptive tests */
	g_test_add("/update_handler/block_hash_index/img_to_raw",
			UpdateHandlerFixture,
			&testpair_matrix[56],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/block_hash_index/img_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[57],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/block_hash_index/ext4_to_raw",
			UpdateHandlerFixture,
			&testpair_matrix[58],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	/* casync blox index tests */
	g_test_add("/update_handler/casync/img.caibx_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[59],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/casync/img.caibx_to_raw",
			UpdateHandlerFixture,
			&testpair_matrix[60],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	/* casync directory index tests */
	g_test_add("/update_handler/casync/caidx_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[61],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	/* FIXME: only works with "--without=sec-time" set for "casync make"*/
	/*
	   g_test_add("/update_handler/casync/caidx_to_vfat",
	                UpdateHandlerFixture,
	                &testpair_matrix[62],
	                update_handler_fixture_set_up,
	                test_update_handler,
	                update_handler_fixture_tear_down);
	 */

	/* too large */
	g_test_add("/update_handler/too_large/normal",
			UpdateHandlerFixture,
			&testpair_matrix[63],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/too_large/adaptive",
			UpdateHandlerFixture,
			&testpair_matrix[64],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	g_test_add("/update_handler/get_handler/img.caibx_to_nor",
			UpdateHandlerFixture,
			&testpair_matrix[65],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/img.caibx_to_nand",
			UpdateHandlerFixture,
			&testpair_matrix[66],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/img.caibx_to_vfat",
			UpdateHandlerFixture,
			&testpair_matrix[67],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/img.caibx_to_jffs2",
			UpdateHandlerFixture,
			&testpair_matrix[68],
			NULL,
			test_get_update_handler,
			NULL);
	g_test_add("/update_handler/get_handler/img_to_jffs2",
			UpdateHandlerFixture,
			&testpair_matrix[69],
			NULL,
			test_get_update_handler,
			NULL);
	/* emptyfs tests */
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/default",
			UpdateHandlerFixture,
			&testpair_matrix[70],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/no-slot",
			UpdateHandlerFixture,
			&testpair_matrix[71],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/pre-hook",
			UpdateHandlerFixture,
			&testpair_matrix[72],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/post-hook",
			UpdateHandlerFixture,
			&testpair_matrix[73],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/install-hook",
			UpdateHandlerFixture,
			&testpair_matrix[74],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/pre-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[75],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/post-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[76],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);
	g_test_add("/update_handler/update_handler/emptyfs_to_ext4/install-hook/fail",
			UpdateHandlerFixture,
			&testpair_matrix[77],
			update_handler_fixture_set_up,
			test_update_handler,
			update_handler_fixture_tear_down);

	return g_test_run();
}
