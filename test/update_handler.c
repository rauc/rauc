#include <locale.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include "update_handler.h"
#include "manifest.h"
#include "common.h"
#include "context.h"
#include "mount.h"

typedef struct {
	gchar *tmpdir;
} UpdateHandlerFixture;

#define BIT(nr) (1UL << (nr))
typedef enum {
	TEST_UPDATE_HANDLER_DEFAULT       = 0,
	TEST_UPDATE_HANDLER_EXPECT_FAIL   = BIT(0),
	TEST_UPDATE_HANDLER_NO_IMAGE_FILE = BIT(1),
	TEST_UPDATE_HANDLER_NO_TARGET_DEV = BIT(2),
	TEST_UPDATE_HANDLER_HOOKS         = BIT(3),
	TEST_UPDATE_HANDLER_PRE_HOOK      = BIT(4),
	TEST_UPDATE_HANDLER_POST_HOOK     = BIT(5),
	TEST_UPDATE_HANDLER_INSTALL_HOOK  = BIT(6),
	TEST_UPDATE_HANDLER_NO_HOOK_FILE  = BIT(7),
	TEST_UPDATE_HANDLER_HOOK_FAIL     = BIT(8),
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
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair*) user_data;
	GError *ierror = NULL;

	image = g_new0(RaucImage, 1);
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strconcat("rootfs.", test_pair->imagetype, NULL);

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_strdup("rootfs.0");
	targetslot->sclass = g_strdup("rootfs");
	targetslot->device = g_strdup("/dev/null");
	targetslot->type = g_strdup(test_pair->slottype);

	handler = get_update_handler(image, targetslot, &ierror);
	if (test_pair->params & TEST_UPDATE_HANDLER_EXPECT_FAIL) {
		g_assert_error(ierror, R_UPDATE_ERROR, R_UPDATE_ERROR_NO_HANDLER);
		g_assert_null(handler);
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
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	GError *ierror = NULL;

	image = g_new0(RaucImage, 1);
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup("rootfs.custom");
	image->hooks.install = TRUE;

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_strdup("rootfs.0");
	targetslot->sclass = g_strdup("rootfs");
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
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair*) user_data;
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_TARGET_DEV)) {
		g_assert(test_prepare_dummy_file(fixture->tmpdir, "rootfs-0",
				SLOT_SIZE, "/dev/zero") == 0);
		if (g_strcmp0(test_pair->slottype, "ext4") == 0) {
			g_assert(test_make_filesystem(fixture->tmpdir, "rootfs-0"));
		}
	}
}

static void update_handler_fixture_tear_down(UpdateHandlerFixture *fixture,
		gconstpointer user_data)
{
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair*) user_data;
	if (!fixture->tmpdir)
		return;

	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_TARGET_DEV)) {
		g_assert(test_remove(fixture->tmpdir, "rootfs-0") == 0);
	}
	g_assert(test_rmdir(fixture->tmpdir, "") == 0);
}

static gsize get_file_size(gchar* filename, GError **error)
{
	GError *ierror = NULL;
	GFile *file = NULL;
	GFileInputStream *filestream = NULL;
	gsize size = 0;
	gboolean res = FALSE;

	file = g_file_new_for_path(filename);
	filestream = g_file_read(file, NULL, &ierror);
	if (filestream == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to open bundle for reading: ");
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(filestream),
			0, G_SEEK_END, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to seek to end of bundle: ");
		goto out;
	}

	size = g_seekable_tell((GSeekable *)filestream);

out:
	g_clear_object(&filestream);
	g_clear_object(&file);

	return size;
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
	g_clear_pointer(&sproc, g_object_unref);
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

static void test_update_handler(UpdateHandlerFixture *fixture,
		gconstpointer user_data)
{
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair*) user_data;
	gchar *slotpath, *imagename, *imagepath, *mountprefix, *hookpath = NULL;
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	GError *ierror = NULL;
	gboolean res = FALSE;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* prepare image and slot information */
	imagename = g_strconcat("image.", test_pair->imagetype, NULL);
	slotpath = g_build_filename(fixture->tmpdir, "rootfs-0", NULL);
	imagepath = g_build_filename(fixture->tmpdir, imagename, NULL);

	/* create source image */
	image = g_new0(RaucImage, 1);
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup(imagepath);
	image->checksum.size = IMAGE_SIZE;
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
			g_assert_true(write_tmp_file(fixture->tmpdir, "hook.sh", hook_content, NULL));
			test_do_chmod(hookpath);
		}
	}

	if (test_pair->params & TEST_UPDATE_HANDLER_NO_IMAGE_FILE) {
		goto no_image;
	}

	if (g_strcmp0(test_pair->imagetype, "img") == 0) {
		g_assert(test_prepare_dummy_file(fixture->tmpdir, "image.img",
				IMAGE_SIZE, "/dev/zero") == 0);
	} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
		g_assert(test_prepare_dummy_file(fixture->tmpdir, "image.ext4",
				IMAGE_SIZE, "/dev/zero") == 0);
		g_assert(test_make_filesystem(fixture->tmpdir, "image.ext4"));
	} else if (g_strcmp0(test_pair->imagetype, "tar.bz2") == 0) {
		g_assert_true(test_prepare_dummy_archive(fixture->tmpdir, "image.tar.bz2", "testfile.txt"));
	} else {
		g_assert_not_reached();
	}

no_image:
	/* create target slot */
	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_strdup("rootfs.0");
	targetslot->sclass = g_strdup("rootfs");
	targetslot->device = g_strdup(slotpath);
	targetslot->type = g_strdup(test_pair->slottype);
	targetslot->state = ST_INACTIVE;

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
	res = handler(image, targetslot, hookpath, &ierror);

	if (test_pair->params & TEST_UPDATE_HANDLER_EXPECT_FAIL) {
		g_assert_error(ierror, test_pair->err_domain, test_pair->err_code);
		g_assert_false(res);
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
		g_assert_cmpint(get_file_size(imagepath, NULL), ==, IMAGE_SIZE);
	} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
		g_assert_cmpint(get_file_size(imagepath, NULL), ==, IMAGE_SIZE);
		g_assert(test_mount(slotpath, mountprefix));
		g_assert(r_umount(slotpath, NULL));
	} else if (g_strcmp0(test_pair->imagetype, "tar.bz2") == 0) {
		gchar *testpath = g_build_filename(mountprefix, "testfile.txt", NULL);
		g_assert(test_mount(slotpath, mountprefix));
		g_assert_true(g_file_test(testpath, G_FILE_TEST_IS_REGULAR));
		g_assert(r_umount(slotpath, NULL));
		g_free(testpath);
	}

out:
	/* clean up source image if it was generated */
	if (!(test_pair->params & TEST_UPDATE_HANDLER_NO_IMAGE_FILE)) {
		if (g_strcmp0(test_pair->imagetype, "img") == 0) {
			g_assert(g_remove(imagepath) == 0);
		} else if (g_strcmp0(test_pair->imagetype, "ext4") == 0) {
			g_assert(g_remove(imagepath) == 0);
		} else if (g_strcmp0(test_pair->imagetype, "tar.bz2") == 0) {
			g_assert(test_remove(fixture->tmpdir, "image.tar.bz2") == 0);
		}
	}

	/* clean up hook scrip if it was generated */
	if ((test_pair->params & TEST_UPDATE_HANDLER_HOOKS) &&
	    !(test_pair->params & TEST_UPDATE_HANDLER_NO_HOOK_FILE)) {
		g_assert(g_remove(hookpath) == 0);
	}

	g_rmdir(mountprefix);

	g_free(slotpath);
	g_free(imagename);
	g_free(imagepath);
	g_clear_pointer(&hookpath, g_free);
	g_free(mountprefix);
	r_free_image(image);
	r_free_slot(targetslot);
}

int main(int argc, char *argv[])
{
	UpdateHandlerTestPair testpair_matrix[] = {
		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubifs", "tar.bz2", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ubifs", "ext4", TEST_UPDATE_HANDLER_EXPECT_FAIL, 0, 0},

		{"raw", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "img", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_DEFAULT, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 2},
		{"raw", "img", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"raw", "ext4", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_IO_ERROR, G_IO_ERROR_NOT_FOUND},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},
		{"raw", "ext4", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "img", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"raw", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"ext4", "ext4", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{"ext4", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_NO_HOOK_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT},

		/* vfat tests */
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_DEFAULT, 0, 0},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_NO_IMAGE_FILE | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 2},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_NO_TARGET_DEV | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK, 0, 0},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK, 0, 0},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK, 0, 0},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_PRE_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_POST_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},
		{"vfat", "tar.bz2", TEST_UPDATE_HANDLER_HOOKS | TEST_UPDATE_HANDLER_INSTALL_HOOK | TEST_UPDATE_HANDLER_HOOK_FAIL | TEST_UPDATE_HANDLER_EXPECT_FAIL, G_SPAWN_EXIT_ERROR, 1},

		{0}
	};
	setlocale(LC_ALL, "C");

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
	g_test_add("/update_handler/get_handler/tar.bz2_to_ubifs",
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

	return g_test_run();
}
