#include <locale.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include "update_handler.h"
#include "common.h"
#include "context.h"

typedef struct {
	gchar *tmpdir;
} BootRawFallbackFixture;

#define BIT(nr) (1UL << (nr))
typedef enum {
	OPT_NONE                      = 0,
	OPT_EXPECT_FAIL               = BIT(0),
	OPT_PRE_INSTALL_PRIMARY_HEAD  = BIT(1),
	OPT_PRE_INSTALL_PRIMARY_IMG   = BIT(2),
	OPT_PRE_INSTALL_FALLBACK_HEAD = BIT(3),
	OPT_PRE_INSTALL_FALLBACK_IMG  = BIT(4),
	OPT_DUMMY_FILL_PRIMARY        = BIT(5),
	OPT_DUMMY_FILL_FALLBACK       = BIT(6),
} BootRawFallbackOptions;

typedef struct {
	BootRawFallbackOptions options;

	GQuark err_domain;
	gint err_code;

	gsize image_size;
	guint64 region_start;
	guint64 region_size;
} BootRawFallbackData;

static gboolean process_file(const gchar *filepath,
		gsize offset,
		gsize size,
		gchar fill,
		gboolean random,
		gboolean compare)
{
	GError *error = NULL;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFileIOStream) stream = NULL;
	g_autofree gchar *buf = NULL;
	g_autofree gchar *cmp_buf = NULL;
	const gsize buf_size = 4096;
	g_autoptr(GRand) rand = g_rand_new_with_seed(31415);
	gboolean res;

	file = g_file_new_for_path(filepath);
	stream = g_file_open_readwrite(file, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(stream);

	res = g_seekable_seek(G_SEEKABLE(stream), offset, G_SEEK_SET, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	buf = g_malloc(buf_size);
	memset(buf, fill, buf_size);

	if (compare)
		cmp_buf = g_malloc(buf_size);

	while (size) {
		gsize bytes_to_process = size < buf_size ? size : buf_size;
		gsize bytes_processed;

		if (random) {
			for (gsize i = 0; i < bytes_to_process; i++)
				buf[i] = g_rand_int(rand);
		}

		if (compare) {
			res = g_input_stream_read_all(g_io_stream_get_input_stream(G_IO_STREAM(stream)),
					cmp_buf,
					bytes_to_process,
					&bytes_processed,
					NULL,
					&error);

			if (memcmp(buf, cmp_buf, bytes_processed)) {
				return FALSE;
			}
		} else {
			res = g_output_stream_write_all(g_io_stream_get_output_stream(G_IO_STREAM(stream)),
					buf,
					bytes_to_process,
					&bytes_processed,
					NULL,
					&error);
		}
		g_assert_no_error(error);
		g_assert_true(res);

		size -= bytes_processed;
	}
	return TRUE;
}

static gboolean fill_file(const gchar *filepath,
		gsize offset,
		gsize size,
		gchar fill,
		gboolean random)
{
	return process_file(filepath, offset, size, fill, random, FALSE);
}

static gboolean compare_file(const gchar *filepath,
		gsize offset,
		gsize size,
		gchar fill,
		gboolean random)
{
	return process_file(filepath, offset, size, fill, random, TRUE);
}

static void boot_raw_fallback_fixture_set_up(BootRawFallbackFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
}

static void boot_raw_fallback_fixture_tear_down(BootRawFallbackFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static RaucImage *create_source_image(const gchar *dirname,
		const gchar *imagename,
		gsize size)
{
	RaucImage *image;
	g_autofree gchar *imagepath = g_build_filename(dirname, imagename, NULL);

	image = r_new_image();
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup(imagepath);
	image->checksum.size = size;
	image->checksum.digest = g_strdup("0xdeadbeef");
	image->type = g_strdup("raw");

	g_assert(test_prepare_dummy_file(dirname, imagename, size, "/dev/zero") == 0);

	fill_file(imagepath, 0, size, 0x00, TRUE);

	return image;
}

static void test_boot_raw_fallback(BootRawFallbackFixture *fixture,
		gconstpointer user_data)
{
	BootRawFallbackData *data = (BootRawFallbackData *) user_data;
	gchar *slotpath, *mountprefix, *hookpath = NULL;
	gsize slot_size;
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	GError *ierror = NULL;
	gboolean res = FALSE;
	const gsize sector_size = 512;
	gsize header_size;

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* prepare slot */
	slotpath = g_strdup(g_getenv("RAUC_TEST_BLOCK_LOOP"));
	if (!slotpath) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	slot_size = get_file_size(slotpath, &ierror);
	g_assert_no_error(ierror);
	g_assert(slot_size != 0);

	fill_file(slotpath, 0, slot_size, 0x00, FALSE);

	header_size = sector_size;
	if (data->image_size < header_size)
		header_size = data->image_size;

	/* pre-install parts of primary location */
	if (data->options & OPT_PRE_INSTALL_PRIMARY_HEAD)
		g_assert_true(fill_file(slotpath, data->region_start, header_size, 0x00, TRUE));

	if (data->options & OPT_PRE_INSTALL_PRIMARY_IMG) {
		g_assert_true(fill_file(slotpath, data->region_start, data->image_size, 0x00, TRUE));
		if (!(data->options & OPT_PRE_INSTALL_PRIMARY_HEAD))
			g_assert_true(fill_file(slotpath, data->region_start, header_size, 0x00, FALSE));
	}

	/* pre-install parts of fallback location */
	if (data->options & OPT_PRE_INSTALL_FALLBACK_HEAD)
		g_assert_true(fill_file(slotpath, data->region_start + (data->region_size / 2), header_size, 0x00, TRUE));

	if (data->options & OPT_PRE_INSTALL_FALLBACK_IMG) {
		g_assert_true(fill_file(slotpath, data->region_start + (data->region_size / 2), data->image_size, 0x00, TRUE));
		if (!(data->options & OPT_PRE_INSTALL_FALLBACK_HEAD))
			g_assert_true(fill_file(slotpath, data->region_start + (data->region_size / 2), data->image_size, 0x00, FALSE));
	}

	/* pre-fill primary partition with dummy data */
	if (data->options & OPT_DUMMY_FILL_PRIMARY)
		g_assert_true(fill_file(slotpath, data->region_start, (data->region_size / 2), 0xAA, FALSE));

	/* pre-fill fallback location with dummy data */
	if (data->options & OPT_DUMMY_FILL_FALLBACK)
		g_assert_true(fill_file(slotpath, data->region_start + (data->region_size / 2), (data->region_size / 2), 0xAA, FALSE));

	image = create_source_image(fixture->tmpdir, "image.img", data->image_size);
	g_assert_nonnull(image);

	/* create target slot */
	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_intern_string("bootloader.0");
	targetslot->sclass = g_intern_string("bootloader");
	targetslot->device = g_strdup(slotpath);
	targetslot->type = g_strdup("boot-raw-fallback");
	targetslot->region_start = data->region_start;
	targetslot->region_size = data->region_size;
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

	/* Monitor if the images are updated in the correct order */
	if (!(data->options & OPT_EXPECT_FAIL)) {
		const gchar *names[] = { "primary", "fallback" };
		gint index = 0;

		if (data->options & (OPT_PRE_INSTALL_PRIMARY_HEAD | OPT_DUMMY_FILL_PRIMARY))
			index++;

		for (gint i = 0; i < 2; i++) {
			gchar *msg;
			msg = g_strdup_printf("Updating %s partition at*", names[index % 2]);
			g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, msg);
			g_free(msg);
			index++;
		}
	}

	/* Run to perform an update */
	res = handler(image, targetslot, hookpath, &ierror);

	if (data->options & OPT_EXPECT_FAIL) {
		g_assert_error(ierror, data->err_domain, data->err_code);
		g_clear_error(&ierror);
		g_assert_false(res);
		goto out;
	} else {
		g_assert_no_error(ierror);
		g_assert_true(res);
	}

	g_test_assert_expected_messages();

	/* Check if the area before the primary image is untouched */
	g_assert_true(compare_file(slotpath,
			0,
			data->region_start,
			0x00,
			FALSE));

	/* Verify primary image */
	g_assert_true(compare_file(slotpath,
			data->region_start,
			data->image_size,
			0x00,
			TRUE));

	/* Verify that the gap between the primary and fallback image is untouched */
	g_assert_true(compare_file(slotpath,
			data->region_start + data->image_size,
			(data->region_size / 2) - data->image_size,
			0x00,
			FALSE));

	/* Verify fallback image */
	g_assert_true(compare_file(slotpath,
			data->region_start + (data->region_size / 2),
			data->image_size,
			0x00,
			TRUE));

	/* Check if the area after the fallback partition is untouched */
	g_assert_true(compare_file(slotpath,
			data->region_start + (data->region_size / 2) + data->image_size,
			slot_size - (data->region_start + (data->region_size / 2) + data->image_size),
			0x00,
			FALSE));

out:
	g_assert(g_remove(image->filename) == 0);

	g_rmdir(mountprefix);

	g_free(slotpath);
	g_clear_pointer(&hookpath, g_free);
	g_free(mountprefix);
	r_free_image(image);
	r_slot_free(targetslot);
}

#define R_QUOTE(...) #__VA_ARGS__
int main(int argc, char *argv[])
{
	BootRawFallbackData *data;

	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	/* Standard scenario - fully programmed and valid slot */
	data = &(BootRawFallbackData) {
		.options = OPT_PRE_INSTALL_PRIMARY_HEAD | OPT_PRE_INSTALL_PRIMARY_IMG | OPT_PRE_INSTALL_FALLBACK_HEAD | OPT_PRE_INSTALL_FALLBACK_IMG,
		.err_domain = 0,
		.err_code = 0,
		.image_size = (1 * 1024 * 1024),
		.region_start = (0 * 1024 * 1024),
		.region_size = (4 * 1024 * 1024),
	};
	g_test_add("/boot_raw_fallback/all-valid",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Interrupted scenario - primary header missing but fallback header and image valid */
	data = &(BootRawFallbackData) {
		.options = OPT_PRE_INSTALL_PRIMARY_IMG | OPT_PRE_INSTALL_FALLBACK_HEAD | OPT_PRE_INSTALL_FALLBACK_IMG,
		.err_domain = 0,
		.err_code = 0,
		.image_size = (1 * 1024 * 1024),
		.region_start = (0 * 1024 * 1024),
		.region_size = (4 * 1024 * 1024),
	};
	g_test_add("/boot_raw_fallback/primary-header-missing",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Basic test on complete blank slot */
	data = &(BootRawFallbackData) {
		.options = OPT_NONE,
		.err_domain = 0,
		.err_code = 0,
		.image_size = (1 * 1024 * 1024),
		.region_start = (0 * 1024 * 1024),
		.region_size = (4 * 1024 * 1024),
	};
	g_test_add("/boot_raw_fallback/all-blank",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Basic test on pre-filled (not cleared) partitions */
	data = &(BootRawFallbackData) {
		.options = OPT_DUMMY_FILL_PRIMARY | OPT_DUMMY_FILL_FALLBACK,
		.err_domain = 0,
		.err_code = 0,
		.image_size = (1 * 1024 * 1024),
		.region_start = (0 * 1024 * 1024),
		.region_size = (4 * 1024 * 1024),
	};
	g_test_add("/boot_raw_fallback/prefilled-partitions",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Image smaller than sector size */
	data = &(BootRawFallbackData) {
		.options = OPT_NONE,
		.err_domain = 0,
		.err_code = 0,
		.image_size = (16),
		.region_start = (0 * 1024),
		.region_size = (2 * 1024),
	};
	g_test_add("/boot_raw_fallback/small-image",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Image larger than available size */
	data = &(BootRawFallbackData) {
		.options = OPT_EXPECT_FAIL,
		.err_domain = R_UPDATE_ERROR,
		.err_code = R_UPDATE_ERROR_FAILED,
		.image_size = (3 *  1024),
		.region_start = (0 * 1024),
		.region_size = (4 * 1024),
	};
	g_test_add("/boot_raw_fallback/image-too-big",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Unaligned region start */
	data = &(BootRawFallbackData) {
		.options = OPT_EXPECT_FAIL,
		.err_domain = R_UPDATE_ERROR,
		.err_code = R_UPDATE_ERROR_FAILED,
		.image_size = (1 *  1024),
		.region_start = (0 * 1024) + 2,
		.region_size = (4 * 1024),
	};
	g_test_add("/boot_raw_fallback/unaligned-region-start",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	/* Unaligned region size */
	data = &(BootRawFallbackData) {
		.options = OPT_EXPECT_FAIL,
		.err_domain = R_UPDATE_ERROR,
		.err_code = R_UPDATE_ERROR_FAILED,
		.image_size = (1 *  1024),
		.region_start = (0 * 1024),
		.region_size = (4 * 1024) + 2,
	};
	g_test_add("/boot_raw_fallback/unaligned-region-size",
			BootRawFallbackFixture,
			data,
			boot_raw_fallback_fixture_set_up,
			test_boot_raw_fallback,
			boot_raw_fallback_fixture_tear_down);

	return g_test_run();
}
