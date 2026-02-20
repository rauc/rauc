#include <locale.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <json-glib/json-glib.h>

#include "update_handler.h"
#include "manifest.h"
#include "common.h"
#include "context.h"
#include "mount.h"

typedef struct {
	gchar *tmpdir;
} BootSwitchFixture;

#define BIT(nr) (1UL << (nr))
typedef enum {
	BOOT_SWITCH_DEFAULT       = 0,
	BOOT_SWITCH_EXPECT_FAIL   = BIT(0),
	BOOT_SWITCH_MBR           = BIT(1),
	BOOT_SWITCH_GPT           = BIT(2),
	BOOT_SWITCH_WRITE_FIRST   = BIT(3),
	BOOT_SWITCH_WRITE_SECOND  = BIT(4),
} BootSwitchTestParams;

typedef struct {
	// whether test is expected to be successful
	BootSwitchTestParams params;
	GQuark err_domain;
	gint err_code;

	// slot type to test
	const gchar *slottype;

	// sfdisk dump for setup
	const gchar *sfdisk_setup;

	// sfdisk json to check against
	const gchar *sfdisk_expect;
} BootSwitchData;

#define IMAGE_SIZE (1*1024*1024)

// from 1MiB to 7MiB (2*3MiB)
#define REGION_START (1024*1024*1)
#define REGION_SIZE (1024*1024*6)

#define PART_SIZE (REGION_SIZE/2)
#define PART_A_START (REGION_START)
#define PART_B_START (REGION_START + PART_SIZE)

static gchar *sfdisk_get(const gchar *device)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *error = NULL;
	g_autofree gchar *stdout_buf = NULL;
	gboolean res = FALSE;

	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_PIPE,
			&error,
			"sfdisk",
			"--json",
			device,
			NULL);
	g_assert_no_error(error);
	g_assert_nonnull(sub);

	res = g_subprocess_communicate_utf8(sub, NULL, NULL, &stdout_buf, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_subprocess_wait_check(sub, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	return g_steal_pointer(&stdout_buf);
}

static void sfdisk_check(const gchar *device, const gchar *expected)
{
	g_autofree gchar *found = sfdisk_get(device);
	g_autoptr(JsonNode) j_expected = NULL;
	g_autoptr(JsonNode) j_found = NULL;
	gboolean equal;
	GError *error = NULL;
	JsonObject *document, *partitiontable;
	JsonArray *partitions;

	j_expected = json_from_string(expected, &error);
	g_assert_no_error(error);
	g_assert_nonnull(j_expected);

	j_found = json_from_string(found, &error);
	g_assert_no_error(error);
	g_assert_nonnull(j_found);

	document = json_node_get_object(j_found);
	g_assert_nonnull(document);
	partitiontable = json_object_get_object_member(document, "partitiontable");
	g_assert_nonnull(partitiontable);

	/* versions of libfdisk/util-linux since 2.35 have a sectorsize member */
	if (json_object_has_member(partitiontable, "sectorsize")) {
		guint64 sectorsize = json_object_get_int_member(partitiontable, "sectorsize");
		g_assert_cmpint(sectorsize, ==, 512);
		json_object_remove_member(partitiontable, "sectorsize");
	}

	/* remove device names before comparison */
	json_object_remove_member(partitiontable, "device");
	partitions = json_object_get_array_member(partitiontable, "partitions");
	g_assert_nonnull(partitions);
	for (guint i = 0; i < json_array_get_length(partitions); i++) {
		JsonObject *partition = json_array_get_object_element(partitions, i);
		json_object_remove_member(partition, "node");
	}

	equal = json_node_equal(j_found, j_expected);
	if (!equal) {
		g_message("not equal:\nfound=%s\nexpected=%s",
				json_to_string(j_found, TRUE),
				json_to_string(j_expected, TRUE));
	}
	g_assert_true(equal);
}

static void sfdisk_set(const gchar *device, const gchar *dump)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *error = NULL;
	g_autoptr(GBytes) stdin_buf = NULL;
	gboolean res = FALSE;

	stdin_buf = g_bytes_new(dump, strlen(dump));

	sub = g_subprocess_new(
			G_SUBPROCESS_FLAGS_STDIN_PIPE,
			&error,
			"sfdisk",
			device,
			NULL);
	g_assert_no_error(error);
	g_assert_nonnull(sub);

	res = g_subprocess_communicate(sub, stdin_buf, NULL, NULL, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_subprocess_wait_check(sub, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);
}

static void swap_marker(const gchar *device, goffset offset, guint64 *marker)
{
	GError *error = NULL;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFileIOStream) stream = NULL;
	guint64 old_marker;
	gboolean res;

	file = g_file_new_for_path(device);
	stream = g_file_open_readwrite(file, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(stream);

	res = g_seekable_seek(G_SEEKABLE(stream), offset, G_SEEK_SET, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_input_stream_read_all(
			g_io_stream_get_input_stream(G_IO_STREAM(stream)),
			&old_marker,
			sizeof(old_marker), NULL, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_seekable_seek(G_SEEKABLE(stream), offset, G_SEEK_SET, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_output_stream_write_all(
			g_io_stream_get_output_stream(G_IO_STREAM(stream)),
			marker, sizeof(*marker), NULL, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	*marker = old_marker;
}

static guint64 get_marker(const gchar *device, goffset offset)
{
	GError *error = NULL;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFileIOStream) stream = NULL;
	guint64 found_marker;
	gboolean res;

	file = g_file_new_for_path(device);
	stream = g_file_open_readwrite(file, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(stream);

	res = g_seekable_seek(G_SEEKABLE(stream), offset, G_SEEK_SET, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = g_input_stream_read_all(
			g_io_stream_get_input_stream(G_IO_STREAM(stream)),
			&found_marker,
			sizeof(found_marker), NULL, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	return found_marker;
}

static void clear_device(const gchar *device)
{
	GError *error = NULL;
	g_autoptr(GFile) file = NULL;
	g_autoptr(GFileIOStream) stream = NULL;
	gchar buf[4096] = {0};
	guint64 size;
	gboolean res;

	file = g_file_new_for_path(device);
	stream = g_file_open_readwrite(file, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(stream);

	res = g_seekable_seek(G_SEEKABLE(stream), 0, G_SEEK_END, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	size = g_seekable_tell(G_SEEKABLE(stream));
	res = g_seekable_seek(G_SEEKABLE(stream), 0, G_SEEK_SET, NULL, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	while (size) {
		gsize bytes_to_write = size < sizeof(buf) ? size : sizeof(buf);
		gsize bytes_written;
		res = g_output_stream_write_all(
				g_io_stream_get_output_stream(G_IO_STREAM(stream)), buf,
				bytes_to_write, &bytes_written, NULL, &error);
		g_assert_no_error(error);
		g_assert_true(res);

		size -= bytes_written;
	}
}

static void boot_switch_fixture_set_up(BootSwitchFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
}

static void boot_switch_fixture_tear_down(BootSwitchFixture *fixture,
		gconstpointer user_data)
{
	if (!fixture->tmpdir)
		return;

	g_assert(test_rmdir(fixture->tmpdir, "") == 0);
	g_free(fixture->tmpdir);
}

static void test_boot_switch(BootSwitchFixture *fixture,
		gconstpointer user_data)
{
	BootSwitchData *data = (BootSwitchData *) user_data;
	g_autofree gchar *slotpath = NULL;
	g_autofree gchar *imagename = NULL;
	g_autofree gchar *imagepath = NULL;
	g_autofree gchar *mountprefix = NULL;
	g_autofree gchar *hookpath = NULL;
	RaucImage *image = NULL;
	RaucSlot *targetslot = NULL;
	img_to_slot_handler handler;
	GError *ierror = NULL;
	gboolean res = FALSE;
	guint64 marker;

	enum {
		M_IMAGE_START = 0x21d5c63ddf5203f3,
		M_PART_A_START = 0x53ab9efa71294261,
		M_PART_A_END = 0x182059db7361c8af,
		M_PART_B_START = 0x242a93c66b47f053,
		M_PART_B_END = 0x1fdc54fe25d81ac5,
	};

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	/* prepare image and slot information */
	imagename = g_strdup("image.img");
	slotpath = g_strdup(g_getenv("RAUC_TEST_BLOCK_LOOP"));
	imagepath = g_build_filename(fixture->tmpdir, imagename, NULL);

	if (!slotpath) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}
	clear_device(slotpath);

	/* create source image */
	image = r_new_image();
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup(imagepath);
	image->checksum.size = IMAGE_SIZE;
	image->checksum.digest = g_strdup("0xdeadbeef");
	image->type = g_strdup("raw");

	g_assert(test_prepare_dummy_file(fixture->tmpdir, imagename,
			IMAGE_SIZE, "/dev/zero") == 0);

	/* create marker in source image */
	marker = M_IMAGE_START;
	swap_marker(imagepath, 0, &marker);
	g_assert_cmphex(marker, ==, 0x0);

	/* create target slot */
	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_intern_string("bootloader.0");
	targetslot->sclass = g_intern_string("bootloader");
	targetslot->device = g_strdup(slotpath);
	targetslot->type = g_strdup(data->slottype);
	targetslot->region_start = REGION_START;
	targetslot->region_size = REGION_SIZE;
	targetslot->state = ST_INACTIVE;

	/* Set mount path to current temp dir */
	mountprefix = g_build_filename(fixture->tmpdir, "testmount", NULL);
	g_assert_nonnull(mountprefix);
	r_context_conf()->mountprefix = mountprefix;
	r_context();
	g_assert(g_mkdir(mountprefix, 0777) == 0);

	/* prepare partitions */
	sfdisk_set(slotpath, data->sfdisk_setup);

	/* prepare marks in block device */
	marker = M_PART_A_START;
	swap_marker(slotpath, PART_A_START, &marker);
	g_assert_cmphex(marker, ==, 0x0);
	marker = M_PART_A_END;
	swap_marker(slotpath, PART_A_START + PART_SIZE - 8, &marker);
	g_assert_cmphex(marker, ==, 0x0);
	marker = M_PART_B_START;
	swap_marker(slotpath, PART_B_START, &marker);
	g_assert_cmphex(marker, ==, 0x0);
	marker = M_PART_B_END;
	swap_marker(slotpath, PART_B_START + PART_SIZE - 8, &marker);
	g_assert_cmphex(marker, ==, 0x0);

	/* get handler for this */
	handler = get_update_handler(image, targetslot, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(handler);

	/* Run to perform an update */
	res = handler(image, targetslot, hookpath, &ierror);

	if (data->params & BOOT_SWITCH_EXPECT_FAIL) {
		g_assert_error(ierror, data->err_domain, data->err_code);
		g_clear_error(&ierror);
		g_assert_false(res);
		goto out;
	} else {
		g_assert_no_error(ierror);
		g_assert_true(res);
	}

	/* check partitions */
	sfdisk_check(slotpath, data->sfdisk_expect);

	/* check marks */
	if (data->params & BOOT_SWITCH_WRITE_FIRST) {
		g_assert_cmphex(get_marker(slotpath, PART_A_START), ==, M_IMAGE_START); /* should contain the image */
		g_assert_cmphex(get_marker(slotpath, PART_A_START + PART_SIZE - 8), ==, 0x0); /* should be cleared */
		g_assert_cmphex(get_marker(slotpath, PART_B_START), ==, M_PART_B_START); /* should not be overwritten */
		g_assert_cmphex(get_marker(slotpath, PART_B_START + PART_SIZE - 8), ==, M_PART_B_END); /* should not be overwritten */
	} else if (data->params & BOOT_SWITCH_WRITE_SECOND) {
		g_assert_cmphex(get_marker(slotpath, PART_A_START), ==, M_PART_A_START); /* should not be overwritten */
		g_assert_cmphex(get_marker(slotpath, PART_A_START + PART_SIZE - 8), ==, M_PART_A_END); /* should not be overwritten */
		g_assert_cmphex(get_marker(slotpath, PART_B_START), ==, M_IMAGE_START); /* should contain the image */
		g_assert_cmphex(get_marker(slotpath, PART_B_START + PART_SIZE - 8), ==, 0x0); /* should be cleared */
	}

out:
	/* clean up source image */
	g_assert(g_remove(imagepath) == 0);

	g_rmdir(mountprefix);

	r_free_image(image);
	r_slot_free(targetslot);
}

#define R_QUOTE(...) #__VA_ARGS__
int main(int argc, char *argv[])
{
	BootSwitchData *data;

	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	data = &(BootSwitchData) {
		.params = BOOT_SWITCH_MBR | BOOT_SWITCH_WRITE_SECOND,
		.err_domain = 0, .err_code = 0,
		.slottype = "boot-mbr-switch",
		.sfdisk_setup =
			"label: dos\n"
			"label-id: 0x8b9e754a\n"
			"unit: sectors\n"
			"\n"
			"start=        2048, size=        6144, type=ef, bootable\n"
			"start=       14336, size=       65536, type=83\n"
			"start=       79872, size=           1, type=5\n"
		,
		.sfdisk_expect = R_QUOTE({
			/* *INDENT-OFF* */
			"partitiontable" : {
				"label" : "dos",
				"id" : "0x8b9e754a",
				"unit" : "sectors",
				"partitions" : [
				{
					"start" : 8192,
					"size" : 6144,
					"type" : "ef",
					"bootable" : true
				},
				{
					"start" : 14336,
					"size" : 65536,
					"type" : "83"
				},
				{
					"start" : 79872,
					"size" : 1,
					"type" : "5"
				}
				]
			}
			/* *INDENT-ON* */
		}),
	};
	g_test_add("/boot_switch/mbr/active-first",
			BootSwitchFixture,
			data,
			boot_switch_fixture_set_up,
			test_boot_switch,
			boot_switch_fixture_tear_down);

	data = &(BootSwitchData) {
		.params = BOOT_SWITCH_MBR | BOOT_SWITCH_WRITE_FIRST,
		.err_domain = 0, .err_code = 0,
		.slottype = "boot-mbr-switch",
		.sfdisk_setup =
			"label: dos\n"
			"label-id: 0x8b9e754a\n"
			"unit: sectors\n"
			"\n"
			"start=        8192, size=        6144, type=ef, bootable\n"
			"start=       14336, size=       65536, type=83\n"
			"start=       79872, size=           1, type=5\n"
			"start=       81920, size=       49152, type=82\n"
		,
		.sfdisk_expect = R_QUOTE({
			/* *INDENT-OFF* */
			"partitiontable" : {
				"label" : "dos",
				"id" : "0x8b9e754a",
				"unit" : "sectors",
				"partitions" : [
				{
					"start" : 2048,
					"size" : 6144,
					"type" : "ef",
					"bootable" : true
				},
				{
					"start" : 14336,
					"size" : 65536,
					"type" : "83"
				},
				{
					"start" : 79872,
					"size" : 1,
					"type" : "5"
				},
				{
					"start" : 81920,
					"size" : 49152,
					"type" : "82"
				}
				]
			}
			/* *INDENT-ON* */
		}),
	};
	g_test_add("/boot_switch/mbr/active-second",
			BootSwitchFixture,
			data,
			boot_switch_fixture_set_up,
			test_boot_switch,
			boot_switch_fixture_tear_down);

#if ENABLE_GPT == 1
	data = &(BootSwitchData) {
		.params = BOOT_SWITCH_GPT | BOOT_SWITCH_WRITE_SECOND,
		.err_domain = 0, .err_code = 0,
		.slottype = "boot-gpt-switch",
		.sfdisk_setup =
			"label: gpt\n"
			"label-id: 823CC890-4129-584D-9BD9-ED291FD87CDA\n"
			"unit: sectors\n"
			"first-lba: 2048\n"
			"last-lba: 131038\n"
			"\n"
			"start=        2048, size=        6144, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=0C25253D-6578-2C47-8C3C-8E03EED3141B\n"
			"start=       14336, size=       65536, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=3C97736F-F91A-F641-BF0D-A8C71DEBABBD\n"
			"start=       79872, size=       32768, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=29836434-34FB-0744-AB30-9BD2F0D7C383\n"
		,
		.sfdisk_expect = R_QUOTE({
			/* *INDENT-OFF* */
			"partitiontable" : {
				"label" : "gpt",
				"id" : "823CC890-4129-584D-9BD9-ED291FD87CDA",
				"unit" : "sectors",
				"firstlba" : 2048,
				"lastlba" : 131038,
				"partitions" : [
				{
					"start" : 8192,
					"size" : 6144,
					"type" : "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
					"uuid" : "0C25253D-6578-2C47-8C3C-8E03EED3141B"
				},
				{
					"start" : 14336,
					"size" : 65536,
					"type" : "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
					"uuid" : "3C97736F-F91A-F641-BF0D-A8C71DEBABBD"
				},
				{
					"start" : 79872,
					"size" : 32768,
					"type" : "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
					"uuid" : "29836434-34FB-0744-AB30-9BD2F0D7C383"
				}
				]
			}
			/* *INDENT-ON* */
		}),
	};
	g_test_add("/boot_switch/gpt/active-first",
			BootSwitchFixture,
			data,
			boot_switch_fixture_set_up,
			test_boot_switch,
			boot_switch_fixture_tear_down);

	data = &(BootSwitchData) {
		.params = BOOT_SWITCH_GPT | BOOT_SWITCH_WRITE_FIRST,
		.err_domain = 0, .err_code = 0,
		.slottype = "boot-gpt-switch",
		.sfdisk_setup =
			"label: gpt\n"
			"label-id: 823CC890-4129-584D-9BD9-ED291FD87CDA\n"
			"unit: sectors\n"
			"first-lba: 2048\n"
			"last-lba: 131038\n"
			"\n"
			"start=        8192, size=        6144, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=0C25253D-6578-2C47-8C3C-8E03EED3141B\n"
			"start=       14336, size=       65536, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=3C97736F-F91A-F641-BF0D-A8C71DEBABBD\n"
			"start=       79872, size=       32768, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, uuid=29836434-34FB-0744-AB30-9BD2F0D7C383\n"
		,
		.sfdisk_expect = R_QUOTE({
			/* *INDENT-OFF* */
			"partitiontable" : {
				"label" : "gpt",
				"id" : "823CC890-4129-584D-9BD9-ED291FD87CDA",
				"unit" : "sectors",
				"firstlba" : 2048,
				"lastlba" : 131038,
				"partitions" : [
				{
					"start" : 2048,
					"size" : 6144,
					"type" : "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
					"uuid" : "0C25253D-6578-2C47-8C3C-8E03EED3141B"
				},
				{
					"start" : 14336,
					"size" : 65536,
					"type" : "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
					"uuid" : "3C97736F-F91A-F641-BF0D-A8C71DEBABBD"
				},
				{
					"start" : 79872,
					"size" : 32768,
					"type" : "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
					"uuid" : "29836434-34FB-0744-AB30-9BD2F0D7C383"
				}
				]
			}
			/* *INDENT-ON* */
		}),
	};
	g_test_add("/boot_switch/gpt/active-second",
			BootSwitchFixture,
			data,
			boot_switch_fixture_set_up,
			test_boot_switch,
			boot_switch_fixture_tear_down);
#endif

	return g_test_run();
}
