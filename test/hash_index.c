#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "context.h"
#include "hash_index.h"
#include "stats.h"
#include "utils.h"

#include "common.h"

typedef struct {
	gchar *tmpdir;
} Fixture;

static void fixture_set_up(Fixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);
	g_test_message("hash_index tmpdir: %s\n", fixture->tmpdir);
}

static void fixture_tear_down(Fixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
}

static void test_basic(Fixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(RaucHashIndex) index = NULL;
	g_autofree RaucHashIndexChunk *chunk = g_new0(RaucHashIndexChunk, 1);
	g_autofree gchar *hashes_filename = NULL;
	g_autofree guint8 *hash = NULL;
	gboolean res = FALSE;
	int datafd = -1;
	guint32 tmp_u32 = 0;

	datafd = g_open("test/dummy.verity", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(datafd, >, 0);

	// open and calculate hash index
	index = r_hash_index_open("test", datafd, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(index);
	datafd = -1; /* belongs to index now */
	(void)datafd; /* ignore dead store */

	g_assert_cmpuint(index->count, ==, 132);
	g_assert_nonnull(index->hashes);
	g_assert_nonnull(index->lookup);
	// everything should be valid
	g_assert_cmpuint(index->invalid_from, ==, G_MAXUINT32);
	g_assert_cmpuint(index->invalid_below, ==, 0);

	// save hash index
	hashes_filename = g_build_filename(fixture->tmpdir, "hashes", NULL);
	g_assert_nonnull(hashes_filename);
	g_assert_false(g_file_test(hashes_filename, G_FILE_TEST_IS_REGULAR));

	res = r_hash_index_export(index, hashes_filename, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_true(g_file_test(hashes_filename, G_FILE_TEST_IS_REGULAR));

	// chunk 0
	hash = r_hex_decode("ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0, ==, GUINT32_FROM_BE(tmp_u32));
	g_clear_pointer(&hash, g_free);

	// chunk 1
	hash = r_hex_decode("d4df50ce982e30f82228d5d69096b6fd6875b921fd6bf64c7d9d4d9e7d785d0a", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(1, ==, GUINT32_FROM_BE(tmp_u32));
	g_clear_pointer(&hash, g_free);

	// chunk 4
	hash = r_hex_decode("9573e6bd3320b3c85ef09743583ed1af87aa479bff046b32762f935b8ffd5ee8", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(4, ==, GUINT32_FROM_BE(tmp_u32));
	g_clear_pointer(&hash, g_free);

	// chunk 64
	hash = r_hex_decode("8dbe6bea5b329593e33668434e9ff515f49215dd88d1e923ef3e04d9b25fa2f1", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(64, ==, GUINT32_FROM_BE(tmp_u32));
	g_clear_pointer(&hash, g_free);

	// chunk 131
	hash = r_hex_decode("4a136f4f52f4403771a09f695b91c139a98898a64a6b5e8fffd3cc26edd095e0", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0xf94b2aeb, ==, GUINT32_FROM_BE(tmp_u32));
	g_clear_pointer(&hash, g_free);

	// not in file
	hash = r_hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_NOT_FOUND);
	g_assert_false(res);
	g_clear_pointer(&hash, g_free);
	g_clear_error(&error);

	// TODO check error detection
}

static void test_ranges(Fixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(RaucHashIndex) index = NULL;
	g_autofree RaucHashIndexChunk *chunk = g_new0(RaucHashIndexChunk, 1);
	g_autofree gchar *data_filename = NULL;
	g_autofree guint8 *hash = NULL;
	gboolean res = FALSE;
	int templatefd = -1, datafd = -1;
	guint32 tmp_u32 = 0;

	templatefd = g_open("test/dummy.verity", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(templatefd, >, 0);

	data_filename = write_random_file(fixture->tmpdir, "data.img", 4096*64, 0xf56ce6bf);
	g_assert_nonnull(data_filename);

	datafd = g_open(data_filename, O_RDWR|O_CLOEXEC, 0);
	g_assert_cmpint(datafd, >, 0);

	// force chunks 0 and 16 to ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
	g_assert_true(r_pread_exact(templatefd, chunk->data, 4096, 0*4096, NULL));
	g_assert_cmpint(lseek(datafd, 0*4096, SEEK_SET), ==, 0*4096);
	g_assert_true(r_write_exact(datafd, chunk->data, 4096, NULL));
	g_assert_cmpint(lseek(datafd, 16*4096, SEEK_SET), ==, 16*4096);
	g_assert_true(r_write_exact(datafd, chunk->data, 4096, NULL));

	// force chunk 4 to 9573e6bd3320b3c85ef09743583ed1af87aa479bff046b32762f935b8ffd5ee8
	g_assert_true(r_pread_exact(templatefd, chunk->data, 4096, 4*4096, NULL));
	g_assert_cmpint(lseek(datafd, 4*4096, SEEK_SET), ==, 4*4096);
	g_assert_true(r_write_exact(datafd, chunk->data, 4096, NULL));

	// open and calculate hash index
	index = r_hash_index_open("test", datafd, NULL, &error);
	g_assert_no_error(error);
	g_assert_nonnull(index);
	// keep datafd valid to let us modify it concurrently

	// overwrite chunk 4 (9573e6bd3320b3c85ef09743583ed1af87aa479bff046b32762f935b8ffd5ee8)
	memset(chunk->data, 0xff, 4096);
	g_assert_cmpint(lseek(datafd, 4*4096, SEEK_SET), ==, 4*4096);
	g_assert_true(r_write_exact(datafd, chunk->data, 4096, NULL));

	g_assert_true(g_close(templatefd, NULL));

	g_assert_cmpuint(index->count, ==, 64);
	g_assert_nonnull(index->hashes);
	g_assert_nonnull(index->lookup);
	// everything should be valid
	g_assert_cmpuint(index->invalid_from, ==, G_MAXUINT32);
	g_assert_cmpuint(index->invalid_below, ==, 0);

	// check chunk 0
	hash = r_hex_decode("ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0, ==, GUINT32_FROM_BE(tmp_u32));

	// nothing in range
	index->invalid_from = 0;
	index->invalid_below = 0;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_NOT_FOUND);
	g_assert_false(res);
	g_clear_error(&error);

	// should be found at chunk 0 again
	index->invalid_from = 1;
	index->invalid_below = 0;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0, ==, GUINT32_FROM_BE(tmp_u32));

	// should be found at chunk 16
	index->invalid_from = 17;
	index->invalid_below = 16;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0, ==, GUINT32_FROM_BE(tmp_u32));

	// nothing in range
	index->invalid_from = 16;
	index->invalid_below = 1;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_NOT_FOUND);
	g_assert_false(res);
	g_clear_error(&error);

	// nothing in range
	index->invalid_from = G_MAXUINT;
	index->invalid_below = 17;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_NOT_FOUND);
	g_assert_false(res);
	g_clear_error(&error);

	g_clear_pointer(&hash, g_free);

	// try to find overwritten chunk 4
	index->invalid_from = G_MAXUINT;
	index->invalid_below = 0;
	hash = r_hex_decode("9573e6bd3320b3c85ef09743583ed1af87aa479bff046b32762f935b8ffd5ee8", 32);
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_MODIFIED);
	g_assert_false(res);
	g_clear_error(&error);
	g_clear_pointer(&hash, g_free);

	// overwrite chunk 0 (ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7)
	memset(chunk->data, 0xff, 4096);
	g_assert_cmpint(lseek(datafd, 0*4096, SEEK_SET), ==, 0*4096);
	g_assert_true(r_write_exact(datafd, chunk->data, 4096, NULL));

	// try to find first copy of ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
	hash = r_hex_decode("ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7", 32);

	// we'll find chunk 0, but it's modified
	index->invalid_from = G_MAXUINT;
	index->invalid_below = 0;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_MODIFIED);
	g_assert_false(res);
	g_clear_error(&error);

	// chunk 16 is excluded
	index->invalid_from = 1;
	index->invalid_below = 0;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_MODIFIED);
	g_assert_false(res);
	g_clear_error(&error);

	// try to find second copy of ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
	// exclude modified chunk
	index->invalid_from = G_MAXUINT;
	index->invalid_below = 1;
	res = r_hash_index_get_chunk(index, hash, chunk, &error);
	g_assert_true(res);
	g_assert_cmpmem(hash, 32, chunk->hash, 32);
	memcpy(&tmp_u32, chunk->data, sizeof(tmp_u32));
	g_assert_cmphex(0, ==, GUINT32_FROM_BE(tmp_u32));

	g_clear_pointer(&hash, g_free);
}

/* Tests error handling when opening hash index for a file size that is not a
 * multiple of 4096 */
static void test_invalid_size(Fixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	g_autoptr(RaucHashIndex) index = NULL;
	int datafd = -1;

	g_autofree gchar *data_filename = write_random_file(fixture->tmpdir, "broken.img", 2048*63, 0xf56ce6bf);
	g_assert_nonnull(data_filename);

	datafd = g_open(data_filename, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(datafd, >, 0);

	// open and calculate hash index
	index = r_hash_index_open("test", datafd, NULL, &error);
	g_assert_error(error, R_HASH_INDEX_ERROR, R_HASH_INDEX_ERROR_SIZE);
	g_assert_null(index);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	r_context_conf();
	r_context();

	g_test_add("/hash_index/basic", Fixture, NULL, fixture_set_up, test_basic, fixture_tear_down);
	g_test_add("/hash_index/ranges", Fixture, NULL, fixture_set_up, test_ranges, fixture_tear_down);
	g_test_add("/hash_index/invalid-size", Fixture, NULL, fixture_set_up, test_invalid_size, fixture_tear_down);

	return g_test_run();
}
