#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>
#include <hash_index.h>

#include "fuzz.h"

#define FUZZ_SHA256_LEN 32
#define FUZZ_MAX_CHUNKS 128
#define FUZZ_MAX_HASHES (256*FUZZ_SHA256_LEN)

/*
 * Fuzzes the block-hash-index handling in hash_index.c.
 *
 * The hash index file shipped inside a bundle image (or read back from a
 * slot's data directory) is attacker-controlled data: it is parsed into a
 * chunk table, sorted into a lookup array and binary-searched during
 * adaptive updates. The harness drives:
 *
 *   - r_hash_index_open() with a fuzzed index file (header validation,
 *     short-index handling, lookup table construction)
 *   - r_hash_index_open() without an index file (fresh hashing path)
 *   - r_hash_index_reuse() on the same data
 *   - r_hash_index_get_chunk() probes for present, absent, and
 *     out-of-valid-range hashes, including the modified-chunk re-hash check
 *   - r_hash_index_export() of the parsed index and re-opening of the
 *     exported index file
 *
 * Input layout: [0] unused, [1..4] LE32 chunk count, [5..] index bytes.
 * The data file is filled from the input so that both the fresh-hashing
 * and the lookup paths operate on fuzzed content.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *dataname = NULL;
	g_autofree gchar *hashesname = NULL;
	g_autofree gchar *exportname = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GChecksum) checksum = NULL;
	guint8 probe_hash[FUZZ_SHA256_LEN];
	gsize hashlen = sizeof(probe_hash);
	gchar *buf = NULL;
	int data_fd = -1;
	gboolean ready = FALSE;

	fuzz_set_logging_func();

	/* hash_file() consults r_context() for progress reporting while
	 * building a fresh index; make sure the context exists (default
	 * configuration, no target setup) before using the index API. */
	(void)r_context_conf();
	(void)r_context();

	if (size < 6)
		return 0;

	tmpdir = g_dir_make_tmp("rauc-fuzz-XXXXXX", NULL);
	if (!tmpdir)
		return 0;

	dataname = g_build_filename(tmpdir, "data.img", NULL);
	hashesname = g_build_filename(tmpdir, "block-hash-index", NULL);
	exportname = g_build_filename(tmpdir, "exported-index", NULL);
	if (!dataname || !hashesname || !exportname)
		goto out;

	/* data file: chunk count from input, bounded, filled from input bytes */
	guint32 chunks = (guint32)data[1] | ((guint32)data[2] << 8) |
		((guint32)data[3] << 16) | ((guint32)data[4] << 24);
	chunks = chunks % FUZZ_MAX_CHUNKS + 1;
	gsize data_size = (gsize)chunks * 4096;

	buf = g_malloc(data_size);
	for (gsize i = 0; i < data_size; i++)
		buf[i] = (gchar)(data[(i + 5) % size]);

	if (!g_file_set_contents(dataname, buf, data_size, NULL))
		goto out;

	/* hash index file: the remaining input */
	gsize hashes_size = size - 5;
	if (hashes_size > FUZZ_MAX_HASHES)
		hashes_size = FUZZ_MAX_HASHES;
	if (!g_file_set_contents(hashesname, (const gchar *)data + 5, hashes_size, NULL))
		goto out;

	/* hash of the first data chunk (for the 'found' probe below) */
	checksum = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(checksum, (const guchar *)buf, 4096);
	g_checksum_get_digest(checksum, probe_hash, &hashlen);
	ready = TRUE;

	data_fd = g_open(dataname, O_RDONLY);
	if (data_fd < 0)
		goto out;

	/* open with the fuzzed index file */
	{
		g_autoptr(RaucHashIndex) idx = r_hash_index_open("fuzz-index", data_fd, hashesname, &error);
		g_clear_error(&error);

		if (idx) {
			RaucHashIndexChunk chunk;
			g_autoptr(GChecksum) probe = NULL;
			gsize probelen = sizeof(probe_hash);

			/* probe with the hashes of several data chunks (present
			 * hits at different positions of the binary search) */
			guint nprobes = chunks < 4 ? chunks : 4;
			for (guint p = 0; p < nprobes; p++) {
				probe = g_checksum_new(G_CHECKSUM_SHA256);
				g_checksum_update(probe, (const guchar *)buf + (gsize)p * 4096, 4096);
				g_checksum_get_digest(probe, probe_hash, &probelen);
				g_checksum_free(probe);
				probe = NULL;

				memset(&chunk, 0, sizeof(chunk));
				(void)r_hash_index_get_chunk(idx, probe_hash, &chunk, &error);
				g_clear_error(&error);

				/* same probe with the re-hash check skipped */
				idx->skip_hash_check = TRUE;
				(void)r_hash_index_get_chunk(idx, probe_hash, &chunk, &error);
				g_clear_error(&error);
				idx->skip_hash_check = FALSE;

				/* probe with the valid range restricted (invalid-region path) */
				idx->invalid_below = 0;
				idx->invalid_from = p + 1;
				(void)r_hash_index_get_chunk(idx, probe_hash, &chunk, &error);
				g_clear_error(&error);
			}
			idx->invalid_below = 0;
			idx->invalid_from = G_MAXUINT32;

			/* probe with an index-supplied hash (usually absent) */
			if (hashes_size >= FUZZ_SHA256_LEN) {
				memset(&chunk, 0, sizeof(chunk));
				(void)r_hash_index_get_chunk(idx, (const guint8 *)data + 5, &chunk, &error);
				g_clear_error(&error);
			}

			(void)r_hash_index_export(idx, exportname, &error);
			g_clear_error(&error);
		}
	}

	/* re-open the exported index (parse our own output again) */
	if (g_file_test(exportname, G_FILE_TEST_IS_REGULAR)) {
		g_autoptr(RaucHashIndex) idx = r_hash_index_open("fuzz-exported", data_fd, exportname, &error);
		g_clear_error(&error);

		if (idx) {
			RaucHashIndexChunk chunk;
			memset(&chunk, 0, sizeof(chunk));
			(void)r_hash_index_get_chunk(idx, probe_hash, &chunk, &error);
			g_clear_error(&error);
		}
	}

	/* open without an index file (fresh hashing path), then reuse it */
	{
		g_autoptr(RaucHashIndex) idx = NULL;
		g_autoptr(RaucHashIndex) reused = NULL;

		lseek(data_fd, 0, SEEK_SET);
		idx = r_hash_index_open("fuzz-fresh", data_fd, NULL, &error);
		g_clear_error(&error);

		if (idx) {
			lseek(data_fd, 0, SEEK_SET);
			reused = r_hash_index_reuse("fuzz-reuse", idx, data_fd, &error);
			g_clear_error(&error);
		}
	}

	close(data_fd);
	data_fd = -1;

out:
	if (data_fd >= 0)
		close(data_fd);
	if (ready) {
		g_remove(exportname);
		g_remove(hashesname);
		g_remove(dataname);
	}
	g_free(buf);
	g_remove(tmpdir);

	return 0;
}
