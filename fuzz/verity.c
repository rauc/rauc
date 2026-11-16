#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <verity_hash.h>

#include "fuzz.h"

/* keep the runtime bounded: at most 64 data blocks (256 KiB) per run */
#define FUZZ_DIGEST_SIZE 32
#define FUZZ_MAX_BLOCKS 64

/*
 * Fuzzes the dm-verity hash tree verification in verity_hash.c.
 *
 * For 'verity' bundles, rauc verifies the bundle payload against a
 * dm-verity hash tree whose parameters (block count, root hash, salt)
 * come from the manifest - i.e. from potentially attacker-influenced
 * data. The verification code walks attacker-sized tree structures with
 * 64-bit offset arithmetic (uint64_mult_overflow, hash_levels), which is
 * a prime spot for integer-overflow and OOB bugs.
 *
 * Input layout:
 *   [0]      op: bit0 = 0: verify with fuzzed root hash
 *                     1: create -> verify round-trip (bit1: corrupt root)
 *   [1..8]   LE64 data block count (bounded to FUZZ_MAX_BLOCKS)
 *   [9..40]  root hash
 *   [41..72] salt
 *   [73..]   data content
 *
 * The round-trip mode builds a correct tree with r_verity_hash_create()
 * and then verifies both the intact and a corrupted root, exercising the
 * deep success and failure paths of the tree walk.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *dataname = NULL;
	int fd = -1;

	fuzz_set_logging_func();

	if (size < 73)
		return 0;

	uint8_t op = data[0];
	uint64_t blocks = 0;
	for (unsigned i = 0; i < 8; i++)
		blocks |= (uint64_t)data[1 + i] << (8 * i);
	blocks = blocks % FUZZ_MAX_BLOCKS + 1;
	const uint8_t *root = data + 9;
	const uint8_t *salt = data + 41;
	gsize data_size = (gsize)blocks * 4096;

	tmpdir = g_dir_make_tmp("rauc-fuzz-XXXXXX", NULL);
	if (!tmpdir)
		return 0;

	dataname = g_build_filename(tmpdir, "payload.img", NULL);
	if (!dataname)
		goto out;

	{
		gchar *buf = g_malloc(data_size);
		for (gsize i = 0; i < data_size; i++)
			buf[i] = (gchar)(data[(i + 73) % size]);
		gboolean written = g_file_set_contents(dataname, buf, data_size, NULL);
		g_free(buf);
		if (!written)
			goto out;
	}

	fd = g_open(dataname, O_RDWR);
	if (fd < 0)
		goto out;

	if (op & 0x01) {
		/* create -> verify round-trip */
		uint64_t combined = 0;
		uint8_t calc[FUZZ_DIGEST_SIZE];

		if (r_verity_hash_create(fd, blocks, &combined, calc, salt) == 0) {
			/* intact root must verify */
			(void)r_verity_hash_verify(fd, blocks, calc, salt);

			/* corrupted root must fail */
			if (op & 0x02)
				calc[0] ^= 0x01;
			else
				calc[FUZZ_DIGEST_SIZE - 1] ^= 0x80;
			(void)r_verity_hash_verify(fd, blocks, calc, salt);
		}
	} else {
		/* verify against the fuzzed root hash */
		uint8_t rootfuzz[FUZZ_DIGEST_SIZE];

		memcpy(rootfuzz, root, FUZZ_DIGEST_SIZE);
		(void)r_verity_hash_verify(fd, blocks, rootfuzz, salt);
	}

	close(fd);
	fd = -1;

out:
	if (fd >= 0)
		close(fd);
	if (dataname) {
		g_remove(dataname);
	}
	g_remove(tmpdir);

	return 0;
}
