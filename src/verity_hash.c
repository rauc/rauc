/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <glib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "verity_hash.h"

#define VERITY_MAX_LEVELS	63

const size_t data_block_size = 4096;
const size_t hash_block_size = 4096;
const size_t digest_size = 32; /* sha256 */
const size_t salt_size = 32;

static unsigned get_bits_up(size_t u)
{
	unsigned i = 0;
	while ((1U << i) < u)
		i++;
	return i;
}

static unsigned get_bits_down(size_t u)
{
	unsigned i = 0;
	while ((u >> i) > 1U)
		i++;
	return i;
}

static int verify_zero(FILE *wr, size_t bytes)
{
	uint8_t block[bytes];
	size_t i;

	if (fread(block, bytes, 1, wr) != 1) {
		g_debug("EIO while reading spare area.");
		return -EIO;
	}
	for (i = 0; i < bytes; i++)
		if (block[i]) {
			g_message("Spare area is not zeroed at position %" PRIu64 ".",
					ftello(wr) - bytes);
			return -EPERM;
		}
	return 0;
}

static int verify_hash_block(
		uint8_t *hash,
		const uint8_t *data,
		const uint8_t *salt)
{
	/* SHA256, version 1 only */
	EVP_MD_CTX *mdctx;
	uint8_t tmp[EVP_MAX_MD_SIZE];
	unsigned int tmp_size = 0;
	int r = 0;

	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit(mdctx, EVP_sha256()) != 1) {
		g_message("init failed");
		r = -EINVAL;
		goto out;
	}

	if (EVP_DigestUpdate(mdctx, salt, salt_size) != 1) {
		g_message("salt update failed");
		r = -EINVAL;
		goto out;
	}

	if (EVP_DigestUpdate(mdctx, data, data_block_size) != 1) {
		g_message("data update failed");
		r = -EINVAL;
		goto out;
	}

	if (EVP_DigestFinal(mdctx, tmp, &tmp_size) != 1) {
		g_message("final failed");
		r = -EINVAL;
		goto out;
	}

	g_assert(tmp_size == digest_size);

	memcpy(hash, tmp, digest_size);

out:
	if (r)
		ERR_print_errors_fp(stderr);
	EVP_MD_CTX_free(mdctx);
	return r;
}

static gboolean uint64_mult_overflow(uint64_t *u, uint64_t b, size_t size)
{
	*u = (uint64_t)b * size;
	if ((uint64_t)(*u / size) != b)
		return TRUE;
	return FALSE;
}

static int hash_levels(
		uint64_t data_file_blocks, uint64_t *hash_position, int *levels,
		uint64_t *hash_level_block, uint64_t *hash_level_size)
{
	size_t hash_per_block_bits;
	uint64_t s, s_shift;
	int i;

	if (!digest_size)
		return -EINVAL;

	hash_per_block_bits = get_bits_down(hash_block_size / digest_size);
	if (!hash_per_block_bits)
		return -EINVAL;

	*levels = 0;
	while (hash_per_block_bits * *levels < 64 &&
	       (data_file_blocks - 1) >> (hash_per_block_bits * *levels))
		(*levels)++;

	if (*levels > VERITY_MAX_LEVELS)
		return -EINVAL;

	for (i = *levels - 1; i >= 0; i--) {
		if (hash_level_block)
			hash_level_block[i] = *hash_position;
		// verity position of block data_file_blocks at level i
		s_shift = (i + 1) * hash_per_block_bits;
		if (s_shift > 63)
			return -EINVAL;
		s = (data_file_blocks + ((uint64_t)1 << s_shift) - 1) >> ((i + 1) * hash_per_block_bits);
		if (hash_level_size)
			hash_level_size[i] = s;
		if ((*hash_position + s) < *hash_position)
			return -EINVAL;
		*hash_position += s;
	}

	return 0;
}

static int create_or_verify(FILE *rd, FILE *wr,
		uint64_t data_block,
		uint64_t hash_block,
		uint64_t blocks,
		int verify,
		uint8_t *calculated_digest,
		const uint8_t *salt)
{
	uint8_t left_block[hash_block_size];
	uint8_t data_buffer[data_block_size];
	uint8_t read_digest[digest_size];
	size_t hash_per_block = 1 << get_bits_down(hash_block_size / digest_size);
	size_t digest_size_full = 1 << get_bits_up(digest_size);
	uint64_t blocks_to_write = (blocks + hash_per_block - 1) / hash_per_block;
	uint64_t seek_rd, seek_wr;
	size_t left_bytes;
	unsigned i;
	int r;

	if (uint64_mult_overflow(&seek_rd, data_block, data_block_size) ||
	    uint64_mult_overflow(&seek_wr, hash_block, hash_block_size)) {
		g_message("Device offset overflow.");
		return -EINVAL;
	}

	if (fseeko(rd, seek_rd, SEEK_SET)) {
		g_debug("Cannot seek to requested position in data device.");
		return -EIO;
	}

	if (wr && fseeko(wr, seek_wr, SEEK_SET)) {
		g_debug("Cannot seek to requested position in hash device.");
		return -EIO;
	}

	memset(left_block, 0, hash_block_size);
	while (blocks_to_write--) {
		left_bytes = hash_block_size;
		for (i = 0; i < hash_per_block; i++) {
			if (!blocks)
				break;
			blocks--;
			if (fread(data_buffer, data_block_size, 1, rd) != 1) {
				g_debug("Cannot read data device block.");
				return -EIO;
			}

			if (verify_hash_block(
					calculated_digest,
					data_buffer,
					salt))
				return -EINVAL;

			if (!wr)
				break;
			if (verify) {
				if (fread(read_digest, digest_size, 1, wr) != 1) {
					g_debug("Cannot read digest from hash device.");
					return -EIO;
				}
				if (memcmp(read_digest, calculated_digest, digest_size)) {
					g_message("Verification failed at position %" PRIu64 ".",
							ftello(rd) - data_block_size);
					return -EPERM;
				}
			} else {
				if (fwrite(calculated_digest, digest_size, 1, wr) != 1) {
					g_debug("Cannot write digest to hash device.");
					return -EIO;
				}
			}
			{ /* version 1 */
				if (digest_size_full - digest_size) {
					if (verify) {
						r = verify_zero(wr, digest_size_full - digest_size);
						if (r)
							return r;
					} else if (fwrite(left_block, digest_size_full - digest_size, 1, wr) != 1) {
						g_debug("Cannot write spare area to hash device.");
						return -EIO;
					}
				}
				left_bytes -= digest_size_full;
			}
		}
		if (wr && left_bytes) {
			if (verify) {
				r = verify_zero(wr, left_bytes);
				if (r)
					return r;
			} else if (fwrite(left_block, left_bytes, 1, wr) != 1) {
				g_debug("Cannot write remaining spare area to hash device.");
				return -EIO;
			}
		}
	}

	return 0;
}

/*
 * Verifies or creates a dm-verity hash (tree)
 *
 * @param verify 0 -> create hash, 1 -> verify hash
 * @param fd file descriptor (FD) of file to create verity hash tree for (verify=0) or FD of file to verify (verify=1)
 * @param data_blocks number of data blocks (of size 4096 bytes)
 * @param combined_blocks return location for number of combined blocks (data+hash) (of size 4096 bytes) (verify=0) or NULL for verification (verify=1)
 * @param root_hash return location for calculated root hash (verify=0) or root hash to verify against (verify=1)
 * @param salt used for creation / verification
 *
 * @return 0 on success, error code otherwise
 */
static int verity_create_or_verify_hash(
		int verify,
		int fd,
		uint64_t data_blocks,
		uint64_t *combined_blocks,
		uint8_t *root_hash,
		const uint8_t *salt)
{
	g_autofree gchar *file = NULL;
	uint64_t hash_position = data_blocks;
	uint8_t calculated_digest[digest_size];
	FILE *data_file = NULL;
	FILE *hash_file = NULL, *hash_file_2;
	uint64_t hash_level_block[VERITY_MAX_LEVELS];
	uint64_t hash_level_size[VERITY_MAX_LEVELS];
	uint64_t data_device_size = 0, hash_device_size = 0;
	int levels, i, r;

	g_debug("Hash %s %s, data blocks %" PRIu64 ".",
			verify ? "verification" : "creation", "SHA256",
			data_blocks);

	if (uint64_mult_overflow(&data_device_size, data_blocks, data_block_size)) {
		g_message("Device offset overflow.");
		return -EINVAL;
	}

	if (hash_levels(data_blocks, &hash_position,
			&levels, &hash_level_block[0], &hash_level_size[0])) {
		g_message("Hash area overflow.");
		return -EINVAL;
	}

	g_debug("Using %d hash levels.", levels);

	if (uint64_mult_overflow(&hash_device_size, hash_position, hash_block_size)) {
		g_message("Device offset overflow.");
		return -EINVAL;
	}
	if (combined_blocks)
		*combined_blocks = hash_position;

	file = g_strdup_printf("/proc/self/fd/%d", fd);

	g_debug("Data size: %" PRIu64 " bytes.",
			data_device_size);
	data_file = fopen(file, "r");
	if (!data_file) {
		g_message("Cannot open file %s.",
				file
				);
		r = -EIO;
		goto out;
	}

	g_debug("Hashed size: %" PRIu64 " bytes.",
			hash_device_size);
	hash_file = fopen(file, verify ? "r" : "r+");
	if (!hash_file) {
		g_message("Cannot open file %s.",
				file);
		r = -EIO;
		goto out;
	}

	memset(calculated_digest, 0, digest_size);

	for (i = 0; i < levels; i++) {
		if (!i) {
			r = create_or_verify(data_file, hash_file,
					0,
					hash_level_block[i],
					data_blocks, verify,
					calculated_digest, salt);
			if (r)
				goto out;
		} else {
			hash_file_2 = fopen(file, "r");
			if (!hash_file_2) {
				g_message("Cannot open device %s.",
						file);
				r = -EIO;
				goto out;
			}
			r = create_or_verify(hash_file_2, hash_file,
					hash_level_block[i - 1],
					hash_level_block[i],
					hash_level_size[i - 1], verify,
					calculated_digest, salt);
			fclose(hash_file_2);
			if (r)
				goto out;
		}
	}

	if (levels)
		r = create_or_verify(hash_file, NULL,
				hash_level_block[levels - 1],
				0,
				1, verify,
				calculated_digest, salt);
	else
		r = create_or_verify(data_file, NULL,
				0,
				0,
				data_blocks, verify,
				calculated_digest, salt);
out:
	if (verify) {
		if (r)
			g_message("Verification of data area failed.");
		else {
			g_debug("Verification of data area succeeded.");
			r = memcmp(root_hash, calculated_digest, digest_size) ? -EPERM : 0;
			if (r)
				g_message("Verification of root hash failed.");
			else
				g_debug("Verification of root hash succeeded.");
		}
	} else {
		if (r == -EIO)
			g_message("Input/output error while creating hash area.");
		else if (r)
			g_message("Creation of hash area failed.");
		else {
			memcpy(root_hash, calculated_digest, digest_size);
		}
	}

	if (data_file)
		fclose(data_file);
	if (hash_file)
		fclose(hash_file);
	return r;
}

int r_verity_hash_create(
		int fd,
		uint64_t data_blocks,
		uint64_t *combined_blocks,
		uint8_t *root_hash,
		const uint8_t *salt)
{
	return verity_create_or_verify_hash(0, fd, data_blocks, combined_blocks, root_hash, salt);
}

int r_verity_hash_verify(
		int fd,
		uint64_t data_blocks,
		uint8_t *root_hash,
		const uint8_t *salt)
{
	return verity_create_or_verify_hash(1, fd, data_blocks, NULL, root_hash, salt);
}
