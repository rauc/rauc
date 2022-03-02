#pragma once

#include <stdlib.h>
#include <stdint.h>

/**
 * Creates a dm-verity hash (tree)
 *
 * @param fd file descriptor (FD) of file to create verity hash tree for
 * @param data_blocks number of data blocks (of size 4096 bytes)
 * @param combined_blocks return location for number of combined blocks (data+hash) (of size 4096 bytes)
 * @param root_hash return location for calculated root hash
 * @param salt used for creation / verification
 *
 * @return 0 on success, error code otherwise
 */
int r_verity_hash_create(
		int fd,
		uint64_t data_blocks,
		uint64_t *combined_blocks,
		uint8_t *root_hash,
		const uint8_t *salt);

/**
 * Verifies a dm-verity hash (tree)
 *
 * @param fd file descriptor (FD) of file to verify
 * @param data_blocks number of data blocks (of size 4096 bytes)
 * @param root_hash root hash to verify against
 * @param salt used for creation / verification
 *
 * @return 0 on success, error code otherwise
 */
int r_verity_hash_verify(
		int fd,
		uint64_t data_blocks,
		uint8_t *root_hash,
		const uint8_t *salt);
