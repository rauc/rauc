#pragma once

#include <stdlib.h>
#include <stdint.h>

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
int verity_create_or_verify_hash(
		int verify,
		int fd,
		off_t data_blocks,
		off_t *combined_blocks,
		uint8_t *root_hash,
		const uint8_t *salt);
