#pragma once

#include <glib.h>

typedef enum {
	R_CHECKSUM_ERROR_FAILED = 0,
	R_CHECKSUM_ERROR_SIZE_MISMATCH,
	R_CHECKSUM_ERROR_DIGEST_MISMATCH,
} RChecksumError;

#define R_CHECKSUM_ERROR (r_checksum_error_quark())
GQuark r_checksum_error_quark(void);

typedef struct {
	GChecksumType type;
	gchar *digest;
	gsize size;
} RaucChecksum;

/**
 * Updates RaucChecksum by checksum calculated for given file.
 *
 * If provided checksum has no type set, it defaults to RAUC_DEFAULT_CHECKSUM
 *
 * @param checksum RaucChecksum to update
 * @param filename name of file to calculate checksum for
 * @param error return location for a GError, or NULL
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean compute_checksum(RaucChecksum *checksum, const gchar *filename, GError **error);

/**
 * Verifies provided file checksum.
 *
 * The provided checksum if compared the the checksum calculated for the provided file
 *
 * @param checksum file checksum to verify
 * @param filename name of file to verify checksum against
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean verify_checksum(const RaucChecksum *checksum, const gchar *filename, GError **error);
