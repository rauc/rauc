#pragma once

#include <glib.h>

#include "config_file.h"
#include "slot.h"
#include "stats.h"

#define R_HASH_INDEX_ERROR r_hash_index_error_quark()
GQuark r_hash_index_error_quark(void);

typedef enum {
	R_HASH_INDEX_ERROR_SIZE,
	R_HASH_INDEX_ERROR_NOT_FOUND,
	R_HASH_INDEX_ERROR_MODIFIED,
} RHashIndexErrorError;

typedef struct {
	guint8 data[4096];
	guint8 hash[32];
} RaucHashIndexChunk;

typedef struct {
	gchar *label; /* label for debugging */
	int data_fd; /* file descriptor of the indexed data */
	guint32 count; /* number of chunks */
	GBytes *hashes; /* either GBytes in memory or GMappedFile */
	guint32 *lookup; /* chunk numbers sorted by chunk hash */
	guint32 invalid_below; /* for old index of target */
	guint32 invalid_from; /* for new index of target */
	RaucStats *match_stats; /* how many searches were successful */
	gboolean skip_hash_check; /* whether to skip the hash check (for bundle payload protected by verity) */
} RaucHashIndex;

/**
 * Creates a hash index for a given open file descriptor.
 *
 * If an existing hash index file is provided via 'hashes_filename', this will
 * be used instead of building a new index.
 *
 * @param label label for hash index (used for debugging/identification)
 * @param data_fd open file descriptor of file to hash
 * @param hashes_filename name of existing hash index file to use instead, or NULL
 * @param error return location for a GError, or NULL
 *
 * @return a newly allocated RaucHashIndex or NULL on error
 */
RaucHashIndex *r_hash_index_open(const gchar *label, int data_fd, const gchar *hashes_filename, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Reuses a previously opened hash index with a new file descriptor.
 *
 * This is useful to find newly written chunks on the destination device in cases
 * where an image contains duplicated chunks. By reusing the source image's hash
 * index with the destination device's file descriptor, we can find these chunks
 * without having to continuously update a separate index.
 *
 * @param label label for hash index (used for debugging/identification)
 * @param idx hash index to be reused
 * @param new_data_fd open file descriptor to associate with the existing index
 * @param error return location for a GError, or NULL
 *
 * @return a newly allocated RaucHashIndex or NULL on error
 */
RaucHashIndex *r_hash_index_reuse(const gchar *label, const RaucHashIndex *idx, int new_data_fd, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a hash index for the given slot.
 *
 * Loads a previously stored `block-hash-index` file from the latest slot's
 * hash directory or falls back to creating a new one from slot device.
 *
 * @param label label for hash index (used for debugging/identification)
 * @param slot slot to open the hash index for
 * @param flags flags for g_open() call
 * @param error return location for a GError, or NULL
 *
 * @return a newly allocated RaucHashIndex or NULL on error
 */
RaucHashIndex *r_hash_index_open_slot(const gchar *label, const RaucSlot *slot, int flags, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a hash index for the given image.
 *
 * Loads a previously stored `<image>.block-hash-index` file from the bundle.
 *
 * @param label label for hash index (used for debugging/identification)
 * @param image image to open the hash index for
 * @param error return location for a GError, or NULL
 *
 * @return a newly allocated RaucHashIndex or NULL on error
 */
RaucHashIndex *r_hash_index_open_image(const gchar *label, const RaucImage *image, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Exports raw hash index to file
 *
 * @param idx RaucHashIndex to export
 * @param hashes_filename name of exported file
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean r_hash_index_export(const RaucHashIndex *idx, const gchar *hashes_filename, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Exports (writes) raw hash index to slot data dir in an image-checksum specific file.
 *
 * @param idx RaucHashIndex to export
 * @param slot slot to write data for
 * @param checksum image checksum to write for
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean r_hash_index_export_slot(const RaucHashIndex *idx, const RaucSlot *slot, const RaucChecksum *checksum, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Search for hash in given hash index.
 *
 * If the hash is found in the provided index, the function returns TRUE and
 * the data inside the provided chunk is reliable.
 *
 * If the hash is not found, the function returns FALSE and the reason can be
 * obtained from error.
 *
 * @param idx RaucHashIndex to obtain chunk from
 * @param hash hash to find
 * @param chunk Newly created chunk instance that should be filled with data
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if chunk was found (and chunk data is reliable), FALSE if not found
 */
gboolean r_hash_index_get_chunk(const RaucHashIndex *idx, const guint8 *hash, RaucHashIndexChunk *chunk, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Frees the hash index.
 *
 * @param idx RaucHashIndex to free
 */
void r_hash_index_free(RaucHashIndex *idx);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucHashIndex, r_hash_index_free);

#define R_HASH_INDEX_ZERO_CHUNK "\xad\x7f\xac\xb2\x58\x6f\xc6\xe9\x66\xc0\x4\xd7\xd1\xd1\x6b\x2\x4f\x58\x5\xff\x7c\xb4\x7c\x7a\x85\xda\xbd\x8b\x48\x89\x2c\xa7"

/** Percentage steps reserved for hash index generation */
#define R_HASH_INDEX_GEN_PROGRESS_SPAN 10
