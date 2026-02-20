#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include <openssl/evp.h>

#include "context.h"
#include "hash_index.h"
#include "utils.h"

#define SHA256_LEN 32

GQuark r_hash_index_error_quark(void)
{
	return g_quark_from_static_string("r-hash-index-error-quark");
}

/**
 * Hash a single chunk using OpenSSL's SHA256.
 *
 * The calculated hash is stored in the chunk struct.
 */
static void hash_chunk(RaucHashIndexChunk *chunk)
{
	EVP_MD_CTX *mdctx;
	uint8_t tmp[EVP_MAX_MD_SIZE];
	unsigned int tmp_size = 0;

	mdctx = EVP_MD_CTX_new();
	if (EVP_DigestInit(mdctx, EVP_sha256()) != 1) {
		g_error("failed to initialize OpenSSL EVP digest");
	}

	if (EVP_DigestUpdate(mdctx, chunk->data, sizeof(chunk->data)) != 1) {
		g_error("failed to update OpenSSL EVP digest");
	}

	if (EVP_DigestFinal(mdctx, tmp, &tmp_size) != 1) {
		g_error("failed to finalize OpenSSL EVP digest");
	}

	g_assert(tmp_size == sizeof(chunk->hash));

	memcpy(chunk->hash, tmp, sizeof(chunk->hash));

	EVP_MD_CTX_free(mdctx);
}

/**
 * Build array of chunk hashes using SHA256.
 */
static GBytes *hash_file(int data_fd, guint32 count, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GByteArray) hashes = g_byte_array_set_size(g_byte_array_new(), ((guint)count)*SHA256_LEN);
	g_autofree RaucHashIndexChunk *chunk = g_new0(RaucHashIndexChunk, 1);

	g_return_val_if_fail(data_fd >= 0, NULL);
	g_return_val_if_fail(count > 0, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (lseek(data_fd, 0, SEEK_SET) != 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to seek to position 0: %s", g_strerror(err));
		return NULL;
	}

	for (guint32 i = 0; i < count; i++) {
		if (!r_read_exact(data_fd, chunk->data, sizeof(chunk->data), &ierror)) {
			if (ierror) {
				g_propagate_error(error, ierror);
			} else {
				g_set_error(error,
						R_HASH_INDEX_ERROR,
						R_HASH_INDEX_ERROR_SIZE,
						"image/partition ended unexpectedly");
			}
			return NULL;
		}
		hash_chunk(chunk);
		memcpy(&hashes->data[i*SHA256_LEN], chunk->hash, SHA256_LEN);

		/* Split the overall hash index calculation into (R_HASH_INDEX_GEN_PROGRESS_SPAN - 1)
		 * segments and increment the progress by one for each. */
		if (r_context()->progress)
			if (i % (count / (R_HASH_INDEX_GEN_PROGRESS_SPAN - 1)) == 0)
				r_context_inc_step_percentage("copy_image");
	}

	return g_byte_array_free_to_bytes(g_steal_pointer(&hashes));
}

/**
 * Compare integers in the same way memcmp() compares memory.
 */
static gint intcmp(guint32 a, guint32 b)
{
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

/**
 * Compare two hash pointers in an index table.
 *
 * This first compares the chunk hashes and then the position in the file.
 */
static gint lookup_compare_sort(gconstpointer a, gconstpointer b, gpointer hashes)
{
	const guint32 *_a = a;
	const guint32 *_b = b;
	guint8 *_hashes = hashes;
	const guint8 *a_hash = _hashes + *_a * SHA256_LEN;
	const guint8 *b_hash = _hashes + *_b * SHA256_LEN;
	int res;

	res = memcmp(a_hash, b_hash, SHA256_LEN);
	if (res)
		return res;

	/* sort identical hashes by chunk number */
	return intcmp(*_a, *_b);
}

/**
 * Build sorted lookup table for finding chunk positions using binary search.
 *
 * Uses qsort_r to create a sorted array of all hashes. Identical hashes are
 * sorted by chunk number to improve locality and cache reuse.
 */
static guint32 *build_lookup(GBytes *hashes)
{
	guint32 *lookup = NULL;
	guint32 count;

	g_return_val_if_fail(hashes != NULL, NULL);

	count = g_bytes_get_size(hashes) / SHA256_LEN;
	lookup = g_new(guint32, count);

	for (guint32 i = 0; i < count; i++) {
		lookup[i] = i;
	}

	qsort_r(lookup, count, sizeof(guint32), lookup_compare_sort, (void *)g_bytes_get_data(hashes, NULL));

	return lookup;
}

/**
 * Calculate chunk count required for file.
 *
 * The chunk size is hard-coded to 4k.
 *
 * @param data_fd open file descriptor of file to get chunk count for
 * @param error return location for a GError, or NULL
 *
 * @return chunk count or 0 on error
 */
static guint32 get_chunk_count(int data_fd, GError **error)
{
	off_t size;

	g_return_val_if_fail(data_fd >= 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Use seek to end instead of fstat or ioctl, as this works for files and
	 * block devices.
	 **/
	size = lseek(data_fd, 0, SEEK_END);
	if (size < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to seek to end: %s", g_strerror(err));
		return 0;
	}
	if (lseek(data_fd, 0, SEEK_SET) != 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"failed to seek to position 0: %s", g_strerror(err));
		return 0;
	}

	/* Verify that the data file has a reasonable size. */
	if (size == 0) {
		g_set_error(error,
				R_HASH_INDEX_ERROR,
				R_HASH_INDEX_ERROR_SIZE,
				"image/partition is empty");
		return 0;
	} else if ((size / 4096) > (off_t)G_MAXUINT32) {
		g_set_error(error,
				R_HASH_INDEX_ERROR,
				R_HASH_INDEX_ERROR_SIZE,
				"image/partition size (%"G_GINT64_FORMAT ") is too large",
				(gint64)size);
		return 0;
	} else if (size % 4096) {
		g_set_error(error,
				R_HASH_INDEX_ERROR,
				R_HASH_INDEX_ERROR_SIZE,
				"image/partition size (%"G_GINT64_FORMAT ") is not a multiple of 4096 bytes",
				(gint64)size);
		return 0;
	}

	return size / 4096;
}

/**
 * Build the lookup table and initialize the hash index with default values.
 */
static void hash_index_prepare(RaucHashIndex *idx)
{
	/* prepare sorted lookup array */
	idx->lookup = build_lookup(idx->hashes);

	/* everything is valid by default */
	idx->invalid_below = 0;
	idx->invalid_from = G_MAXUINT32;

	idx->match_stats = r_stats_new(idx->label);
}

RaucHashIndex *r_hash_index_open(const gchar *label, int data_fd, const gchar *hashes_filename, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucHashIndex) idx = g_new0(RaucHashIndex, 1);

	g_return_val_if_fail(label, NULL);
	g_return_val_if_fail(data_fd >= 0, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	idx->label = g_strdup(label);
	idx->data_fd = dup(data_fd);

	idx->count = get_chunk_count(data_fd, &ierror);
	if (!idx->count) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* load or calculate chunk hashes */
	if (hashes_filename && g_file_test(hashes_filename, G_FILE_TEST_IS_REGULAR)) {
		g_autoptr(GMappedFile) mapped_file = g_mapped_file_new(hashes_filename, FALSE, &ierror);
		gsize mapped_size;

		if (!mapped_file) {
			g_propagate_error(error, ierror);
			return NULL;
		}

		mapped_size = g_mapped_file_get_length(mapped_file);
		g_assert(mapped_size < (gsize)G_MAXUINT32);

		g_info("using existing hash index for %s from %s", label, hashes_filename);

		if (mapped_size / SHA256_LEN < idx->count) {
			g_info(
					"hash index (%"G_GUINT32_FORMAT " chunks) does not cover complete data range (%"G_GUINT32_FORMAT " chunks), ignoring the rest",
					(guint32)(mapped_size / SHA256_LEN),
					idx->count
					);
			idx->count = mapped_size / SHA256_LEN;
		}

		idx->hashes = g_mapped_file_get_bytes(mapped_file);
	}

	if (!idx->hashes) {
		g_message("Building new hash index for %s with %"G_GUINT32_FORMAT " chunks", label, idx->count);
		idx->hashes = hash_file(data_fd, idx->count, &ierror);
		if (!idx->hashes) {
			g_propagate_error(error, ierror);
			return NULL;
		}
	}

	hash_index_prepare(idx);

	return g_steal_pointer(&idx);
}

RaucHashIndex *r_hash_index_reuse(const gchar *label, const RaucHashIndex *idx, int new_data_fd, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucHashIndex) new_idx = g_new0(RaucHashIndex, 1);

	g_return_val_if_fail(label, NULL);
	g_return_val_if_fail(idx, FALSE);
	g_return_val_if_fail(new_data_fd >= 0, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	new_idx->label = g_strdup_printf("%s (reusing %s)", label, idx->label);
	new_idx->data_fd = new_data_fd;

	new_idx->count = get_chunk_count(new_data_fd, &ierror);
	if (!new_idx->count) {
		g_propagate_error(error, ierror);
		return NULL;
	}
	if (new_idx->count > idx->count) {
		new_idx->count = idx->count;
	}

	/* use a subsection of the original hashes */
	new_idx->hashes = g_bytes_new_from_bytes(idx->hashes, 0, new_idx->count * SHA256_LEN);

	hash_index_prepare(new_idx);

	return g_steal_pointer(&new_idx);
}

RaucHashIndex *r_hash_index_open_slot(const gchar *label, const RaucSlot *slot, int flags, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucHashIndex) idx = NULL;
	g_autofree gchar *dir = NULL;
	g_autofree gchar *index_filename = NULL;
	g_auto(filedesc) data_fd = -1;

	g_return_val_if_fail(label, NULL);
	g_return_val_if_fail(slot, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	data_fd = g_open(slot->device, flags | O_CLOEXEC);
	if (data_fd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open slot device %s: %s", slot->device, g_strerror(err));
		return NULL;
	}

	dir = r_slot_get_checksum_data_directory(slot, NULL, &ierror);
	if (!dir) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	index_filename = g_build_filename(dir, "block-hash-index", NULL);

	/* r_hash_index_open handles missing index file */
	idx = r_hash_index_open(label, data_fd, index_filename, &ierror);
	if (!idx) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_debug("opened hash index for slot %s as %s", slot->name, label);

	return g_steal_pointer(&idx);
}

RaucHashIndex *r_hash_index_open_image(const gchar *label, const RaucImage *image, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucHashIndex) idx = NULL;
	g_autofree gchar *index_filename = NULL;
	g_auto(filedesc) data_fd = -1;

	g_return_val_if_fail(label, NULL);
	g_return_val_if_fail(image, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	data_fd = g_open(image->filename, O_RDONLY | O_CLOEXEC);
	if (data_fd < 0) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open image file %s: %s", image->filename, g_strerror(err));
		return NULL;
	}

	index_filename = g_strdup_printf("%s.block-hash-index", image->filename);

	idx = r_hash_index_open(label, data_fd, index_filename, &ierror);
	if (!idx) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_debug("opened hash index for image %s with index %s", image->filename, index_filename);

	return g_steal_pointer(&idx);
}

gboolean r_hash_index_export(const RaucHashIndex *idx, const gchar *hashes_filename, GError **error)
{
	g_return_val_if_fail(idx, FALSE);
	g_return_val_if_fail(hashes_filename, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	return write_file(hashes_filename, idx->hashes, error);
}

gboolean r_hash_index_export_slot(const RaucHashIndex *idx, const RaucSlot *slot, const RaucChecksum *checksum, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *dir = NULL;
	g_autofree gchar *index_filename = NULL;

	g_return_val_if_fail(idx, FALSE);
	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	dir = r_slot_get_checksum_data_directory(slot, checksum, &ierror);
	if (!dir) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	index_filename = g_build_filename(dir, "block-hash-index", NULL);

	return write_file(index_filename, idx->hashes, error);
}

gboolean r_hash_index_get_chunk(const RaucHashIndex *idx, const guint8 *hash, RaucHashIndexChunk *chunk, GError **error)
{
	GError *ierror = NULL;
	gboolean ret = FALSE;
	const guint8(*hashes)[SHA256_LEN];
	guint32 left, middle, right;
	gboolean found = FALSE;
	off_t offset;

	g_return_val_if_fail(idx, FALSE);
	g_return_val_if_fail(idx->hashes, FALSE);
	g_return_val_if_fail(idx->count > 0, FALSE);
	g_return_val_if_fail(hash, FALSE);
	g_return_val_if_fail(chunk, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	hashes = g_bytes_get_data(idx->hashes, NULL);

	/* use a binary search over the sorted chunk hash indices */
	left = 0;
	right = idx->count - 1;
	middle = 0;
	while (left <= right) {
		int cmp;
		middle = left + (right - left) / 2;
		cmp = memcmp(hashes[idx->lookup[middle]], hash, SHA256_LEN);
		if (cmp == 0) {
			found = TRUE;
			break;
		} else if (cmp < 0) {
			left = middle + 1;
		} else if (middle > 0) {
			right = middle - 1;
		} else {
			break; /* not found */
		}
	}
	if (!found) {
		g_set_error(error,
				R_HASH_INDEX_ERROR,
				R_HASH_INDEX_ERROR_NOT_FOUND,
				"hash not found in index");
		ret = FALSE;
		goto out;
	}

	//g_debug("found middle=%u/%u", middle, idx->lookup[middle]);

	/* find the first chunk with this hash (to make it deterministic) */
	for (guint32 i = middle; i > 0; i--) {
		guint32 next = idx->lookup[i-1];

		if (memcmp(hashes[next], hash, SHA256_LEN) != 0) {
			middle = i;
			break;
		}
	}
	//g_debug("first middle=%u/%u", middle, idx->lookup[middle]);

	/* find the first chunk with this hash in the valid range */
	found = FALSE;
	for (guint32 i = middle; i < idx->count; i++) {
		guint32 curr = idx->lookup[i];

		if (memcmp(hashes[curr], hash, SHA256_LEN) != 0)
			break;

		if (curr >= idx->invalid_from) {
			/* only invalid chunks remaining */
			break;
		} else if (curr < idx->invalid_below) {
			if (i < idx->count - 1) {
				/* keep looking for a chunk in the valid range */
				continue;
			} else {
				/* at the end of the index */
				break;
			}
		} else {
			/* in valid range */
			found = TRUE;
			middle = i;
			break;
		}
	}
	if (!found) {
		g_set_error(error,
				R_HASH_INDEX_ERROR,
				R_HASH_INDEX_ERROR_NOT_FOUND,
				"hash not in valid region [%"G_GUINT32_FORMAT "..%"G_GUINT32_FORMAT ")",
				idx->invalid_below, idx->invalid_from);
		ret = FALSE;
		goto out;
	}

	offset = ((off_t)(idx->lookup[middle])) * sizeof(chunk->data);
	if (!r_pread_exact(idx->data_fd, chunk->data, sizeof(chunk->data), offset, &ierror)) {
		if (ierror) {
			g_propagate_error(error, ierror);
		} else {
			g_set_error(error,
					R_HASH_INDEX_ERROR,
					R_HASH_INDEX_ERROR_SIZE,
					"image/partition ended unexpectedly");
		}
		ret = FALSE;
		goto out;
	}

	if (!idx->skip_hash_check) {
		hash_chunk(chunk);
		if (memcmp(chunk->hash, hash, SHA256_LEN) != 0) {
			g_set_error(error,
					R_HASH_INDEX_ERROR,
					R_HASH_INDEX_ERROR_MODIFIED,
					"data chunk hash differs from index");
			ret = FALSE;
			goto out;
		}
	}

	ret = TRUE;

out:
	r_stats_add(idx->match_stats, ret);

	return ret;
}

void r_hash_index_free(RaucHashIndex *idx)
{
	if (!idx)
		return;

	g_free(idx->label);

	g_close(idx->data_fd, NULL);

	g_bytes_unref(idx->hashes);
	g_free(idx->lookup);

	r_stats_free(idx->match_stats);

	g_free(idx);
}
