#include "checksum.h"

#define RAUC_DEFAULT_CHECKSUM G_CHECKSUM_SHA256
/*
 * G_CHECKSUM_MD5 is 0. We will never allow use of such a weak hash
 * for anything. Hence checking for !checksum->type below to mean "use
 * the default" is ok.
 */
G_STATIC_ASSERT(G_CHECKSUM_MD5 == 0);
G_STATIC_ASSERT(RAUC_DEFAULT_CHECKSUM != 0);

G_DEFINE_QUARK(r-checksum-error-quark, r_checksum_error)

gboolean compute_checksum(RaucChecksum *checksum, const gchar *filename, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GMappedFile) file = NULL;
	g_autoptr(GBytes) content = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	file = g_mapped_file_new(filename, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	if (!checksum->type)
		checksum->type = RAUC_DEFAULT_CHECKSUM;
	g_clear_pointer(&checksum->digest, g_free);
	checksum->digest = g_compute_checksum_for_bytes(checksum->type, content);
	checksum->size = g_bytes_get_size(content);

	res = TRUE;
out:
	if (!res) {
		g_clear_pointer(&checksum->digest, g_free);
		checksum->size = 0;
	}
	return res;
}

gboolean verify_checksum(const RaucChecksum *checksum, const gchar *filename, GError **error)
{
	gboolean res = FALSE;
	RaucChecksum computed = {};

	if (checksum->digest == NULL) {
		g_set_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_FAILED, "No digest provided");
		goto out;
	}
	computed.type = checksum->type;

	if (!compute_checksum(&computed, filename, error))
		goto out;

	res = checksum->size == computed.size;
	if (!res) {
		g_set_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_SIZE_MISMATCH, "Sizes do not match");
		goto out;
	}

	res = g_str_equal(checksum->digest, computed.digest);
	if (!res) {
		g_set_error(error, R_CHECKSUM_ERROR, R_CHECKSUM_ERROR_DIGEST_MISMATCH, "Digests do not match");
		goto out;
	}

out:
	g_free(computed.digest);
	return res;
}
