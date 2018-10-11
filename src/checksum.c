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

static gboolean
update_from_file(GChecksum *ctx, const gchar *filename, gsize *total, GError **error)
{
	g_autoptr(GMappedFile) file = NULL;
	const guchar *content;
	gsize size;

	file = g_mapped_file_new(filename, FALSE, error);
	if (file == NULL)
		return FALSE;

	content = (const guchar *)g_mapped_file_get_contents(file);
	size = g_mapped_file_get_length(file);
	g_checksum_update(ctx, content, size);
	*total += size;

	return TRUE;
}

gboolean compute_checksum(RaucChecksum *checksum, const gchar *filename, GError **error)
{
	g_autoptr(GChecksum) ctx = NULL;
	GChecksumType type = checksum->type;
	gsize total = 0;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!type)
		type = RAUC_DEFAULT_CHECKSUM;
	ctx = g_checksum_new(type);

	if (!update_from_file(ctx, filename, &total, error))
		return FALSE;

	g_clear_pointer(&checksum->digest, g_free);
	checksum->digest = g_strdup(g_checksum_get_string(ctx));
	checksum->size = total;
	checksum->type = type;

	return TRUE;
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
