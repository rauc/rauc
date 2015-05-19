#include "checksum.h"

#define RAUC_DEFAULT_CHECKSUM G_CHECKSUM_SHA256


#define R_CHECKSUM_ERROR r_checksum_error_quark ()

static GQuark r_checksum_error_quark (void)
{
  return g_quark_from_static_string ("r_checksum_error_quark");
}

gboolean update_checksum(RaucChecksum *checksum, const gchar *filename, GError **error) {
	GError *ierror = NULL;
	GMappedFile *file;
	GBytes *content = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	file = g_mapped_file_new(filename, FALSE, &ierror);
	if (file == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}
	content = g_mapped_file_get_bytes(file);

	if (checksum->digest == NULL)
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
	g_clear_pointer(&content, g_bytes_unref);
	g_clear_pointer(&file, g_mapped_file_unref);
	return res;
}

gboolean verify_checksum(const RaucChecksum *checksum, const gchar *filename, GError **error) {
	GError *ierror = NULL;
	RaucChecksum tmp;
	gboolean res = FALSE;

	if (checksum->digest == NULL)
		goto out;

	tmp.type = checksum->type;
	tmp.digest = NULL;

	// TODO: add hint for empty checksum?
	res = update_checksum(&tmp, filename, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = g_str_equal(checksum->digest, tmp.digest);
	if (!res) {
		g_set_error(error, R_CHECKSUM_ERROR, 0, "Checksums do not match");
		goto out;
	}

out:
	return res;
}
