#include "checksum.h"

#define RAUC_DEFAULT_CHECKSUM G_CHECKSUM_SHA256

gboolean update_checksum(RaucChecksum *checksum, const gchar *filename) {
	GMappedFile *file;
	GBytes *content = NULL;
	gboolean res = FALSE;

	file = g_mapped_file_new(filename, FALSE, NULL);
	if (file == NULL)
		goto out;
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

gboolean verify_checksum(const RaucChecksum *checksum, const gchar *filename) {
	RaucChecksum tmp;
	gboolean res = FALSE;

	if (checksum->digest == NULL)
		goto out;

	tmp.type = checksum->type;
	tmp.digest = NULL;

	res = update_checksum(&tmp, filename);
	if (!res)
		goto out;

	res = g_str_equal(checksum->digest, tmp.digest);

	if (!res)
		g_print("Checksum mismatch: %s != %s\n", checksum->digest, tmp.digest);

out:
	return res;
}
