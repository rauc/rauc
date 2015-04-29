#include "checksum.h"

gboolean update_checksum(RaucChecksum *checksum, const gchar *filename) {
	GMappedFile *file;
	GBytes *content = NULL;
	gboolean res = FALSE;

	file = g_mapped_file_new(filename, FALSE, NULL);
	if (file == NULL)
		goto out;
	content = g_mapped_file_get_bytes(file);

	g_clear_pointer(&checksum->digest, g_free);
	checksum->digest = g_compute_checksum_for_bytes(checksum->type, content);
	
	res = TRUE;
out:
	return res;
}

gboolean verify_checksum(RaucChecksum *checksum, const gchar *filename) {
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

out:
	g_clear_pointer(&checksum->digest, g_free);
	return res;
}
