#include "utils.h"

GBytes *read_file(const gchar *filename) {
	gchar *contents;
	gsize length;

	if (!g_file_get_contents(filename, &contents, &length, NULL))
		return NULL;

	return g_bytes_new_take(contents, length);
}

gboolean write_file(const gchar *filename, GBytes *bytes) {
	const gchar *contents;
	gsize length;

	contents = g_bytes_get_data(bytes, &length);

	return g_file_set_contents(filename, contents, length, NULL);
}
