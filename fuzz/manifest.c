#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <config_file.h>
#include <context.h>
#include <manifest.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	GBytes *dt = NULL;
	RaucManifest *rm = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	dt = g_bytes_new(data, size);
	res = load_manifest_mem(dt, &rm, &error);

	g_clear_error(&error);
	g_clear_pointer(&rm, free_manifest);
	g_assert_null(rm);
	g_clear_pointer(&dt, g_bytes_unref);
	return 0;
}
