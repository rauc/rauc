#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <config_file.h>
#include <context.h>
#include <manifest.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autoptr(GBytes) dt = g_bytes_new(data, size);
	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GError) error = NULL;

	(void) load_manifest_mem(dt, &rm, &error);

	return 0;
}
