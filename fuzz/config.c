#include <stdint.h>
#include <stddef.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <config_file.h>

#include "fuzz.h"

/*
 * Fuzzes the rauc system configuration (system.conf) parser.
 *
 * The system.conf file controls slot layout, keyring, handlers, polling,
 * encryption and artifact repositories. Although it is normally written by
 * the admin, its parser is a central typed-INI interpreter whose input
 * influences security decisions (keyring paths, allowed signer CNs, bundle
 * format mask, boot chooser selection). Feeding arbitrary bytes exercises
 * the full group/key matrix in config_file.c: memory safety of string list
 * and integer parsing, allocation paths and error handling.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *confname = NULL;
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) error = NULL;

	fuzz_set_logging_func();

	tmpdir = g_dir_make_tmp("rauc-fuzz-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	confname = g_build_filename(tmpdir, "system.conf", NULL);
	g_assert_nonnull(confname);

	if (!g_file_set_contents(confname, (const gchar *)data, size, &error)) {
		g_clear_error(&error);
		goto out;
	}

	(void)load_config(confname, &config, &error);

out:
	g_remove(confname);
	g_remove(tmpdir);

	return 0;
}
