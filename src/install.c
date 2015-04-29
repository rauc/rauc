#include <glib.h>
#include <gio/gio.h>

#include "install.h"

#define BOOTNAME "root"

gchar* get_active_slot_bootname(void) {

	GRegex *regex;
	GMatchInfo *match;
	char *contents;
	char *word = NULL;

	if (!g_file_get_contents ("/proc/cmdline", &contents, NULL, NULL))
		return NULL;

	regex = g_regex_new (BOOTNAME "=(\\S+)", 0, G_REGEX_MATCH_NOTEMPTY, NULL);
	if (!g_regex_match (regex, contents, G_REGEX_MATCH_NOTEMPTY, &match))
		goto out;

	word = g_match_info_fetch (match, 1);

out:
	g_match_info_free (match);
	g_regex_unref (regex);
	g_free (contents);

	return word;

}

