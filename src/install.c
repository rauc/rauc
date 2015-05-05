#include <glib.h>
#include <gio/gio.h>

#include <context.h>
#include "install.h"
#include "manifest.h"

#define BOOTNAME "root"

const gchar* get_cmdline_bootname(void) {

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

gboolean determine_slot_states(const gchar* (*bootname_provider)(void)) {
	GList *slotlist, *l;
	const gchar *bootname;
	RaucSlot *booted = NULL;
	gboolean res = FALSE;

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);

	bootname = bootname_provider();

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);
		if (!s->bootname) {
			g_warning("Warning: No bootname given\n");
			continue;
		}

		if (g_strcmp0(s->bootname, bootname) == 0) {
			booted = s;
			break;
		}
	}

	if (!booted) {
		g_warning("Did not find booted slot\n");
		goto out;
	}

	res = TRUE;
	booted->state = ST_ACTIVE;

	/* Determine active group members */
	for (l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);

		if (s->parent) {
			if (s->parent->state == ST_ACTIVE) {
				s->state = ST_ACTIVE;
			} else {
				s->state = ST_INACTIVE;
			}
		} else {
			if (s->state == ST_UNKNOWN)
				s->state = ST_INACTIVE;
		}

	}

out:
	g_list_free(slotlist);

	return res;

}

GList* get_slot_class_members(const gchar* slotclass) {
	GList *slotlist;
	GList *members = NULL;

	g_assert_nonnull(slotclass);

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		gchar **split;

		split = g_strsplit(l->data, ".", 2);

		if (g_strcmp0(split[0], slotclass) == 0) {
			members = g_list_append(members, l->data);
		}

		g_free(split);
	}

	return members;
}

GHashTable* determine_target_install_group(RaucManifest *manifest) {
	RaucSlot *targetgroup_root = NULL;
	GList *slotmembers;
	GHashTable *targetgroup = NULL;

	g_assert_nonnull(manifest->images->data);

	/* Determine slot class members for first image in manifest */
	slotmembers = get_slot_class_members(((RaucImage*)manifest->images->data)->slotclass);

	/* Get the first inactive slot in slot group and determine root slot */
	for (GList *l = slotmembers; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);

		if (s->state == ST_INACTIVE) {
			if (s->parent)
				targetgroup_root = s->parent;
			else
				targetgroup_root = s;
		}
	}

	if (!targetgroup_root) {
		g_warning("Failed to determine target install group\n");
		return NULL;
	}

	targetgroup = g_hash_table_new(g_str_hash, g_str_equal);

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucSlot *image_target = NULL;
		RaucImage *img = l->data;

		slotmembers = get_slot_class_members(img->slotclass);

		for (GList *li = slotmembers; li != NULL; li = li->next) {
			RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, li->data);

			if (s == targetgroup_root || s->parent == targetgroup_root) {
				image_target = s;
			}
		}

		if (!image_target) {
			g_warning("No target for class '%s' found!\n", img->slotclass);
			return NULL;
		}

		g_hash_table_insert(targetgroup, img->slotclass, image_target->name);
	}

	return targetgroup;
}

