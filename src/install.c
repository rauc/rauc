#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include <context.h>
#include "install.h"
#include "manifest.h"
#include "bundle.h"

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


static gboolean launch_and_wait_custom_handler(gchar* cwd, gchar* name) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	gchar* handler_name;

	handler_name = g_build_filename(cwd, name, NULL);

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);

	g_subprocess_launcher_setenv(handlelaunch, "SYSTEM_CONFIG", r_context()->configpath, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "CURRENT_BOOTNAME", "TODO", TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "TARGET_SLOTS", "TODO", TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "UPDATE_SOURCE", cwd, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "MOUNT_PREFIX", r_context()->mountprefix ? r_context()->mountprefix : r_context()->config->mount_prefix , TRUE);

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch,
			&error, handler_name,
			NULL);


	if (handleproc == NULL) {
		g_warning("failed to start custom handler: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(handleproc, NULL, &error);
	if (!res) {
		g_warning("failed to run custom handler: %s\n", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	g_free(handler_name);
	return res;
}

/* Creates a mount subdir in mount path prefix */
static gchar* create_mount_point(const gchar *name) {
	gchar* prefix;
	gchar* mountpoint = NULL;

	prefix = r_context()->mountprefix == NULL ? r_context()->config->mount_prefix : r_context()->mountprefix;
	if (!g_file_test (prefix, G_FILE_TEST_IS_DIR)) {
		g_warning("mount prefix path %s does not exist", prefix);
		goto out;
	}


	mountpoint = g_build_filename(prefix, name, NULL);

	if (!g_file_test (mountpoint, G_FILE_TEST_IS_DIR)) {
		gint ret;
		ret = g_mkdir(mountpoint, 0777);

		if (ret != 0) {
			g_print("Failed creating mount path '%s'\n", mountpoint);
			g_free(mountpoint);
			mountpoint = NULL;
			goto out;
		}
	}

out:

	return mountpoint;
}

static gboolean launch_and_wait_default_handler(RaucManifest *manifest, GHashTable *target_group) {

	gboolean res = FALSE;
	gchar *mountpoint;

	mountpoint = create_mount_point("image");

	if (!mountpoint) {
		goto out;
	}
	
	// TODO: mark slots as non-bootable

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		gchar *dest_slot_name;
		RaucSlot  *dest_slot;
		RaucImage *mfimage;

		mfimage = l->data;
		dest_slot_name = g_hash_table_lookup(target_group, mfimage->slotclass);
		dest_slot = g_hash_table_lookup(r_context()->config->slots, dest_slot_name);

		g_print("I will mount %s to %s and copy %s\n", dest_slot->device, mountpoint, mfimage->filename);

		// TODO: check

		// TODO: copy

		// TODO: update slot
	}

	// TODO: mark slots as non-bootable

	res = TRUE;

out:
	g_free(mountpoint);

	return res;
}


gboolean do_install_bundle(const gchar* bundlefile) {

	gboolean res = FALSE;
	gchar* mountpoint;
	gchar* bundlelocation = NULL;
	RaucManifest *manifest;
	GHashTable *target_group;

	g_assert_nonnull(bundlefile);

	mountpoint = create_mount_point("bundle");

	if (!mountpoint) {
		goto out;
	}

	if (!g_path_is_absolute(bundlefile)) {
		bundlelocation = g_build_filename(g_get_current_dir(), bundlefile, NULL);
	} else {
		bundlelocation = g_strdup(bundlefile);
	}

	// TODO: mount info in context ?
	res = mount_bundle(bundlelocation, mountpoint);

	if (!res) {
		g_warning("Failed mounting bundle");
		goto umount;
	}

	res = verify_manifest(mountpoint, &manifest, FALSE);

	if (!res) {
		g_warning("Failed veryfing manifest");
		goto umount;
	}

	target_group = determine_target_install_group(manifest);

	if (!target_group) {
		g_warning("Could not determine target group");
		goto umount;
	}

	if (manifest->handler_name) {
		g_print("Using custom handler: %s\n", manifest->handler_name);
		res = launch_and_wait_custom_handler(mountpoint, manifest->handler_name);
	} else {
		g_print("Using default handler\n");
		res = launch_and_wait_default_handler(manifest, target_group);
	}

	if (!res) {
		g_warning("Starting handler failed");
		goto umount;
	}

	res = TRUE;

umount:

	umount_bundle(bundlelocation);
	g_rmdir(mountpoint);

out:
	g_free(mountpoint);
	g_free(bundlelocation);
	free_manifest(manifest);

	return res;

}
