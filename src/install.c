#include <errno.h>
#include <fcntl.h>
#include <gio/gfiledescriptorbased.h>
#include <gio/gio.h>
#include <gio/gunixmounts.h>
#include <gio/gunixoutputstream.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bootchooser.h"
#include "bundle.h"
#include "context.h"
#include "event_log.h"
#include "install.h"
#include "manifest.h"
#include "mark.h"
#include "mount.h"
#include "service.h"
#include "signature.h"
#include "status_file.h"
#include "update_handler.h"
#include "utils.h"

/* All exit codes of hook script above this mean 'rejected' */
#define INSTALL_HOOK_REJECT_CODE 10

#define R_INSTALL_ERROR r_install_error_quark()

GQuark r_install_error_quark(void)
{
	return g_quark_from_static_string("r_install_error_quark");
}

__attribute__((__format__(__printf__, 2, 3)))
static void install_args_update(RaucInstallArgs *args, const gchar *msg, ...)
{
	va_list list;
	gchar *formatted = NULL;

	g_return_if_fail(args);
	g_return_if_fail(msg);

	va_start(list, msg);
	formatted = g_strdup_vprintf(msg, list);
	va_end(list);

	g_mutex_lock(&args->status_mutex);
	g_queue_push_tail(&args->status_messages, formatted);
	g_mutex_unlock(&args->status_mutex);
	g_main_context_invoke(NULL, args->notify, args);
}

static gchar *resolve_loop_device(const gchar *devicepath, GError **error)
{
	g_autoptr(GRegex) regex = NULL;
	g_autoptr(GMatchInfo) match_info = NULL;
	g_autofree gchar *devicename = NULL;
	g_autofree gchar *syspath = NULL;
	gchar *content = NULL;
	GError *ierror = NULL;

	regex = g_regex_new("/dev/(loop\\d+)(p\\d+)?", 0, 0, NULL);
	g_assert_nonnull(regex);

	g_regex_match(regex, devicepath, 0, &match_info);
	if (!g_match_info_matches(match_info))
		return g_strdup(devicepath);

	devicename = g_match_info_fetch(match_info, 1);
	syspath = g_build_filename("/sys/block", devicename, "loop/backing_file", NULL);

	content = read_file_str(syspath, &ierror);
	if (!content) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Error getting loop backing_file for %s: ", devicepath);
		return NULL;
	}

	/* g_strchomp modifies the string and returns it */
	return g_strchomp(content);
}

/*
 * Resolve UBI volume name notation (ubi<N>:<volname>) to device path.
 * UBI volumes are mounted with notation like "ubi0:root" but the actual
 * device is /dev/ubi0_0. This function resolves the name by looking up
 * the volume name in /sys/class/ubi/ubi<N>_<M>/name.
 */
static gchar *resolve_ubi_volume(const gchar *devicepath)
{
	g_autoptr(GRegex) regex = NULL;
	g_autoptr(GMatchInfo) match_info = NULL;
	g_autofree gchar *ubi_num = NULL;
	g_autofree gchar *vol_name = NULL;
	g_autofree gchar *ubi_class_path = NULL;
	g_autoptr(GDir) dir = NULL;

	regex = g_regex_new("^ubi(\\d+):(.+)$", 0, 0, NULL);
	g_assert_nonnull(regex);

	g_regex_match(regex, devicepath, 0, &match_info);
	if (!g_match_info_matches(match_info))
		return g_strdup(devicepath);

	ubi_num = g_match_info_fetch(match_info, 1);
	vol_name = g_match_info_fetch(match_info, 2);

	/* Search through /sys/class/ubi/ubi<N>_X/name for matching volume */
	ubi_class_path = g_strdup("/sys/class/ubi");
	dir = g_dir_open(ubi_class_path, 0, NULL);
	if (dir) {
		const gchar *entry;
		g_autofree gchar *prefix = g_strdup_printf("ubi%s_", ubi_num);

		while ((entry = g_dir_read_name(dir)) != NULL) {
			if (g_str_has_prefix(entry, prefix)) {
				g_autofree gchar *name_path = g_build_filename(ubi_class_path, entry, "name", NULL);
				g_autofree gchar *name_content = NULL;

				if (g_file_get_contents(name_path, &name_content, NULL, NULL)) {
					g_strchomp(name_content);
					if (g_strcmp0(name_content, vol_name) == 0) {
						return g_strdup_printf("/dev/%s", entry);
					}
				}
			}
		}
	}

	/* Volume not found, return original */
	return g_strdup(devicepath);
}

gboolean update_external_mount_points(GError **error)
{
	g_autolist(GUnixMountEntry) mountlist = NULL;
	GHashTableIter iter;
	RaucSlot *slot;
	GError *ierror = NULL;

	/* Clear all previously detected external mount points as we will
	 * re-deterrmine them. */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		g_clear_pointer(&slot->ext_mount_point, g_free);
	}

	/* Determine active slot mount points */
	mountlist = g_unix_mounts_get(NULL);
	for (GList *l = mountlist; l != NULL; l = l->next) {
		GUnixMountEntry *m = (GUnixMountEntry*)l->data;
		g_autofree gchar *devicepath = NULL;
		g_autofree gchar *resolved_devicepath = NULL;
		RaucSlot *s;
		devicepath = resolve_loop_device(g_unix_mount_get_device_path(m), &ierror);
		if (!devicepath) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		/* Resolve UBI volume names like ubi0:root to /dev/ubi0_0 */
		resolved_devicepath = resolve_ubi_volume(devicepath);
		s = find_config_slot_by_device(r_context()->config,
				resolved_devicepath);
		if (s) {
			/* We might have multiple mount entries matching the same device and thus the same slot.
			 * To avoid leaking the string returned by g_unix_mount_get_mount_path() here, we skip all further matches
			 */
			if (s->ext_mount_point) {
				continue;
			}
			s->ext_mount_point = g_strdup(g_unix_mount_get_mount_path(m));
			g_debug("Found external mountpoint for slot %s at %s", s->name, s->ext_mount_point);
		}
	}

	return TRUE;
}

/*
 * Based on the 'bootslot' information (derived from /proc/cmdline during
 * context setup), this determines 'booted', 'active' and 'inactive' states for
 * each slot and stores this in the 'state' member of each slot.
 *
 * First, the booted slot is determined by comparing the 'bootslot' against the
 * slot's 'bootname', 'name', or device path. Then, the other states are
 * determined based on the slot hierarchies.
 *
 * If 'bootslot' is '/dev/nfs' or '_external_', all slots are considered
 * 'inactive'.
 *
 * @param error Return location for a GError, or NULL
 *
 * @return TRUE if succeeded, FALSE if failed
 */
gboolean determine_slot_states(GError **error)
{
	g_autoptr(GList) slotlist = NULL;
	RaucSlot *booted = NULL;

	g_assert_nonnull(r_context()->config);

	if (r_context()->config->slots == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_CONFIG,
				"No slot configuration found");
		return FALSE;
	}

	if (r_context()->bootslot == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_BOOTSLOT,
				"Could not find any root device or rauc slot information in /proc/cmdline");
		return FALSE;
	}

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		g_autofree gchar *realdev = NULL;
		RaucSlot *s = g_hash_table_lookup(r_context()->config->slots, l->data);
		g_assert_nonnull(s);

		if (g_strcmp0(s->bootname, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}

		if (g_strcmp0(s->name, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}

		realdev = r_realpath(s->device);
		if (realdev == NULL) {
			g_message("Failed to resolve realpath for '%s'", s->device);
			realdev = g_strdup(s->device);
		}

		if (g_strcmp0(realdev, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}
	}

	if (!booted) {
		gboolean extboot = FALSE;

		if (g_strcmp0(r_context()->bootslot, "/dev/nfs") == 0) {
			g_message("Detected nfs boot, ignoring missing active slot");
			extboot = TRUE;
		}

		if (g_strcmp0(r_context()->bootslot, "_external_") == 0) {
			g_message("Detected explicit external boot, ignoring missing active slot");
			extboot = TRUE;
		}

		if (extboot) {
			/* mark all as inactive */
			g_debug("Marking all slots as 'inactive'");
			for (GList *l = slotlist; l != NULL; l = l->next) {
				RaucSlot *s = g_hash_table_lookup(r_context()->config->slots, l->data);
				g_assert_nonnull(s);

				s->state = ST_INACTIVE;
			}

			r_context()->config->slot_states_determined = TRUE;

			return TRUE;
		}

		g_set_error(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
				"Did not find booted slot (matching '%s')", r_context()->bootslot);
		return FALSE;
	}

	/* Determine active group members */
	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = g_hash_table_lookup(r_context()->config->slots, l->data);
		g_assert_nonnull(s);

		if (s == booted) {
			s->state = ST_BOOTED;
			g_debug("Found booted slot: %s on %s", s->name, s->device);
		} else if (s->parent && s->parent == booted) {
			s->state = ST_ACTIVE;
		} else {
			s->state = ST_INACTIVE;
		}
	}

	r_context()->config->slot_states_determined = TRUE;

	return TRUE;
}

gboolean determine_boot_states(GError **error)
{
	GHashTableIter iter;
	RaucSlot *slot;
	gboolean had_errors = FALSE;

	/* get boot state */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		GError *ierror = NULL;

		if (!slot->bootname)
			continue;

		if (!r_boot_get_state(slot, &slot->boot_good, &ierror)) {
			g_message("Failed to get boot state of %s: %s", slot->name, ierror->message);
			had_errors = TRUE;
		}
	}

	if (had_errors)
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
				"Could not determine all boot states");

	return !had_errors;
}

/* Returns NULL-teminated intern string array of all classes listed in
 * given manifest.
 * Free with g_free */
static gchar** get_all_manifest_slot_classes(const RaucManifest *manifest)
{
	GPtrArray *slotclasses = NULL;

	g_return_val_if_fail(manifest, NULL);

	slotclasses = g_ptr_array_new();

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		const gchar *key = NULL;
		RaucImage *iterimage = l->data;
		g_assert_nonnull(iterimage->slotclass);
		key = g_intern_string(iterimage->slotclass);
		g_ptr_array_remove_fast(slotclasses, (gpointer)key); /* avoid duplicates */
		g_ptr_array_add(slotclasses, (gpointer)key);
	}
	g_ptr_array_add(slotclasses, NULL);

	return (gchar**) g_ptr_array_free(slotclasses, FALSE);
}
/* Selects a single appropriate inactive slot of root slot class
 *
 * Note: This function may be extended to be more sophisticated or follow a
 * certain policy for selecting an appropriate slot!
 *
 * @param rootclass name of root slot class
 *
 * @return pointer to appropriate slot in system slot list
 */
static RaucSlot *select_inactive_slot_class_member(const gchar *rootclass)
{
	RaucSlot *iterslot;
	GHashTableIter iter;

	g_return_val_if_fail(rootclass, NULL);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &iterslot)) {
		if (iterslot->state != ST_INACTIVE)
			continue;

		if (g_strcmp0(iterslot->sclass, rootclass) == 0) {
			return iterslot;
		}
	}

	return NULL;
}

/* Map each slot class available to a potential target slot.
 *
 * Algorithm:
 *
 * - Get all root classes (classes of slots that do not have a parent)
 * - For each root class:
 *     - select 1 (inactive) member (function)
 * -> set of selected root slots
 * -> collect target install group
 *
 * @return Newly allocated HashTable of
 *         slotclass (gchar*) -> target slot (RaucSlot *)
 */
GHashTable* determine_target_install_group(void)
{
	g_autofree gchar **rootclasses = NULL;
	GHashTable *targetgroup = NULL;
	GHashTableIter iter;
	RaucSlot *iterslot = NULL;
	g_autoptr(GList) selected_root_slots = NULL;

	r_context_begin_step("determine_target_install_group", "Determining target install group", 0);

	/* collect all root classes available in system.conf */
	rootclasses = r_slot_get_root_classes(r_context()->config->slots);

	for (gchar **rootslot = rootclasses; *rootslot != NULL; rootslot++) {
		RaucSlot *selected = NULL;

		selected = select_inactive_slot_class_member(*rootslot);

		if (selected == NULL)
			continue;

		selected_root_slots = g_list_append(selected_root_slots, selected);
	}

	targetgroup = g_hash_table_new(g_str_hash, g_str_equal);

	/* Now, iterate over all slots available and add those who's parent are
	 * in the selected root slots */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &iterslot)) {
		RaucSlot *parent = r_slot_get_parent_root(iterslot);
		g_debug("Checking slot: %s", iterslot->name);


		if (r_slot_list_contains(selected_root_slots, parent)) {
			g_debug("\tAdding mapping: %s -> %s", iterslot->sclass, iterslot->name);
			g_hash_table_insert(targetgroup, (gpointer) iterslot->sclass, iterslot);
		} else {
			g_debug("\tNo mapping found");
		}
	}

	r_context_end_step("determine_target_install_group", TRUE);

	return targetgroup;
}

void r_image_install_plan_free(gpointer value)
{
	RImageInstallPlan *plan = (RImageInstallPlan*)value;

	if (!plan)
		return;

	g_free(plan);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RImageInstallPlan, r_image_install_plan_free);

GPtrArray* r_install_make_plans(const RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar **slotclasses = NULL;
	g_autoptr(GPtrArray) install_plans = g_ptr_array_new_with_free_func(r_image_install_plan_free);

	g_return_val_if_fail(manifest != NULL, NULL);
	g_return_val_if_fail(target_group != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	slotclasses = get_all_manifest_slot_classes(manifest);

	/* Find exactly 1 image for each class listed in manifest */
	for (gchar **cls = slotclasses; *cls != NULL; cls++) {
		RaucImage *matching_img = NULL;
		g_autoptr(RImageInstallPlan) plan = g_new0(RImageInstallPlan, 1);

		for (GList *l = manifest->images; l != NULL; l = l->next) {
			RaucImage *lookup_image = l->data;

			/* Not interested in slots of other classes */
			if (g_strcmp0(lookup_image->slotclass, *cls) != 0)
				continue;

			/* If this is a default variant and we have no better
			 * match yet, use it and continue scanning.
			 * Otherwise test if it is our variant and directly use
			 * it if so */
			if (lookup_image->variant == NULL) {
				if (!matching_img)
					matching_img = lookup_image;
			} else if (g_strcmp0(lookup_image->variant, r_context()->config->system_variant) == 0) {
				g_debug("Using variant %s image %s for %s", lookup_image->variant, lookup_image->filename, lookup_image->slotclass);
				matching_img = lookup_image;
				break;
			}
		}

		/* If we have an image for a class in the manifest but none
		 * that matches our variant, we assume this to be a failure */
		if (!matching_img) {
			g_set_error(error,
					R_INSTALL_ERROR,
					R_INSTALL_ERROR_FAILED,
					"Failed to find matching variant of image for %s", *cls);
			return NULL;
		}

		g_debug("Found image mapping: %s -> %s", matching_img->filename, matching_img->slotclass);
		plan->image = matching_img;

		/* Check if target_group contains an appropriate slot for this image */
		plan->target_slot = g_hash_table_lookup(target_group, matching_img->slotclass);
		if (!plan->target_slot) {
			g_set_error(error,
					R_INSTALL_ERROR,
					R_INSTALL_ERROR_FAILED,
					"No target slot for class %s of image %s found", matching_img->slotclass, matching_img->filename);
			return NULL;
		}
		if (plan->target_slot->readonly) {
			g_set_error(error,
					R_INSTALL_ERROR,
					R_INSTALL_ERROR_FAILED,
					"Target slot for class %s of image %s is readonly", matching_img->slotclass, matching_img->filename);
			return NULL;
		}

		/* determine whether update image type is compatible with destination slot type */
		plan->slot_handler = get_update_handler(plan->image, plan->target_slot, &ierror);
		if (plan->slot_handler == NULL) {
			g_propagate_error(error, ierror);
			return NULL;
		}

		g_ptr_array_add(install_plans, g_steal_pointer(&plan));
	}

	if (install_plans->len == 0) {
		g_set_error_literal(error,
				R_INSTALL_ERROR,
				R_INSTALL_ERROR_FAILED,
				"No installable image found");
		return NULL;
	}

	return g_steal_pointer(&install_plans);
}

static gchar* parse_handler_output(gchar* line)
{
	gchar *message = NULL;
	g_auto(GStrv) split = NULL;

	g_assert_nonnull(line);

	if (!g_str_has_prefix(line, "<< ")) {
		g_print("# %s\n", line);
		return NULL;
	}

	split = g_strsplit(line, " ", 5);

	if (!split[1])
		return NULL;

	if (g_strcmp0(split[1], "handler") == 0) {
		message = g_strdup_printf("Handler status: %s", split[2]);
	} else if (g_strcmp0(split[1], "image") == 0) {
		message = g_strdup_printf("Image '%s' status: %s", split[2], split[3]);
	} else if (g_strcmp0(split[1], "bootloader") == 0) {
		message = g_strdup_printf("Bootloader status: %s", split[2]);
	} else if (g_strcmp0(split[1], "error") == 0) {
		g_autofree gchar *joined = g_strjoinv(" ", &split[2]);
		message = g_strdup_printf("Error: %s", joined);
	} else if (g_strcmp0(split[1], "debug") == 0) {
		g_autofree gchar *joined = g_strjoinv(" ", &split[2]);
		message = g_strdup_printf("Debug: %s", joined);
	} else {
		message = g_strdup_printf("Unknown handler output: %s", line);
	}

	return message;
}

static gboolean verify_compatible(RaucInstallArgs *args, RaucManifest *manifest, GError **error)
{
	if (args->ignore_compatible) {
		return TRUE;
	} else if (g_strcmp0(r_context()->config->system_compatible,
			manifest->update_compatible) == 0) {
		return TRUE;
	} else {
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_COMPAT_MISMATCH,
				"Compatible mismatch: Expected '%s' but bundle manifest has '%s'",
				r_context()->config->system_compatible,
				manifest->update_compatible);
		return FALSE;
	}
}

static gchar **add_system_environment(gchar **envp)
{
	GHashTableIter iter;
	const gchar *key;
	const gchar *value;

	g_return_val_if_fail(envp, NULL);

	envp = g_environ_setenv(envp, "RAUC_SYSTEM_CONFIG", r_context()->configpath, TRUE);
	envp = g_environ_setenv(envp, "RAUC_CURRENT_BOOTNAME", r_context()->bootslot, TRUE);
	envp = g_environ_setenv(envp, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	g_assert_nonnull(r_context()->system_info);
	g_hash_table_iter_init(&iter, r_context()->system_info);
	/* Allow defining new env variables based on system-info
	 * handler, but do not override existing ones. */
	while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
		envp = g_environ_setenv(envp, key, value, FALSE);
	}

	return envp;
}

/**
 * Sets up an environment containing RAUC information, ready to be passed to e.g. handlers
 *
 * Extends the system environment so that the result is save to be used with
 * g_subprocess_launcher_set_environ().
 *
 * @param update_source Path to the current bundle mount point
 * @param manifest Currently used manifest
 * @param target_group Determined target group
 *
 * @return A newly allocated List of environment variables
 */
static gchar **prepare_environment(gchar *update_source, RaucManifest *manifest, GHashTable *target_group)
{
	GHashTableIter iter;
	RaucSlot *slot;
	gint slotcnt = 0;
	g_autoptr(GString) slots = g_string_sized_new(128);
	g_autoptr(GString) target_slots = g_string_sized_new(128);

	/* get current process environment to use as base for appending */
	gchar **envp = g_get_environ();

	envp = add_system_environment(envp);
	envp = g_environ_setenv(envp, "RAUC_BUNDLE_MOUNT_POINT", update_source, TRUE);
	/* Deprecated, included for backwards compatibility: */
	envp = g_environ_setenv(envp, "RAUC_UPDATE_SOURCE", update_source, TRUE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		gchar *varname;
		GHashTableIter iiter;
		gpointer member;

		slotcnt++;

		if (slots->len)
			g_string_append_c(slots, ' ');
		g_string_append_printf(slots, "%i", slotcnt);

		g_hash_table_iter_init(&iiter, target_group);
		while (g_hash_table_iter_next(&iiter, NULL, &member)) {
			if (slot != member) {
				continue;
			}

			/* for target slots, get image name and add number to list */
			for (GList *l = manifest->images; l != NULL; l = l->next) {
				RaucImage *img = l->data;
				if (g_str_equal(slot->sclass, img->slotclass)) {
					varname = g_strdup_printf("RAUC_IMAGE_NAME_%i", slotcnt);
					envp = g_environ_setenv(envp, varname, img->filename ?: "", TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_DIGEST_%i", slotcnt);
					envp = g_environ_setenv(envp, varname, img->checksum.digest ?: "", TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_CLASS_%i", slotcnt);
					envp = g_environ_setenv(envp, varname, img->slotclass, TRUE);
					g_clear_pointer(&varname, g_free);

					break;
				}
			}

			if (target_slots->len)
				g_string_append_c(target_slots, ' ');
			g_string_append_printf(target_slots, "%i", slotcnt);
		}

		varname = g_strdup_printf("RAUC_SLOT_NAME_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->name, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_CLASS_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->sclass, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_TYPE_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->type, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_DEVICE_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->device, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_BOOTNAME_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->bootname ? slot->bootname : "", TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_PARENT_%i", slotcnt);
		envp = g_environ_setenv(envp, varname, slot->parent ? slot->parent->name : "", TRUE);
		g_clear_pointer(&varname, g_free);
	}

	envp = g_environ_setenv(envp, "RAUC_SLOTS", slots->str, TRUE);
	envp = g_environ_setenv(envp, "RAUC_TARGET_SLOTS", target_slots->str, TRUE);

	return envp;
}

/**
 * Launches a handler using g_subprocess and waits for it to finish.
 *
 * Messages printed by the handler to stdout or stderr are parsed and can be
 * used for generating high-level user output in RAUC.
 * See parse_handler_output().
 *
 * @param args Install args, required for user output
 * @param handler_name Path to the handler script/binary
 * @param handler_argv Argument list passed to the handler call, or NULL
 * @param override_env Environment to set for the handler call, or NULL
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE otherwise
 */
static gboolean launch_and_wait_handler(RaucInstallArgs *args, gchar *handler_name, gchar **handler_argv, gchar **override_env, GError **error)
{
	g_autoptr(GSubprocessLauncher) handlelaunch = NULL;
	g_autoptr(GSubprocess) handleproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(GPtrArray) args_array = NULL;
	GInputStream *instream = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	gchar *outline;

	g_return_val_if_fail(args, FALSE);
	g_return_val_if_fail(handler_name, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	if (override_env)
		g_subprocess_launcher_set_environ(handlelaunch, override_env);

	args_array = g_ptr_array_new();
	g_ptr_array_add(args_array, handler_name);
	if (handler_argv) {
		r_ptr_array_addv(args_array, handler_argv, FALSE);
	}
	g_ptr_array_add(args_array, NULL);

	handleproc = r_subprocess_launcher_spawnv(
			handlelaunch, args_array, &ierror);
	if (handleproc == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(handleproc);
	datainstream = g_data_input_stream_new(instream);

	do {
		g_autofree gchar *handler_message = NULL;
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline)
			continue;

		handler_message = parse_handler_output(outline);
		if (handler_message != NULL)
			install_args_update(args, "%s", handler_message);

		g_free(outline);
	} while (outline);

	res = g_subprocess_wait_check(handleproc, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;

out:
	return res;
}

static gboolean run_bundle_hook(RaucManifest *manifest, gchar* bundledir, const gchar *hook_cmd, GError **error)
{
	g_autofree gchar *hook_name = NULL;
	g_autoptr(GSubprocessLauncher) launcher = NULL;
	g_autoptr(GSubprocess) sproc = NULL;
	GError *ierror = NULL;
	GInputStream *instream = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	gboolean res = FALSE;
	gchar *outline = NULL;
	g_autofree gchar *hookreturnmsg = NULL;

	g_assert_nonnull(manifest->hook_name);

	hook_name = g_build_filename(bundledir, manifest->hook_name, NULL);

	g_message("Running bundle hook %s", hook_cmd);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDERR_PIPE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_COMPATIBLE", r_context()->config->system_compatible, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_VARIANT", r_context()->config->system_variant ?: "", TRUE);

	g_subprocess_launcher_setenv(launcher, "RAUC_MF_COMPATIBLE", manifest->update_compatible, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_MF_VERSION", manifest->update_version ?: "", TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	sproc = g_subprocess_launcher_spawn(
			launcher, &ierror,
			hook_name,
			hook_cmd,
			NULL);
	if (sproc == NULL) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to start bundle hook: ");
		goto out;
	}

	/* Read scripts stderr output */
	instream = g_subprocess_get_stderr_pipe(sproc);
	datainstream = g_data_input_stream_new(instream);

	do {
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (outline) {
			g_clear_pointer(&hookreturnmsg, g_free);
			hookreturnmsg = outline;
		}
	} while (outline);

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	if (!res) {
		/* Subprocess exited with code 1 */
		if ((ierror->domain == G_SPAWN_EXIT_ERROR) && (ierror->code >= INSTALL_HOOK_REJECT_CODE)) {
			if (hookreturnmsg) {
				g_clear_error(&ierror);
				g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_REJECTED,
						"Hook returned: %s", hookreturnmsg);
			} else {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Hook returned with exit code %d: ", ierror->code);
			}
		} else {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to run bundle hook: ");
		}
		goto out;
	}

out:
	return res;
}

static gboolean launch_and_wait_custom_handler(RaucInstallArgs *args, gchar* bundledir, RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar* handler_name = NULL;
	g_autoptr(GPtrArray) handler_args = NULL;
	g_auto(GStrv) env = NULL;
	gboolean res = FALSE;

	r_context_begin_step_weighted("launch_and_wait_custom_handler", "Launching update handler", 0, 6);

	handler_name = g_build_filename(bundledir, manifest->handler_name, NULL);
	handler_args = g_ptr_array_new_full(0, g_free);
	if (manifest->handler_args) {
		g_auto(GStrv) handler_argvp = NULL;
		res = g_shell_parse_argv(manifest->handler_args, NULL, &handler_argvp, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
		r_ptr_array_addv(handler_args, handler_argvp, TRUE);
	}
	if (r_context()->handlerextra) {
		g_auto(GStrv) extra_argvp = NULL;
		res = g_shell_parse_argv(r_context()->handlerextra, NULL, &extra_argvp, &ierror);
		if (!res) {
			g_propagate_error(error, ierror);
			goto out;
		}
		r_ptr_array_addv(handler_args, extra_argvp, TRUE);
	}
	g_ptr_array_add(handler_args, NULL);

	env = prepare_environment(bundledir, manifest, target_group);
	res = launch_and_wait_handler(args, handler_name, (gchar**) handler_args->pdata, env, error);

out:
	r_context_end_step("launch_and_wait_custom_handler", res);
	return res;
}

static gboolean pre_install_check_slot_mount_status(RaucSlot *slot, RaucImage *mfimage, GError **error)
{
	/* OK if the slot is not mounted at all. */
	if (!(slot->mount_point || slot->ext_mount_point))
		return TRUE;

	/* OK if the configuration says it may already be mounted and the
	 * bundle has a custom install hook. */
	if (slot->allow_mounted && mfimage->hooks.install)
		return TRUE;

	if (slot->allow_mounted)
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MOUNTED,
				"Mounted device '%s' may only be updated by a custom install hook", slot->device);
	else
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MOUNTED,
				"Destination device '%s' already mounted", slot->device);

	return FALSE;
}

static gboolean pre_install_checks(gchar* bundledir, GPtrArray *install_plans, GHashTable *target_group, GError **error)
{
	for (guint i = 0; i < install_plans->len; i++) {
		const RImageInstallPlan *plan = g_ptr_array_index(install_plans, i);

		if (!plan->image->filename) {
			/* having no filename is valid for install hook only */
			if (plan->image->hooks.install)
				goto skip_filename_checks;
			else
				/* Should not be reached as the pre-conditions for optional 'filename' are already
				 * checked during manifest parsing in manifest.c: parse_image() */
				g_assert_not_reached();
		}

		/* if image filename is relative, make it absolute */
		if (!g_path_is_absolute(plan->image->filename)) {
			gchar *filename = g_build_filename(bundledir, plan->image->filename, NULL);
			g_free(plan->image->filename);
			plan->image->filename = filename;
		}

		if (!g_file_test(plan->image->filename, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NOSRC,
					"Source image '%s' not found in bundle", plan->image->filename);
			return FALSE;
		}

skip_filename_checks:
		if (!g_file_test(plan->target_slot->device, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NODST,
					"Destination device '%s' not found", plan->target_slot->device);
			return FALSE;
		}

		if (!pre_install_check_slot_mount_status(plan->target_slot, plan->image, error)) {
			/* error is already set */
			return FALSE;
		}
	}

	return TRUE;
}

static void update_slot_status(RaucSlotStatus *slot_state, const gchar* status, const RaucManifest *manifest, const RImageInstallPlan *plan, const RaucInstallArgs *args)
{
	g_autoptr(GDateTime) now = NULL;

	r_slot_clear_status(slot_state);

	now = g_date_time_new_now_utc();

	slot_state->bundle_compatible = g_strdup(manifest->update_compatible);
	slot_state->bundle_version = g_strdup(manifest->update_version);
	slot_state->bundle_description = g_strdup(manifest->update_description);
	slot_state->bundle_build = g_strdup(manifest->update_build);
	slot_state->bundle_hash = g_strdup(manifest->hash);
	slot_state->status = g_strdup(status);
	slot_state->checksum.type = plan->image->checksum.type;
	slot_state->checksum.digest = g_strdup(plan->image->checksum.digest);
	slot_state->checksum.size = plan->image->checksum.size;
	slot_state->installed_txn = g_strdup(args->transaction);
	slot_state->installed_timestamp = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");
	slot_state->installed_count++;
}

static gboolean handle_slot_install_plan(const RaucManifest *manifest, const RImageInstallPlan *plan, RaucInstallArgs *args, const char *hook_name, GError **error)
{
	GError *ierror = NULL;
	RaucSlotStatus *slot_state = NULL;

	install_args_update(args, "Checking slot %s", plan->target_slot->name);

	r_context_begin_step_weighted_formatted("check_slot", 0, 1, "Checking slot %s", plan->target_slot->name);

	r_slot_status_load(plan->target_slot);
	slot_state = plan->target_slot->status;

	/* In case we failed unmounting while reading per-slot status
	 * file, abort here */
	if (plan->target_slot->mount_point) {
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MOUNTED,
				"Slot '%s' still mounted", plan->target_slot->device);
		r_context_end_step("check_slot", FALSE);
		return FALSE;
	}

	/* For global slot status: Clear checksum info and make status
	 * 'pending' to prevent the slot status from looking valid later in
	 * case we crash while installing. */
	if (g_strcmp0(r_context()->config->statusfile_path, "per-slot") != 0) {
		g_clear_pointer(&slot_state->status, g_free);
		slot_state->status = g_strdup("pending");
		g_clear_pointer(&slot_state->checksum.digest, g_free);
		slot_state->checksum.size = 0;

		if (!r_slot_status_save(plan->target_slot, &ierror)) {
			g_propagate_prefixed_error(error, ierror, "Error while writing status file: ");
			r_context_end_step("check_slot", FALSE);
			return FALSE;
		}
	}

	/* if explicitly enabled, skip update of up-to-date slots */
	if (!plan->target_slot->install_same && g_strcmp0(plan->image->checksum.digest, slot_state->checksum.digest) == 0) {
		install_args_update(args, "Skipping update for correct image %s", plan->image->filename);
		g_message("Skipping update for correct image %s", plan->image->filename);
		r_context_end_step("check_slot", TRUE);

		/* Dummy step to indicate slot was skipped */
		r_context_begin_step("skip_image", "Copying image skipped", 0);

		/* Update the status also for skipped slots */
		g_message("Updating slot %s status", plan->target_slot->name);
		update_slot_status(slot_state, "ok", manifest, plan, args);
		if (!r_slot_status_save(plan->target_slot, &ierror)) {
			g_propagate_prefixed_error(error, ierror, "Error while writing status file: ");
			r_context_end_step("skip_image", FALSE);
			return FALSE;
		}

		r_context_end_step("skip_image", TRUE);

		install_args_update(args, "Updating slot %s done", plan->target_slot->name);
		return TRUE;
	}

	g_free(slot_state->status);
	slot_state->status = g_strdup("update");

	r_context_end_step("check_slot", TRUE);

	install_args_update(args, "Updating slot %s", plan->target_slot->name);
	r_event_log_message(R_EVENT_LOG_TYPE_WRITE_SLOT, "Updating slot %s", plan->target_slot->name);

	/* update slot */
	if (plan->image->hooks.install) {
		g_message("Updating %s with 'install' slot hook", plan->target_slot->device);
	} else {
		if (plan->image->variant)
			g_message("Updating %s with %s (variant: %s)", plan->target_slot->device, plan->image->filename, plan->image->variant);
		else
			g_message("Updating %s with %s", plan->target_slot->device, plan->image->filename);
	}

	r_context_begin_step_weighted_formatted("copy_image", 0, 9, "Copying image to %s", plan->target_slot->name);

	if (!plan->slot_handler(plan->image, plan->target_slot, hook_name, &ierror)) {
		g_autoptr(GError) ierror_status = NULL;

		g_propagate_prefixed_error(error, ierror,
				"Failed updating slot %s: ", plan->target_slot->name);
		r_context_end_step("copy_image", FALSE);

		g_message("Updating slot %s status", plan->target_slot->name);
		update_slot_status(slot_state, "failed", manifest, plan, args);
		if (!r_slot_status_save(plan->target_slot, &ierror_status)) {
			g_warning("Error while writing status file after slot update failure: %s", ierror_status->message);
		}

		return FALSE;
	}

	r_context_end_step("copy_image", TRUE);

	g_message("Updating slot %s status", plan->target_slot->name);
	update_slot_status(slot_state, "ok", manifest, plan, args);
	if (!r_slot_status_save(plan->target_slot, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Error while writing status file: ");
		return FALSE;
	}

	install_args_update(args, "Updating slot %s done", plan->target_slot->name);
	return TRUE;
}

/* For each installation plan list, there should be one slot that we need to
 * mark bad and active for the bootloader.
 * In cases where we have only images for slots that are not part of the
 * redundancy scheme (e.g. bootloader-only updates), having no such slot at all
 * is also valid */
static RaucSlot* get_boot_mark_slot(const GPtrArray *install_plans)
{
	RaucSlot *bootslot = NULL;

	for (guint i = 0; i < install_plans->len; i++) {
		const RImageInstallPlan *plan = g_ptr_array_index(install_plans, i);

		g_assert_nonnull(plan->target_slot);

		if (plan->target_slot->parent || !plan->target_slot->bootname) {
			continue;
		}

		if (bootslot) {
			g_error("Inconsistency detected: "
					"Would need to activate more than one slot."
					"At least %s and %s have a bootname set and are about to be updated",
					bootslot->name, plan->target_slot->name);
		}

		bootslot = plan->target_slot;
	}

	return bootslot;
}

#define MESSAGE_ID_INSTALLATION_STARTED   "b05410e8a93345389cd061aab1e9516d"
#define MESSAGE_ID_INSTALLATION_SUCCEEDED "0163db5468ac4237b090d28490c301ed"
#define MESSAGE_ID_INSTALLATION_FAILED    "c48141f7fd49443aafff862b4809168f"
#define MESSAGE_ID_INSTALLATION_REJECTED  "60bea7e4fea549ccad68af457308b13a"

static void log_event_installation_started(RaucInstallArgs *args)
{
	g_log_structured(R_EVENT_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE,
			"RAUC_EVENT_TYPE", "install",
			"MESSAGE_ID", MESSAGE_ID_INSTALLATION_STARTED,
			"TRANSACTION_ID", args->transaction,
			"MESSAGE", "Installation %.8s started", args->transaction // truncate ID for readability
			);
}

/**
 * @param args RaucInstallArgs
 * @param manifest Manifest
 * @param GError Error or NULL
 */
static void log_event_installation_done(RaucInstallArgs *args, RaucManifest *manifest, const GError *error)
{
	g_autofree gchar *formatted = NULL;
	GLogField fields[] = {
		{"MESSAGE", NULL, -1 },
		{"MESSAGE_ID", NULL, -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "install", -1},
		{"BUNDLE_HASH", "", -1},
		{"BUNDLE_DESCRIPTION", "", -1},
		{"BUNDLE_VERSION", "", -1},
		{"TRANSACTION_ID", args->transaction, -1},
	};

	g_return_if_fail(args);

	if (error) {
		if (g_error_matches(error, R_INSTALL_ERROR, R_INSTALL_ERROR_REJECTED) ||
		    g_error_matches(error, R_INSTALL_ERROR, R_INSTALL_ERROR_COMPAT_MISMATCH)) {
			formatted = g_strdup_printf("Installation %.8s rejected: %s", args->transaction, error->message);
			fields[1].value = MESSAGE_ID_INSTALLATION_REJECTED;
		} else {
			formatted = g_strdup_printf("Installation %.8s failed: %s", args->transaction, error->message);
			fields[1].value = MESSAGE_ID_INSTALLATION_FAILED;
		}
	} else {
		formatted = g_strdup_printf("Installation %.8s succeeded", args->transaction);
		fields[1].value = MESSAGE_ID_INSTALLATION_SUCCEEDED;
	}

	fields[0].value = formatted;
	if (manifest) {
		fields[4].value = manifest->hash ?: "";
		fields[5].value = manifest->update_description ?: "";
		fields[6].value = manifest->update_version ?: "";
	}

	g_log_structured_array(G_LOG_LEVEL_MESSAGE, fields, G_N_ELEMENTS(fields));
}

static gboolean launch_and_wait_default_handler(RaucInstallArgs *args, gchar* bundledir, RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	g_autofree gchar *hook_name = NULL;
	GError *ierror = NULL;
	g_autoptr(GPtrArray) install_plans = NULL;
	RaucSlot *boot_mark_slot = NULL;

	install_plans = r_install_make_plans(manifest, target_group, &ierror);
	if (install_plans == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	boot_mark_slot = get_boot_mark_slot(install_plans);

	if (!pre_install_checks(bundledir, install_plans, target_group, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (boot_mark_slot) {
		/* Mark boot slot non-bootable */
		g_message("Marking target slot %s as non-bootable...", boot_mark_slot->name);
		if (!r_mark_bad(boot_mark_slot, &ierror)) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_NONBOOTABLE,
					"Failed marking slot %s non-bootable: %s", boot_mark_slot->name, ierror->message);
			g_clear_error(&ierror);
			return FALSE;
		}
	}

	if (manifest->hook_name)
		hook_name = g_build_filename(bundledir, manifest->hook_name, NULL);

	r_context_begin_step_weighted("update_slots", "Updating slots", install_plans->len * 10, 6);
	install_args_update(args, "Updating slots...");

	for (guint i = 0; i < install_plans->len; i++) {
		const RImageInstallPlan *plan = g_ptr_array_index(install_plans, i);

		if (!handle_slot_install_plan(manifest, plan, args, hook_name, &ierror)) {
			g_propagate_error(error, ierror);
			r_context_end_step("update_slots", FALSE);
			return FALSE;
		}
	}

	r_context_end_step("update_slots", TRUE);
	install_args_update(args, "All slots updated");

	if (boot_mark_slot) {
		if (r_context()->config->activate_installed) {
			/* Mark boot slot bootable */
			g_message("Marking target slot %s as bootable...", boot_mark_slot->name);
			if (!r_mark_active(boot_mark_slot, &ierror)) {
				g_propagate_prefixed_error(error, ierror,
						"Failed marking slot %s bootable: ", boot_mark_slot->name);
				return FALSE;
			}
		} else {
			g_message("Leaving target slot non-bootable as requested by activate_installed == false.");
		}
	}


	return TRUE;
}

static gchar* get_uptime(void)
{
	g_autofree gchar *contents = NULL;
	g_autoptr(GError) ierror = NULL;
	g_auto(GStrv) uptime = NULL;

	if (!g_file_get_contents("/proc/uptime", &contents, NULL, &ierror)) {
		g_warning("Failed to get uptime: %s", ierror->message);
		return NULL;
	}

	/* file contains two values and a newline, 'chomp' in-place and split then */
	uptime = g_strsplit(g_strchomp(contents), " ", 2);

	return g_strdup(uptime[0]);
}

/* If the input key starts with RAUC_HTTP_, it returns a valid HTTP header
 * string with 'RAUC_HTTP_' replaced by 'RAUC-'.
 * If the input string does not start with RAUC_HTTP_, NULL is returned.
 */
static gchar *system_info_to_header(const gchar *key, const gchar *value)
{
	g_autofree gchar *header_key = NULL;

	g_return_val_if_fail(key, NULL);
	g_return_val_if_fail(value, NULL);

	if (!g_str_has_prefix(key, "RAUC_HTTP_"))
		return NULL;

	header_key = g_strdup(key + strlen("RAUC_HTTP_"));
	for (size_t i = 0; i < strlen(header_key); i++) {
		if (header_key[i] == '_')
			header_key[i] = '-';
	}

	return g_strdup_printf("RAUC-%s: %s", header_key, value);
}

static gchar **assemble_info_headers(RaucInstallArgs *args)
{
	GPtrArray *headers = g_ptr_array_new_with_free_func(g_free);

	g_return_val_if_fail(args, NULL);

	if (!r_context()->config->enabled_headers)
		goto no_std_headers;

	for (gchar **header = r_context()->config->enabled_headers; *header; header++) {
		/* Add static system information */
		if (g_strcmp0(*header, "boot-id") == 0)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Boot-ID: %s", r_context()->boot_id));
		if (g_strcmp0(*header, "machine-id") == 0)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Machine-ID: %s", r_context()->machine_id));
		if (g_strcmp0(*header, "serial") == 0)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Serial: %s", r_context()->system_serial));
		if (g_strcmp0(*header, "variant") == 0)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Variant: %s", r_context()->config->system_variant));
		/* Add per-installation information */
		if (g_strcmp0(*header, "transaction-id") == 0)
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Transaction-ID: %s", args->transaction));
		/* Add live information */
		if (g_strcmp0(*header, "uptime") == 0) {
			g_autofree gchar *uptime = get_uptime();
			g_ptr_array_add(headers, g_strdup_printf("RAUC-Uptime: %s", uptime));
		}
	}

no_std_headers:

	if (r_context()->system_info) {
		GHashTableIter iter;
		gchar *key = NULL;
		gchar *value = NULL;

		g_hash_table_iter_init(&iter, r_context()->system_info);
		while (g_hash_table_iter_next(&iter, (gpointer*) &key, (gpointer*) &value)) {
			gchar *header = system_info_to_header(key, value);
			if (header)
				g_ptr_array_add(headers, header);
		}
	}
	g_ptr_array_add(headers, NULL);

	return (gchar**) g_ptr_array_free(headers, FALSE);
}

gboolean do_install_bundle(RaucInstallArgs *args, GError **error)
{
	const gchar* bundlefile = args->name;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GHashTable) target_group = NULL;
	g_auto(GStrv) handler_env = NULL;

	g_assert_nonnull(bundlefile);
	g_assert_null(r_context()->install_info->mounted_bundle);
	g_assert_true(r_context()->config->slot_states_determined);

	if (!args->transaction)
		args->transaction = g_uuid_string_random();

	r_context_begin_step("do_install_bundle", "Installing", 10);

	log_event_installation_started(args);

	r_context_begin_step("determine_slot_states", "Determining slot states", 0);
	res = update_external_mount_points(&ierror);
	r_context_end_step("determine_slot_states", res);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	// TODO: mount info in context ?
	install_args_update(args, "Checking and mounting bundle...");

	args->access_args.http_info_headers = assemble_info_headers(args);

	res = check_bundle(bundlefile, &bundle, CHECK_BUNDLE_DEFAULT, &args->access_args, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (bundle->manifest && bundle->manifest->bundle_format == R_MANIFEST_FORMAT_CRYPT && !bundle->was_encrypted) {
		g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_REJECTED, "Refusing to install unencrypted crypt bundles");
		res = FALSE;
		goto out;
	}

	res = mount_bundle(bundle, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed mounting bundle: ");
		goto umount;
	}

	r_context()->install_info->mounted_bundle = bundle;

	target_group = determine_target_install_group();
	if (!target_group) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_TARGET_GROUP, "Could not determine target group");
		res = FALSE;
		goto umount;
	}

	handler_env = prepare_environment(bundle->mount_point, bundle->manifest, target_group);
	handler_env = g_environ_setenv(handler_env, "RAUC_TRANSACTION_ID", args->transaction, TRUE);

	if (r_context()->config->preinstall_handler) {
		g_message("Starting pre install handler: %s", r_context()->config->preinstall_handler);
		res = launch_and_wait_handler(args, r_context()->config->preinstall_handler, NULL, handler_env, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Pre-install handler error: ");
			goto umount;
		}
	}

	/* Allow overriding compatible check by hook */
	if (bundle->manifest->hooks.install_check) {
		run_bundle_hook(bundle->manifest, bundle->mount_point, "install-check", &ierror);
		if (ierror) {
			res = FALSE;
			if (g_error_matches(ierror, R_INSTALL_ERROR, R_INSTALL_ERROR_REJECTED)) {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Bundle rejected: ");
			} else {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Install-check hook failed: ");
			}
			goto umount;
		}
	} else if (!verify_compatible(args, bundle->manifest, &ierror)) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto umount;
	}

	if (bundle->manifest->handler_name) {
		g_message("Using custom handler: %s", bundle->manifest->handler_name);
		res = launch_and_wait_custom_handler(args, bundle->mount_point, bundle->manifest, target_group, &ierror);
	} else {
		g_debug("Using default installation handler");
		res = launch_and_wait_default_handler(args, bundle->mount_point, bundle->manifest, target_group, &ierror);
	}

	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Installation error: ");
		goto umount;
	}

	if (r_context()->config->postinstall_handler) {
		g_message("Starting post install handler: %s", r_context()->config->postinstall_handler);
		res = launch_and_wait_handler(args, r_context()->config->postinstall_handler, NULL, handler_env, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Post-install handler error: ");
			goto umount;
		}
	}


	res = TRUE;

umount:
	if (bundle->mount_point) {
		umount_bundle(bundle, NULL);
	}
	r_context()->install_info->mounted_bundle = NULL;

out:
	log_event_installation_done(args, bundle ? bundle->manifest : NULL, error ? *error : NULL);

	r_context_end_step("do_install_bundle", res);

	return res;
}

static gboolean install_done(gpointer data)
{
	RaucInstallArgs *args = data;

	args->cleanup(args);

	r_context_set_busy(FALSE);

	return G_SOURCE_REMOVE;
}

static gpointer install_thread(gpointer data)
{
	GError *ierror = NULL;
	RaucInstallArgs *args = data;
	gint result;

	/* clear LastError property */
	set_last_error("");

	g_debug("thread started for %s", args->name);
	install_args_update(args, "started");

	result = !do_install_bundle(args, &ierror);

	if (result != 0) {
		g_warning("%s", ierror->message);
		install_args_update(args, "%s", ierror->message);
		set_last_error(ierror->message);
		g_clear_error(&ierror);
	}

	g_mutex_lock(&args->status_mutex);
	args->status_result = result;
	g_mutex_unlock(&args->status_mutex);
	install_args_update(args, "finished");
	g_debug("thread finished for %s", args->name);

	g_main_context_invoke(NULL, install_done, args);
	return NULL;
}

RaucInstallArgs *install_args_new(void)
{
	RaucInstallArgs *args = g_new0(RaucInstallArgs, 1);

	g_mutex_init(&args->status_mutex);
	g_queue_init(&args->status_messages);
	args->status_result = -2;

	return args;
}

void install_args_free(RaucInstallArgs *args)
{
	g_free(args->name);
	g_free(args->transaction);
	g_mutex_clear(&args->status_mutex);
	g_assert_cmpint(args->status_result, >=, 0);
	g_assert_true(g_queue_is_empty(&args->status_messages));
	clear_bundle_access_args(&args->access_args);
	g_free(args);
}

gboolean install_run(RaucInstallArgs *args)
{
	g_autoptr(GThread) thread = NULL;
	r_context_set_busy(TRUE);

	g_message("Active slot bootname: %s", r_context()->bootslot);

	thread = g_thread_new("installer", install_thread, args);
	if (thread == NULL)
		return FALSE;

	return TRUE;
}

static const gchar *supported_http_headers[] = {"boot-id", "transaction-id", "machine-id", "serial", "variant", "uptime", NULL};

gboolean r_install_is_supported_http_header(const gchar *header)
{
	return g_strv_contains(supported_http_headers, header);
}
