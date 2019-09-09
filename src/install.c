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
#include "install.h"
#include "manifest.h"
#include "mark.h"
#include "mount.h"
#include "service.h"
#include "signature.h"
#include "update_handler.h"
#include "utils.h"

/* All exit codes of hook script above this mean 'rejected' */
#define INSTALL_HOOK_REJECT_CODE 10

#define R_INSTALL_ERROR r_install_error_quark()

GQuark r_install_error_quark(void)
{
	return g_quark_from_static_string("r_install_error_quark");
}

static void install_args_update(RaucInstallArgs *args, const gchar *msg)
{
	g_mutex_lock(&args->status_mutex);
	g_queue_push_tail(&args->status_messages, g_strdup(msg));
	g_mutex_unlock(&args->status_mutex);
	g_main_context_invoke(NULL, args->notify, args);
}

static gchar *resolve_loop_device(const gchar *devicepath)
{
	g_autofree gchar *devicename = NULL;
	g_autofree gchar *syspath = NULL;
	gchar *content = NULL;
	GError *ierror = NULL;

	if (!g_str_has_prefix(devicepath, "/dev/loop"))
		return g_strdup(devicepath);

	devicename = g_path_get_basename(devicepath);
	syspath = g_build_filename("/sys/block", devicename, "loop/backing_file", NULL);

	content = read_file_str(syspath, &ierror);
	if (!content) {
		g_message("%s", ierror->message);
		g_clear_error(&ierror);
		return NULL;
	}

	/* g_strchomp modifies the string and returns it */
	return g_strchomp(content);
}

gboolean determine_slot_states(GError **error)
{
	GList *slotlist = NULL;
	GList *mountlist = NULL;
	RaucSlot *booted = NULL;
	GHashTableIter iter;
	RaucSlot *slot;
	gboolean res = FALSE;

	g_assert_nonnull(r_context()->config);

	if (r_context()->config->slots == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_CONFIG,
				"No slot configuration found");
		goto out;
	}
	g_assert_nonnull(r_context()->config->slots);

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
		g_autofree gchar *devicepath = resolve_loop_device(g_unix_mount_get_device_path(m));
		RaucSlot *s = find_config_slot_by_device(r_context()->config,
				devicepath);
		if (s) {
			/* We might have multiple mount entries matching the same device and thus the same slot.
			 * To avoid leaking the string returned by g_unix_mount_get_mount_path() here, we skip all further matches
			 */
			if (s->ext_mount_point) {
				break;
			}
			s->ext_mount_point = g_strdup(g_unix_mount_get_mount_path(m));
			g_debug("Found external mountpoint for slot %s at %s", s->name, s->ext_mount_point);
		}
	}
	g_list_free_full(mountlist, (GDestroyNotify)g_unix_mount_free);

	if (r_context()->bootslot == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_BOOTSLOT,
				"Bootname or device of booted slot not found");
		goto out;
	}

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		gchar buf[PATH_MAX + 1];
		gchar *realdev = NULL;

		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);

		if (g_strcmp0(s->bootname, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}

		if (g_strcmp0(s->name, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}

		realdev = realpath(s->device, buf);
		if (realdev == NULL) {
			g_message("Failed to resolve realpath for '%s'", s->device);
			realdev = s->device;
		}

		if (g_strcmp0(realdev, r_context()->bootslot) == 0) {
			booted = s;
			break;
		}
	}


	if (booted) {
		booted->state = ST_BOOTED;
		g_debug("Found booted slot: %s on %s", booted->name, booted->device);
	}

	/* Determine active group members */
	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);

		if (s->parent) {
			if (s->parent->state & ST_ACTIVE) {
				s->state |= ST_ACTIVE;
			} else {
				s->state |= ST_INACTIVE;
			}
		} else {
			if (s->state == ST_UNKNOWN)
				s->state |= ST_INACTIVE;
		}
	}

	if (!booted) {
		if (g_strcmp0(r_context()->bootslot, "/dev/nfs") == 0) {
			g_message("Detected nfs boot, ignoring missing active slot");
			res = TRUE;
			goto out;
		}

		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				R_SLOT_ERROR_NO_SLOT_WITH_STATE_BOOTED,
				"Did not find booted slot");
		goto out;
	}

	res = TRUE;

out:
	g_clear_pointer(&slotlist, g_list_free);

	return res;
}

gboolean determine_boot_states(GError **error)
{
	GHashTableIter iter;
	RaucSlot *slot;
	gchar *name;
	GError *ierror = NULL;

	/* get boot state */
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, (gpointer*) &name, (gpointer*) &slot)) {
		if (slot->bootname && !r_boot_get_state(slot, &slot->boot_good, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

/* Returns newly allocated NULL-teminated string array of all classes listed in
 * given manifest.
 * Free with g_strfreev */
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
static RaucSlot *select_inactive_slot_class_member(gchar *rootclass)
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
	gchar **rootclasses = NULL;
	GHashTable *targetgroup = NULL;
	GHashTableIter iter;
	RaucSlot *iterslot = NULL;
	GList *selected_root_slots = NULL;

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


GList* get_install_images(const RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	GList *install_images = NULL;
	gchar **slotclasses = NULL;

	g_return_val_if_fail(manifest != NULL, NULL);
	g_return_val_if_fail(target_group != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	slotclasses = get_all_manifest_slot_classes(manifest);

	/* Find exactly 1 image for each class listed in manifest */
	for (gchar **cls = slotclasses; *cls != NULL; cls++) {
		RaucImage *matching_img = NULL;

		for (GList *l = manifest->images; l != NULL; l = l->next) {
			RaucImage *lookup_image = l->data;
			RaucSlot *target_slot = NULL;

			/* Not interested in slots of other classes */
			if (g_strcmp0(lookup_image->slotclass, *cls) != 0)
				continue;

			/* Check if target_group contains an appropriate slot for this image */
			target_slot = g_hash_table_lookup(target_group, lookup_image->slotclass);
			if (!target_slot) {
				g_set_error(error,
						R_INSTALL_ERROR,
						R_INSTALL_ERROR_FAILED,
						"No target slot for class %s of image %s found", lookup_image->slotclass, lookup_image->filename);
				g_clear_pointer(&install_images, g_list_free);
				goto out;
			}

			if (target_slot->readonly) {
				g_set_error(error,
						R_INSTALL_ERROR,
						R_INSTALL_ERROR_FAILED,
						"Target slot for class %s of image %s is readonly", lookup_image->slotclass, lookup_image->filename);
				g_clear_pointer(&install_images, g_list_free);
				goto out;
			}

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
			g_clear_pointer(&install_images, g_list_free);
			goto out;
		}

		g_debug("Found image mapping: %s -> %s", matching_img->filename, matching_img->slotclass);
		install_images = g_list_append(install_images, matching_img);
	}

	if (!install_images)
		g_set_error_literal(error,
				R_INSTALL_ERROR,
				R_INSTALL_ERROR_FAILED,
				"No install image found");
out:

	return install_images;
}

static void parse_handler_output(gchar* line)
{
	g_auto(GStrv) split = NULL;

	g_assert_nonnull(line);

	if (!g_str_has_prefix(line, "<< ")) {
		g_print("# %s\n", line);
		return;
	}

	split = g_strsplit(line, " ", 5);

	if (!split[1])
		return;

	if (g_strcmp0(split[1], "handler") == 0) {
		g_print("Handler status: %s\n", split[2]);
	} else if (g_strcmp0(split[1], "image") == 0) {
		g_print("Image '%s' status: %s\n", split[2], split[3]);
	} else if (g_strcmp0(split[1], "error") == 0) {
		g_print("error: '%s'\n", split[2]);
	} else if (g_strcmp0(split[1], "bootloader") == 0) {
		g_print("error: '%s'\n", split[2]);
	} else {
		g_print("Unknown command: %s\n", split[1]);
	}
}

static gboolean verify_compatible(RaucManifest *manifest)
{
	if (r_context()->ignore_compatible) {
		return TRUE;
	} else if (g_strcmp0(r_context()->config->system_compatible,
			manifest->update_compatible) == 0) {
		return TRUE;
	} else {
		g_warning("incompatible manifest for this system (%s): %s",
				r_context()->config->system_compatible,
				manifest->update_compatible);
		return FALSE;
	}
}

static void prepare_environment(GSubprocessLauncher *launcher, gchar *update_source, RaucManifest *manifest, GHashTable *target_group)
{
	GHashTableIter iter;
	RaucSlot *slot;
	gint slotcnt = 0;
	g_autofree gchar *targetlist = NULL;
	g_autofree gchar *slotlist = NULL;

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_CONFIG", r_context()->configpath, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_CURRENT_BOOTNAME", r_context()->bootslot, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_UPDATE_SOURCE", update_source, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		gchar *varname;
		gchar *tmp;
		GHashTableIter iiter;
		gpointer member;

		slotcnt++;

		tmp = g_strdup_printf("%s%i ", slotlist ? slotlist : "", slotcnt);
		g_clear_pointer(&slotlist, g_free);
		slotlist = tmp;

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
					g_subprocess_launcher_setenv(launcher, varname, img->filename, TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_DIGEST_%i", slotcnt);
					g_subprocess_launcher_setenv(launcher, varname, img->checksum.digest, TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_CLASS_%i", slotcnt);
					g_subprocess_launcher_setenv(launcher, varname, img->slotclass, TRUE);
					g_clear_pointer(&varname, g_free);

					break;
				}
			}

			tmp = g_strdup_printf("%s%i ", targetlist ? targetlist : "", slotcnt);
			g_clear_pointer(&targetlist, g_free);
			targetlist = tmp;
		}

		varname = g_strdup_printf("RAUC_SLOT_NAME_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->name, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_CLASS_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->sclass, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_TYPE_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->type, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_DEVICE_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->device, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_BOOTNAME_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->bootname ? slot->bootname : "", TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_PARENT_%i", slotcnt);
		g_subprocess_launcher_setenv(launcher, varname, slot->parent ? slot->parent->name : "", TRUE);
		g_clear_pointer(&varname, g_free);
	}

	g_subprocess_launcher_setenv(launcher, "RAUC_SLOTS", slotlist, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_TARGET_SLOTS", targetlist, TRUE);
}

static gboolean launch_and_wait_handler(gchar *update_source, gchar *handler_name, RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	g_autoptr(GSubprocessLauncher) handlelaunch = NULL;
	g_autoptr(GSubprocess) handleproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GInputStream *instream = NULL;
	g_autoptr(GDataInputStream) datainstream = NULL;
	gchar *outline;

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	prepare_environment(handlelaunch, update_source, manifest, target_group);

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch, &ierror,
			handler_name,
			manifest->handler_args,
			NULL);
	if (handleproc == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(handleproc);
	datainstream = g_data_input_stream_new(instream);

	do {
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline)
			continue;

		parse_handler_output(outline);

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
	gchar *outline, *hookreturnmsg = NULL;

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
	g_autofree gchar* handler_name = NULL;
	gboolean res = FALSE;

	r_context_begin_step("launch_and_wait_custom_handler", "Launching update handler", 0);

	/* Allow overriding compatible check by hook */
	if (manifest->hooks.install_check) {
		GError *ierror = NULL;
		run_bundle_hook(manifest, bundledir, "install-check", &ierror);
		if (ierror) {
			g_propagate_error(error, ierror);
			res = FALSE;
			goto out;
		}
	} else if (!verify_compatible(manifest)) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_COMPAT_MISMATCH,
				"Compatible mismatch");
		res = FALSE;
		goto out;
	}

	handler_name = g_build_filename(bundledir, manifest->handler_name, NULL);

	res = launch_and_wait_handler(bundledir, handler_name, manifest, target_group, error);

out:
	r_context_end_step("launch_and_wait_custom_handler", res);
	return res;
}

static gboolean pre_install_checks(gchar* bundledir, GList *install_images, GHashTable *target_group, GError **error)
{
	for (GList *l = install_images; l != NULL; l = l->next) {
		RaucImage *mfimage = l->data;
		RaucSlot *dest_slot = g_hash_table_lookup(target_group, mfimage->slotclass);

		/* if image filename is relative, make it absolute */
		if (!g_path_is_absolute(mfimage->filename)) {
			gchar *filename = g_build_filename(bundledir, mfimage->filename, NULL);
			g_free(mfimage->filename);
			mfimage->filename = filename;
		}

		if (!g_file_test(mfimage->filename, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NOSRC,
					"Source image '%s' not found", mfimage->filename);
			return FALSE;
		}

		if (!g_file_test(dest_slot->device, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NODST,
					"Destination device '%s' not found", dest_slot->device);
			return FALSE;
		}

		if (dest_slot->mount_point || dest_slot->ext_mount_point) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MOUNTED,
					"Destination device '%s' already mounted", dest_slot->device);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean launch_and_wait_default_handler(RaucInstallArgs *args, gchar* bundledir, RaucManifest *manifest, GHashTable *target_group, GError **error)
{
	gchar *hook_name = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GList *install_images = NULL;
	RaucImage *mfimage;

	install_images = get_install_images(manifest, target_group, &ierror);
	if (install_images == NULL) {
		g_propagate_error(error, ierror);
		goto early_out;
	}

	/* Allow overriding compatible check by hook */
	if (manifest->hooks.install_check) {
		run_bundle_hook(manifest, bundledir, "install-check", &ierror);
		if (ierror) {
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
			res = FALSE;
			goto early_out;
		}
	} else if (!verify_compatible(manifest)) {
		res = FALSE;
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_COMPAT_MISMATCH,
				"Compatible mismatch");
		goto early_out;
	}

	res = pre_install_checks(bundledir, install_images, target_group, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto early_out;
	}

	/* Mark all parent destination slots non-bootable */
	for (GList *l = install_images; l != NULL; l = l->next) {
		RaucSlot *dest_slot = g_hash_table_lookup(target_group, ((RaucImage*)l->data)->slotclass);

		g_assert_nonnull(dest_slot);

		if (dest_slot->parent || !dest_slot->bootname) {
			continue;
		}

		g_message("Marking target slot %s as non-bootable...", dest_slot->name);
		res = r_boot_set_state(dest_slot, FALSE, &ierror);

		if (!res) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_NONBOOTABLE,
					"Failed marking slot %s non-bootable: %s", dest_slot->name, ierror->message);
			g_clear_error(&ierror);
			goto early_out;
		}
	}

	if (manifest->hook_name)
		hook_name = g_build_filename(bundledir, manifest->hook_name, NULL);

	r_context_begin_step("update_slots", "Updating slots", g_list_length(install_images) * 2);
	install_args_update(args, "Updating slots...");
	for (GList *l = install_images; l != NULL; l = l->next) {
		RaucSlot *dest_slot;
		img_to_slot_handler update_handler = NULL;
		RaucSlotStatus *slot_state = NULL;
		GDateTime *now;

		mfimage = l->data;
		dest_slot = g_hash_table_lookup(target_group, mfimage->slotclass);

		/* Verify image checksum (for non-casync images) */
		if (!g_str_has_suffix(mfimage->filename, ".caibx") && !g_str_has_suffix(mfimage->filename, ".caidx")) {
			res = verify_checksum(&mfimage->checksum, mfimage->filename, &ierror);
			if (!res) {
				g_propagate_prefixed_error(error, ierror, "Failed verifying checksum: ");
				goto out;
			}
		}

		/* determine whether update image type is compatible with destination slot type */
		update_handler = get_update_handler(mfimage, dest_slot, &ierror);
		if (update_handler == NULL) {
			res = FALSE;
			g_propagate_error(error, ierror);
			goto out;
		}

		install_args_update(args, g_strdup_printf("Checking slot %s", dest_slot->name));

		r_context_begin_step_formatted("check_slot", 0, "Checking slot %s", dest_slot->name);

		load_slot_status(dest_slot);
		slot_state = dest_slot->status;

		/* In case we failed unmounting while reading status
		 * file, abort here */
		if (dest_slot->mount_point) {
			res = FALSE;
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MOUNTED,
					"Slot '%s' still mounted", dest_slot->device);
			r_context_end_step("check_slot", FALSE);

			goto out;
		}

		/* if explicitly enabled, skip update of up-to-date slots */
		if (!dest_slot->install_same && g_strcmp0(mfimage->checksum.digest, slot_state->checksum.digest) == 0) {
			install_args_update(args, g_strdup_printf("Skipping update for correct image %s", mfimage->filename));
			g_message("Skipping update for correct image %s", mfimage->filename);
			r_context_end_step("check_slot", TRUE);

			/* Dummy step to indicate slot was skipped */
			r_context_begin_step("skip_image", "Copying image skipped", 0);
			r_context_end_step("skip_image", TRUE);

			goto image_out;
		}

		g_free(slot_state->status);
		slot_state->status = g_strdup("update");

		g_message("Slot needs to be updated with %s", mfimage->filename);

		r_context_end_step("check_slot", TRUE);

		install_args_update(args, g_strdup_printf("Updating slot %s", dest_slot->name));

		/* update slot */
		if (mfimage->variant)
			g_message("Updating %s with %s (variant: %s)", dest_slot->device, mfimage->filename, mfimage->variant);
		else
			g_message("Updating %s with %s", dest_slot->device, mfimage->filename);

		r_context_begin_step_formatted("copy_image", 0, "Copying image to %s", dest_slot->name);

		res = update_handler(
				mfimage,
				dest_slot,
				hook_name,
				&ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror,
					"Failed updating slot %s: ", dest_slot->name);
			r_context_end_step("copy_image", FALSE);
			goto out;
		}

		g_free(slot_state->bundle_compatible);
		g_free(slot_state->bundle_version);
		g_free(slot_state->bundle_description);
		g_free(slot_state->bundle_build);
		g_free(slot_state->status);
		g_free(slot_state->checksum.digest);
		g_free(slot_state->installed_timestamp);

		now = g_date_time_new_now_utc();

		slot_state->bundle_compatible = g_strdup(manifest->update_compatible);
		slot_state->bundle_version = g_strdup(manifest->update_version);
		slot_state->bundle_description = g_strdup(manifest->update_description);
		slot_state->bundle_build = g_strdup(manifest->update_build);
		slot_state->status = g_strdup("ok");
		slot_state->checksum.type = mfimage->checksum.type;
		slot_state->checksum.digest = g_strdup(mfimage->checksum.digest);
		slot_state->checksum.size = mfimage->checksum.size;
		slot_state->installed_timestamp = g_date_time_format(now, "%Y-%m-%dT%H:%M:%SZ");
		slot_state->installed_count++;

		g_date_time_unref(now);

		r_context_end_step("copy_image", TRUE);

		install_args_update(args, g_strdup_printf("Updating slot %s status", dest_slot->name));
		res = save_slot_status(dest_slot, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Error while writing status file: ");
			goto out;
		}

image_out:

		install_args_update(args, g_strdup_printf("Updating slot %s done", dest_slot->name));
	}

	if (r_context()->config->activate_installed) {
		/* Mark all parent destination slots bootable */
		for (GList *l = install_images; l != NULL; l = l->next) {
			RaucSlot *dest_slot = g_hash_table_lookup(target_group, ((RaucImage*)l->data)->slotclass);

			if (dest_slot->parent || !dest_slot->bootname)
				continue;

			g_message("Marking target slot %s as bootable...", dest_slot->name);
			mark_active(dest_slot, &ierror);
			if (g_error_matches(ierror, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_BOOTABLE)) {
				g_propagate_prefixed_error(error, ierror,
						"Failed marking slot %s bootable: ", dest_slot->name);
				res = FALSE;
				goto out;
			} else if (g_error_matches(ierror, R_INSTALL_ERROR, R_INSTALL_ERROR_FAILED)) {
				g_propagate_prefixed_error(error, ierror,
						"Marked slot %s bootable, but failed to write status file: ",
						dest_slot->name);
				res = FALSE;
				goto out;
			} else if (ierror) {
				g_propagate_prefixed_error(error, ierror,
						"Unexpected error while trying to mark slot %s bootable: ",
						dest_slot->name);
				res = FALSE;
				goto out;
			}
		}
	} else {
		g_message("Leaving target slot non-bootable as requested by activate_installed == false.");
	}

	install_args_update(args, "All slots updated");

	res = TRUE;

out:
	//g_free(hook_name);
	r_context_end_step("update_slots", res);
early_out:
	return res;
}

gboolean do_install_bundle(RaucInstallArgs *args, GError **error)
{
	const gchar* bundlefile = args->name;
	GError *ierror = NULL;
	gboolean res = FALSE;
	g_autoptr(RaucManifest) manifest = NULL;
	g_autoptr(RaucBundle) bundle = NULL;
	GHashTable *target_group;
	g_autofree gchar* manifestpath = NULL;

	g_assert_nonnull(bundlefile);
	g_assert_null(r_context()->install_info->mounted_bundle);

	r_context_begin_step("do_install_bundle", "Installing", 5);

	r_context_begin_step("determine_slot_states", "Determining slot states", 0);
	res = determine_slot_states(&ierror);
	r_context_end_step("determine_slot_states", res);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	// TODO: mount info in context ?
	install_args_update(args, "Checking and mounting bundle...");

	res = check_bundle(bundlefile, &bundle, TRUE, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
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

	manifestpath = g_build_filename(bundle->mount_point, "manifest.raucm", NULL);
	res = load_manifest_file(manifestpath, &manifest, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed loading manifest: ");
		goto umount;
	}

	target_group = determine_target_install_group();
	if (!target_group) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_TARGET_GROUP, "Could not determine target group");
		res = FALSE;
		goto umount;
	}

	if (r_context()->config->preinstall_handler) {
		g_message("Starting pre install handler: %s", r_context()->config->preinstall_handler);
		res = launch_and_wait_handler(bundle->mount_point, r_context()->config->preinstall_handler, manifest, target_group, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Pre-install handler error: ");
			goto umount;
		}
	}


	if (manifest->handler_name) {
		g_message("Using custom handler: %s", manifest->handler_name);
		res = launch_and_wait_custom_handler(args, bundle->mount_point, manifest, target_group, &ierror);
	} else {
		g_debug("Using default installation handler");
		res = launch_and_wait_default_handler(args, bundle->mount_point, manifest, target_group, &ierror);
	}

	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Installation error: ");
		goto umount;
	}

	if (r_context()->config->postinstall_handler) {
		g_message("Starting post install handler: %s", r_context()->config->postinstall_handler);
		res = launch_and_wait_handler(bundle->mount_point, r_context()->config->postinstall_handler, manifest, target_group, &ierror);
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
	set_last_error(g_strdup(""));

	g_debug("thread started for %s", args->name);
	install_args_update(args, "started");

	result = !do_install_bundle(args, &ierror);

	if (result != 0) {
		g_warning("%s", ierror->message);
		install_args_update(args, ierror->message);
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
	g_mutex_clear(&args->status_mutex);
	g_assert_cmpint(args->status_result, >=, 0);
	g_assert_true(g_queue_is_empty(&args->status_messages));
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
