#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include <context.h>
#include <network.h>
#include <signature.h>
#include "install.h"
#include "manifest.h"
#include "bundle.h"
#include "mount.h"
#include "utils.h"
#include "bootchooser.h"
#include "service.h"
#include "update_handler.h"
#include <sys/ioctl.h>
#include <gio/gfiledescriptorbased.h>
#include <gio/gunixmounts.h>
#include <gio/gunixoutputstream.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <config.h>

/* All exit codes of hook script above this mean 'rejected' */
#define INSTALL_HOOK_REJECT_CODE 10

#define R_SLOT_ERROR r_slot_error_quark ()

static GQuark r_slot_error_quark (void)
{
	return g_quark_from_static_string ("r_slot_error_quark");
}

#define R_INSTALL_ERROR r_install_error_quark ()

GQuark r_install_error_quark (void)
{
	return g_quark_from_static_string ("r_install_error_quark");
}

static void install_args_update(RaucInstallArgs *args, const gchar *msg) {
	g_mutex_lock(&args->status_mutex);
	g_queue_push_tail(&args->status_messages, g_strdup(msg));
	g_mutex_unlock(&args->status_mutex);
	g_main_context_invoke(NULL, args->notify, args);
}

static const gchar* get_cmdline_bootname(void) {
	GRegex *regex = NULL;
	GMatchInfo *match = NULL;
	char *contents = NULL;
	static const char *bootname = NULL;

	if (bootname != NULL)
		return bootname;

	if (!g_file_get_contents("/proc/cmdline", &contents, NULL, NULL))
		return NULL;

	regex = g_regex_new("rauc\\.slot=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		bootname = g_match_info_fetch(match, 1);
		goto out;
	}
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);

	/* For barebox, we check if the bootstate code set the active slot name
	 * in the command line */
	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		regex = g_regex_new("(?:bootstate|bootchooser)\\.active=(\\S+)", 0, 0, NULL);
		if (g_regex_match(regex, contents, 0, &match)) {
			bootname = g_match_info_fetch(match, 1);
			goto out;
		}
		g_clear_pointer(&match, g_match_info_free);
		g_clear_pointer(&regex, g_regex_unref);
	}

	regex = g_regex_new("root=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		bootname = g_match_info_fetch(match, 1);
		goto out;
	}

out:
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&contents, g_free);

	return bootname;
}

static const gchar* (*bootname_provider)(void) = get_cmdline_bootname;

void set_bootname_provider(const gchar* (*provider)(void)) {
	bootname_provider = provider;
}

const gchar* get_bootname(void) {
	return bootname_provider();
}

static gchar *resolve_loop_device(const gchar *devicepath) {
	gchar *devicename = NULL;
	gchar *syspath = NULL;
	gchar *res = NULL;

	if (!g_str_has_prefix(devicepath, "/dev/loop"))
		return g_strdup(devicepath);

	devicename = g_path_get_basename(devicepath);
	syspath = g_build_filename("/sys/block", devicename, "loop/backing_file", NULL);
	res = g_strchomp(read_file_str(syspath, NULL));

	g_free(syspath);
	g_free(devicename);

	return res;
}

gboolean determine_slot_states(GError **error) {
	GList *slotlist = NULL;
	GList *mountlist = NULL;
	const gchar *bootname;
	RaucSlot *booted = NULL;
	gboolean res = FALSE;

	g_assert_nonnull(r_context()->config);

	r_context_begin_step("determine_slot_states", "Determining slot states", 0);

	if (r_context()->config->slots == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				1,
				"No slot configuration found");
		goto out;
	}
	g_assert_nonnull(r_context()->config->slots);

	/* Determine active slot mount points */
	mountlist = g_unix_mounts_get(NULL);
	for (GList *l = mountlist; l != NULL; l = l->next) {
		GUnixMountEntry *m = (GUnixMountEntry*)l->data;
		gchar *devicepath = resolve_loop_device(g_unix_mount_get_device_path(m));
		RaucSlot *s = find_config_slot_by_device(r_context()->config,
				devicepath);
		if (s) {
			s->mount_point = g_strdup(g_unix_mount_get_mount_path(m));
			g_debug("Found mountpoint for slot %s at %s", s->name, s->mount_point);
		}
		g_free(devicepath);
	}
	g_list_free_full(mountlist, (GDestroyNotify)g_unix_mount_free);

	bootname = bootname_provider();
	if (bootname == NULL) {
		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				2,
				"Bootname not found");
		goto out;
	}

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);
		if (!s->bootname) {
			continue;
		}

		if (g_strcmp0(s->bootname, bootname) == 0) {
			booted = s;
			break;
		}

		if (g_strcmp0(s->device, bootname) == 0) {
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

		if (g_strcmp0(bootname, "/dev/nfs") == 0) {
			g_message("Detected nfs boot, ignoring missing active slot");
			res = TRUE;
			goto out;
		}

		g_set_error_literal(
				error,
				R_SLOT_ERROR,
				3,
				"Did not find booted slot");
		goto out;
	}

	res = TRUE;

out:
	g_clear_pointer(&slotlist, g_list_free);
	r_context_end_step("determine_slot_states", res);

	return res;
}

/* Returns the inactive slots for a given slot class */
static GList* get_inactive_slot_class_members(const gchar* slotclass) {
	GList *members = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_assert_nonnull(slotclass);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		/* only collect inactive slots */
		if (slot->state != ST_INACTIVE)
			continue;

		if (g_strcmp0(slot->sclass, slotclass) == 0) {
			members = g_list_append(members, slot);
		}
	}

	return members;
}

/* Returns inactive base parent slot for given slot (if available), otherwise
 * NULL */
static RaucSlot* get_inactive_base_slot(RaucSlot *slot) {
	RaucSlot *base = NULL;

	g_assert_nonnull(slot);

	base = (slot->state == ST_INACTIVE) ? slot : NULL;
	while (base != NULL && base->parent != NULL)
		base = (base->parent->state == ST_INACTIVE) ? base->parent : NULL;

	return base;
}

GHashTable* determine_target_install_group(RaucManifest *manifest) {
	GPtrArray *slotclasses = NULL;
	GHashTable *bases = NULL;
	GHashTable *targetgroup = NULL;
	gboolean res = FALSE;

	r_context_begin_step("determine_target_install_group", "Determining target install group", 0);

	/* collect referenced slot classes from manifest */
	slotclasses = g_ptr_array_new();
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		const gchar *key = g_intern_string(((RaucImage*)l->data)->slotclass);
		g_ptr_array_add(slotclasses, (gpointer)key);
	}
	for (GList *l = manifest->files; l != NULL; l = l->next) {
		const gchar *key = g_intern_string(((RaucFile*)l->data)->slotclass);
		g_ptr_array_remove_fast(slotclasses, (gpointer)key); /* avoid duplicates */
		g_ptr_array_add(slotclasses, (gpointer)key);
	}

	g_assert_cmpuint(slotclasses->len, >, 0);

	/* slots with no parent, already selected for installing */
	bases = g_hash_table_new(NULL, NULL); /* keys are interned strings */
	targetgroup = g_hash_table_new(g_str_hash, g_str_equal);

	/* iterate over each slot class mentioned in manifest */
	for (guint i = 0; i < slotclasses->len; i++) {
		const gchar *slotclass = slotclasses->pdata[i];
		GList *slotmembers;
		RaucSlot *target_slot = NULL;

		/* iterate over each inactive slot in this slot class */
		slotmembers = get_inactive_slot_class_members(slotclass);
		for (GList *l = slotmembers; l != NULL; l = l->next) {
			RaucSlot *base, *known_base = NULL;
			RaucSlot *slot = (RaucSlot*) l->data;
			base = get_inactive_base_slot(slot);
			/* check if we have found a base for this class already */
			known_base = (RaucSlot *)g_hash_table_lookup(bases, (gpointer)base->sclass);
			if (known_base) {
				/* if we already have another base selected for this, skip */
				if (base->name != known_base->name)
					continue;
			} else {
				g_hash_table_insert(bases, (gpointer)base->sclass, base);
			}

			target_slot = slot;
			break;
		}
		g_list_free(slotmembers);

		if (target_slot == NULL) {
			g_warning("No target for class '%s' found!", slotclass);
			res = FALSE;
			goto out;
		}

		g_print("Adding to target group: %s -> %s\n", target_slot->sclass, target_slot->name);
		g_hash_table_insert(targetgroup, (gpointer)target_slot->sclass, target_slot);
	}

	res = TRUE;

out:
	if (!res)
		g_clear_pointer(&targetgroup, g_hash_table_unref);
	g_clear_pointer(&bases, g_hash_table_unref);
	g_clear_pointer(&slotclasses, g_ptr_array_unref);
	r_context_end_step("determine_target_install_group", res);

	return targetgroup;
}

static void parse_handler_output(gchar* line) {
	gchar **split = NULL;

	g_assert_nonnull(line);

	if (!g_str_has_prefix(line, "<< ")) {
		g_print("# %s\n", line);
		goto out;
	}

	split = g_strsplit(line, " ", 5);

	if (!split[1])
		goto out;

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

out:
	g_strfreev(split);
}

static gboolean verify_compatible(RaucManifest *manifest) {
	if (g_strcmp0(r_context()->config->system_compatible,
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
	gchar *targetlist = NULL;
	gchar *slotlist = NULL;

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_CONFIG", r_context()->configpath, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_CURRENT_BOOTNAME", bootname_provider(), TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_UPDATE_SOURCE", update_source, TRUE);
	g_subprocess_launcher_setenv(launcher, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
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
	g_clear_pointer(&targetlist, g_free);
	g_clear_pointer(&slotlist, g_free);
}

static gboolean launch_and_wait_handler(gchar *update_source, gchar *handler_name, RaucManifest *manifest, GHashTable *target_group, GError **error) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GInputStream *instream = NULL;
	GDataInputStream *datainstream = NULL;
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
	} while (outline);
	
	res = g_subprocess_wait_check(handleproc, NULL, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;

out:
	g_clear_pointer(&handlelaunch, g_object_unref);
	g_clear_pointer(&handleproc, g_object_unref);
	return res;
}

static gboolean run_bundle_hook(RaucManifest *manifest, gchar* bundledir, const gchar *hook_cmd, GError **error) {
	gchar *hook_name = NULL;
	GSubprocessLauncher *launcher = NULL;
	GSubprocess *sproc = NULL;
	GError *ierror = NULL;
	GInputStream *instream = NULL;
	GDataInputStream *datainstream = NULL;
	gboolean res = FALSE;
	gchar *outline, *hookreturnmsg = NULL;

	g_assert_nonnull(manifest->hook_name);

	hook_name = g_build_filename(bundledir, manifest->hook_name, NULL);

	g_message("Running bundle hook %s", hook_cmd);

	launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDERR_PIPE);

	g_subprocess_launcher_setenv(launcher, "RAUC_SYSTEM_COMPATIBLE", r_context()->config->system_compatible, TRUE);
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
				g_propagate_prefixed_error (
						error,
						ierror,
						"Hook returned with exit code %d: ", ierror->code);
			}
		} else {
			g_propagate_prefixed_error (
					error,
					ierror,
					"failed to run bundle hook: ");
		}
		goto out;
	}

out:
	g_clear_pointer(&launcher, g_object_unref);
	g_clear_pointer(&sproc, g_object_unref);
	g_clear_pointer(&hook_name, g_free);
	return res;
}

static gboolean launch_and_wait_custom_handler(RaucInstallArgs *args, gchar* bundledir, RaucManifest *manifest, GHashTable *target_group, GError **error) {
	gchar* handler_name = NULL;
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
	g_free(handler_name);
	r_context_end_step("launch_and_wait_custom_handler", res);
	return res;
}


static gboolean launch_and_wait_default_handler(RaucInstallArgs *args, gchar* bundledir, RaucManifest *manifest, GHashTable *target_group, GError **error) {
	gchar *hook_name = NULL;
	GError *ierror = NULL;
	gboolean res = FALSE;
	GHashTableIter iter;
	RaucSlot *dest_slot;

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

	/* Mark all parent destination slots non-bootable */
	g_message("Marking target slot as non-bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&dest_slot)) {
		if (dest_slot->parent || !dest_slot->bootname) {
			continue;
		}

		res = r_boot_set_state(dest_slot, FALSE);

		if (!res) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_NONBOOTABLE,
					"Failed marking slot %s non-bootable", dest_slot->name);
			goto early_out;
		}
	}

	if (manifest->hook_name)
		hook_name = g_build_filename(bundledir, manifest->hook_name, NULL);

	r_context_begin_step("update_slots", "Updating slots", g_list_length(manifest->images)*2);
	install_args_update(args, "Updating slots...");
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		RaucImage *mfimage;
		GFile *destdevicefile = NULL;
		gchar *slotstatuspath = NULL;
		RaucSlotStatus *slot_state = NULL;
		img_to_slot_handler update_handler = NULL;

		mfimage = l->data;
		dest_slot = g_hash_table_lookup(target_group, mfimage->slotclass);

		/* if image filename is relative, make it absolute */
		if (!g_path_is_absolute(mfimage->filename)) {
			gchar *filename = g_build_filename(bundledir, mfimage->filename, NULL);
			g_free(mfimage->filename);
			mfimage->filename = filename;
		}

		if (!g_file_test(mfimage->filename, G_FILE_TEST_EXISTS)) {
			res = FALSE;
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NOSRC,
					"Source image '%s' not found", mfimage->filename);
			goto out;
		}

		if (!g_file_test(dest_slot->device, G_FILE_TEST_EXISTS)) {
			res = FALSE;
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_NODST,
					"Destination device '%s' not found", dest_slot->device);
			goto out;
		}

		/* determine whether update image type is compatible with destination slot type */
		update_handler = get_update_handler(mfimage, dest_slot, &ierror);
		if (update_handler == NULL) {
			res = FALSE;
			g_propagate_error(error, ierror);
			goto out;
		}

		install_args_update(args, g_strdup_printf("Checking slot %s", dest_slot->name));

		r_context_begin_step("check_slot", g_strdup_printf("Checking slot %s", dest_slot->name), 0);
	
		destdevicefile = g_file_new_for_path(dest_slot->device);

		/* read slot status */
		g_message("mounting slot %s", dest_slot->device);
		res = r_mount_slot(dest_slot, &ierror);
		if (!res) {
			g_message("Mounting failed: %s", ierror->message);
			g_clear_error(&ierror);

			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
			r_context_end_step("check_slot", FALSE);
			goto copy;
		}

		slotstatuspath = g_build_filename(dest_slot->mount_point, "slot.raucs", NULL);

		res = load_slot_status(slotstatuspath, &slot_state, &ierror);

		if (!res) {
			g_message("Failed to load slot status file: %s", ierror->message);
			g_clear_error(&ierror);

			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
		} else {
			/* skip if slot is up-to-date */
			res = g_str_equal(mfimage->checksum.digest, slot_state->checksum.digest);
			if (res) {
				install_args_update(args, g_strdup_printf("Skipping update for correct image %s", mfimage->filename));
				g_message("Skipping update for correct image %s", mfimage->filename);
				r_context_end_step("check_slot", TRUE);
				r_context_begin_step("copy_image", "Copying image", 0);
				r_context_end_step("copy_image", TRUE);
				goto image_out;
			} else {
				g_message("Slot needs to be updated with %s", mfimage->filename);
			}
		}

		res = r_umount_slot(dest_slot, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Unmounting failed: ");
			r_context_end_step("check_slot", FALSE);
			goto out;
		}

		r_context_end_step("check_slot", TRUE);

copy:
		install_args_update(args, g_strdup_printf("Updating slot %s", dest_slot->name));

		/* update slot */
		g_message("Updating %s with %s", dest_slot->device, mfimage->filename);

		r_context_begin_step("copy_image", "Copying image", 0);

		res = update_handler(
			mfimage,
			dest_slot,
			hook_name,
			&ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror,
					"Failed updating slot: ");
			r_context_end_step("copy_image", FALSE);
			goto out;
		}

		r_context_end_step("copy_image", TRUE);

		if (g_strcmp0(dest_slot->type, "nand") == 0) {
			g_message("Skipping slot status update for nand slot %s ", dest_slot->device);
			goto image_out;
		}

		if (g_strcmp0(dest_slot->type, "ubivol") == 0) {
			g_message("Skipping slot status update for ubi (static volume) slot %s ", dest_slot->device);
			goto image_out;
		}

		g_debug("mounting slot %s", dest_slot->device);
		res = r_mount_slot(dest_slot, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror,
					"Mounting failed: ");
			goto out;
		}

		slot_state->status = g_strdup("ok");
		slot_state->checksum.type = mfimage->checksum.type;
		slot_state->checksum.digest = g_strdup(mfimage->checksum.digest);

		if (!slotstatuspath)
			slotstatuspath = g_build_filename(dest_slot->mount_point, "slot.raucs", NULL);
		
		g_message("Updating slot file %s", slotstatuspath);
		install_args_update(args, g_strdup_printf("Updating slot %s status", dest_slot->name));

		res = save_slot_status(slotstatuspath, slot_state, &ierror);
		if (!res) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Failed writing status file: ");

			r_umount_slot(dest_slot, NULL);

			goto out;
		}
		
image_out:
		g_clear_pointer(&slot_state, free_slot_status);
		g_clear_pointer(&destdevicefile, g_object_unref);
		g_clear_pointer(&slotstatuspath, g_free);

		if (dest_slot->mount_internal) {
			g_debug("unmounting slot %s", dest_slot->device);
			res = r_umount_slot(dest_slot, &ierror);
			if (!res) {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Unmounting failed: ");
				goto out;
			}
		}

		install_args_update(args, g_strdup_printf("Updating slot %s done", dest_slot->name));
	}

	/* Mark all parent destination slots bootable */
	g_message("Marking slots as bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&dest_slot)) {
		if (dest_slot->parent || !dest_slot->bootname)
			continue;

		res = r_boot_set_primary(dest_slot);

		if (!res) {
			g_set_error(error, R_INSTALL_ERROR, R_INSTALL_ERROR_MARK_BOOTABLE,
					"Failed marking slot %s bootable", dest_slot->name);
			goto out;
		}
	}

	install_args_update(args, "All slots updated");

	res = TRUE;

out:
	//g_free(hook_name);
	r_context_end_step("update_slots", res);
early_out:
	return res;
}

#if ENABLE_NETWORK
static gboolean reuse_existing_file_checksum(const RaucChecksum *checksum, const gchar *filename) {
	GError *error = NULL;
	gboolean res = FALSE;
	gchar *basename = g_path_get_basename(filename);
	GHashTableIter iter;
	RaucSlot *slot;

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		gchar *srcname = NULL;
		if (!slot->mount_point)
			goto next;
		srcname = g_build_filename(slot->mount_point, basename, NULL);
		if (!verify_checksum(checksum, srcname, NULL))
			goto next;
		g_unlink(filename);
		res = copy_file(srcname, NULL, filename, NULL, &error);
		if (!res) {
			g_warning("Failed to copy file from %s to %s: %s", srcname, filename, error->message);
			goto next;
		}

next:
		g_clear_pointer(&srcname, g_free);
		if (res)
			break;
	}

	g_clear_pointer(&basename, g_free);
	return res;
}

static gboolean launch_and_wait_network_handler(const gchar* base_url,
						RaucManifest *manifest,
						GHashTable *target_group) {
	gboolean res = FALSE, invalid = FALSE;
	GHashTableIter iter;
	RaucSlot *slot;

	if (!verify_compatible(manifest)) {
		res = FALSE;
		goto out;
	}

	/* Mark all parent destination slots non-bootable */
	g_message("Marking active slot as non-bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		if (slot->state & ST_ACTIVE && !slot->parent) {
			break;
		}

		res = r_boot_set_state(slot, FALSE);

		if (!res) {
			g_warning("Failed marking slot %s non-bootable", slot->name);
			goto out;
		}
	}

	// for slot in target_group
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		gchar *slotstatuspath = NULL;
		RaucSlotStatus *slot_state = NULL;

		res = r_mount_slot(slot, NULL);
		if (!res) {
			g_warning("Mounting failed");
			goto slot_out;
		}
		g_print(G_STRLOC " Mounted %s to %s\n", slot->device, slot->mount_point);

		// read status
		slotstatuspath = g_build_filename(slot->mount_point, "slot.raucs", NULL);
		res = load_slot_status(slotstatuspath, &slot_state, NULL);
		if (!res) {
			g_print("Failed to load status file\n");
			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
		}

		// for file targeting this slot
		for (GList *l = manifest->files; l != NULL; l = l->next) {
			RaucFile *mffile = l->data;
			gchar *filename = g_build_filename(slot->mount_point,
							 mffile->destname,
							 NULL);
			gchar *fileurl = g_strconcat(base_url, "/",
						     mffile->filename, NULL);

			res = verify_checksum(&mffile->checksum, filename, NULL);
			if (res) {
				g_message("Skipping download for correct file from %s",
					  fileurl);
				goto file_out;
			}

			res = reuse_existing_file_checksum(&mffile->checksum, filename);
			if (res) {
				g_message("Skipping download for reused file from %s",
					  fileurl);
				goto file_out;
			}


			res = download_file_checksum(filename, fileurl, &mffile->checksum);
			if (!res) {
				g_warning("Failed to download file from %s", fileurl);
				goto file_out;
			}

file_out:
			g_clear_pointer(&filename, g_free);
			g_clear_pointer(&fileurl, g_free);
			if (!res) {
				invalid = TRUE;
				goto slot_out;
			}
		}

		// write status
		slot_state->status = g_strdup("ok");
		res = save_slot_status(slotstatuspath, slot_state, NULL);
		if (!res) {
			g_warning("Failed to save status file");
			invalid = TRUE;
			goto slot_out;
		}

slot_out:
		g_clear_pointer(&slotstatuspath, g_free);
		g_clear_pointer(&slot_state, free_slot_status);
		res = r_umount_slot(slot, NULL);
		if (!res) {
			g_warning("Unounting failed");
			goto out;
		}
		g_print(G_STRLOC " Unmounted %s from %s\n", slot->device, slot->mount_point);
	}

	if (invalid) {
		res = FALSE;
		goto out;
	}

	/* Mark all parent destination slots bootable */
	g_message("Marking slots as bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&slot)) {
		if (slot->parent || !slot->bootname)
			continue;

		res = r_boot_set_primary(slot);

		if (!res) {
			g_warning("Failed marking slot %s bootable", slot->name);
			goto out;
		}
	}

	res = TRUE;

out:
	return res;
}
#endif

static void print_slot_hash_table(GHashTable *hash_table) {
	GHashTableIter iter;
	const gchar *key;
	RaucSlot *slot;

	g_hash_table_iter_init(&iter, hash_table);
	while (g_hash_table_iter_next(&iter, (gpointer *)&key, (gpointer *)&slot)) {
		g_print("  %s -> %s\n", key, slot->name);
	}
}

gboolean do_install_bundle(RaucInstallArgs *args, GError **error) {
	const gchar* bundlefile = args->name;
	GError *ierror = NULL;
	gboolean res = FALSE;
	gchar* mountpoint;
	RaucManifest *manifest = NULL;
	GHashTable *target_group;

	g_assert_nonnull(bundlefile);

	r_context_begin_step("do_install_bundle", "Installing", 5);
	res = determine_slot_states(&ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	mountpoint = r_create_mount_point("bundle", &ierror);
	if (!mountpoint) {
		res = FALSE;
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed creating mount point: ");
		goto out;
	}

	// TODO: mount info in context ?
	g_message("Mounting bundle '%s' to '%s'", bundlefile, mountpoint);
	install_args_update(args, "Checking and mounting bundle...");
	res = mount_bundle(bundlefile, mountpoint, TRUE, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed mounting bundle: ");
		goto umount;
	}

	res = verify_manifest(mountpoint, &manifest, FALSE, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed verifying manifest: ");
		goto umount;
	}

	target_group = determine_target_install_group(manifest);
	if (!target_group) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_TARGET_GROUP, "Could not determine target group");
		res = FALSE;
		goto umount;
	}

	g_print("Target Group:\n");
	print_slot_hash_table(target_group);

	if (r_context()->config->preinstall_handler) {
		g_print("Starting pre install handler: %s\n", r_context()->config->preinstall_handler);
		res = launch_and_wait_handler(mountpoint, r_context()->config->preinstall_handler, manifest, target_group, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Handler error: ");
			goto out;
		}
	}


	if (manifest->handler_name) {
		g_print("Using custom handler: %s\n", manifest->handler_name);
		res = launch_and_wait_custom_handler(args, mountpoint, manifest, target_group, &ierror);
	} else {
		g_print("Using default handler\n");
		res = launch_and_wait_default_handler(args, mountpoint, manifest, target_group, &ierror);
	}

	if (!res) {
		g_propagate_prefixed_error(error, ierror, "Handler error: ");
		goto umount;
	}

	if (r_context()->config->postinstall_handler) {
		g_print("Starting post install handler: %s\n", r_context()->config->postinstall_handler);
		res = launch_and_wait_handler(mountpoint, r_context()->config->postinstall_handler, manifest, target_group, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Handler error: ");
			goto umount;
		}
	}


	res = TRUE;

umount:
	umount_bundle(mountpoint, NULL);
	g_rmdir(mountpoint);
	g_clear_pointer(&mountpoint, g_free);

out:
	g_clear_pointer(&manifest, free_manifest);
	r_context_end_step("do_install_bundle", res);

	return res;
}

gboolean do_install_network(const gchar *url, GError **error) {
#if ENABLE_NETWORK
	gboolean res = FALSE;
	GError *ierror = NULL;
	gchar *base_url = NULL, *signature_url = NULL;
	GBytes *manifest_data = NULL, *signature_data = NULL;
	RaucManifest *manifest = NULL;
	GHashTable *target_group = NULL;

	g_assert_nonnull(url);

	res = determine_slot_states(&ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = download_mem(&manifest_data, url, 64*1024);
	if (!res) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_DOWNLOAD_MF, "Failed to download manifest");
		goto out;
	}

	signature_url = g_strconcat(url, ".sig", NULL);
	res = download_mem(&signature_data, signature_url, 64*1024);
	if (!res) {
		g_warning("Failed to download manifest signature");
		goto out;
	}

	res = cms_verify(manifest_data, signature_data, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed verifying manifest: ");
		goto out;
	}

	res = load_manifest_mem(manifest_data, &manifest, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed loading manifest: ");
		goto out;
	}

	target_group = determine_target_install_group(manifest);
	if (!target_group) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_TARGET_GROUP, "Could not determine target group");
		goto out;
	}

	g_print("Target Group:\n");
	print_slot_hash_table(target_group);

	base_url = g_path_get_dirname(url);

	if (r_context()->config->preinstall_handler) {
		g_print("Starting pre install handler: %s\n", r_context()->config->preinstall_handler);
		res = launch_and_wait_handler(base_url, r_context()->config->preinstall_handler, manifest, target_group, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Handler error: ");
			goto out;
		}
	}


	g_print("Using network handler for %s\n", base_url);
	res = launch_and_wait_network_handler(base_url, manifest, target_group);
	if (!res) {
		g_set_error_literal(error, R_INSTALL_ERROR, R_INSTALL_ERROR_HANDLER,
				"Handler error");
		goto out;
	}

	if (r_context()->config->postinstall_handler) {
		g_print("Starting post install handler: %s\n", r_context()->config->postinstall_handler);
		res = launch_and_wait_handler(base_url, r_context()->config->postinstall_handler, manifest, target_group, &ierror);
		if (!res) {
			g_propagate_prefixed_error(error, ierror, "Handler error: ");
			goto out;
		}
	}


	res = TRUE;

out:
	g_clear_pointer(&target_group, g_hash_table_unref);
	g_clear_pointer(&manifest, free_manifest);
	g_clear_pointer(&base_url, g_free);
	g_clear_pointer(&signature_url, g_free);
	g_clear_pointer(&manifest_data, g_bytes_unref);
	g_clear_pointer(&signature_data, g_bytes_unref);

	return res;
#else
	g_set_error_literal(
			error,
			R_INSTALL_ERROR,
			R_INSTALL_ERROR_NO_SUPPORTED,
			"Compiled without network support");
	return FALSE;
#endif
}

static gboolean install_done(gpointer data) {
	RaucInstallArgs *args = data;

	args->cleanup(args);

	r_context_set_busy(FALSE);

	return G_SOURCE_REMOVE;
}

static gpointer install_thread(gpointer data) {
	GError *ierror = NULL;
	RaucInstallArgs *args = data;
	gint result;

	/* clear LastError property */
	set_last_error(g_strdup(""));

	g_debug("thread started for %s\n", args->name);
	install_args_update(args, "started");

	if (g_str_has_suffix(args->name, ".raucb")) {
		result = !do_install_bundle(args, &ierror);
		if (result != 0) {
			g_warning("%s", ierror->message);
			install_args_update(args, ierror->message);
			set_last_error(ierror->message);
			g_clear_error(&ierror);
		}
	} else {
		result = !do_install_network(args->name, &ierror);
		if (result != 0) {
			g_warning("%s", ierror->message);
			install_args_update(args, ierror->message);
			set_last_error(ierror->message);
			g_clear_error(&ierror);
		}
	}

	g_mutex_lock(&args->status_mutex);
	args->status_result = result;
	g_mutex_unlock(&args->status_mutex);
	install_args_update(args, "finished");
	g_debug("thread finished for %s\n", args->name);

	g_main_context_invoke(NULL, install_done, args);
	return NULL;
}

RaucInstallArgs *install_args_new(void) {
	RaucInstallArgs *args = g_new0(RaucInstallArgs, 1);

	g_mutex_init(&args->status_mutex);
	g_queue_init(&args->status_messages);
	args->status_result = -2;

	return args;
}

void install_args_free(RaucInstallArgs *args) {
	g_free(args->name);
	g_mutex_clear(&args->status_mutex);
	g_assert_cmpint(args->status_result, >=, 0);
	g_assert_true(g_queue_is_empty(&args->status_messages));
	g_free(args);
}

gboolean install_run(RaucInstallArgs *args) {
	GThread *thread = NULL;
	r_context_set_busy(TRUE);

	g_print("Active slot bootname: %s\n", get_cmdline_bootname());

	thread = g_thread_new("installer", install_thread, args);
	if (thread == NULL)
		return FALSE;

	g_thread_unref(thread);

	return TRUE;
}
