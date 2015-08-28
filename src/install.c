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
#include <sys/ioctl.h>
#include <gio/gfiledescriptorbased.h>
#include <gio/gunixoutputstream.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <mtd/ubi-user.h>

#define R_INSTALL_ERROR r_install_error_quark ()

static GQuark r_install_error_quark (void)
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

gboolean determine_slot_states(void) {
	GList *slotlist = NULL;
	const gchar *bootname;
	RaucSlot *booted = NULL;
	gboolean res = FALSE;

	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->slots);

	bootname = bootname_provider();
	if (bootname == NULL) {
		g_warning("Warning: No bootname found");
		goto out;
	}

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);
		if (!s->bootname && s->parent) {
			g_warning("Warning: No bootname configured for %s", s->name);
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

	if (!booted) {
		g_warning("Did not find booted slot");
		goto out;
	}

	res = TRUE;
	booted->state = ST_BOOTED;
	g_print("Found booted slot: %s on %s\n", booted->name, booted->device);

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

out:
	g_clear_pointer(&slotlist, g_list_free);

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
	GPtrArray *slotclasses = NULL;
	GList *slotmembers;
	GHashTable *targetgroup = NULL;

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

	/* Determine slot class members for first image in manifest */
	slotmembers = get_slot_class_members(slotclasses->pdata[0]);

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
		g_warning("Failed to determine target install group");
		return NULL;
	}

	targetgroup = g_hash_table_new(g_str_hash, g_str_equal);

	for (guint i = 0; i < slotclasses->len; i++) {
		RaucSlot *image_target = NULL;

		slotmembers = get_slot_class_members(slotclasses->pdata[i]);

		for (GList *li = slotmembers; li != NULL; li = li->next) {
			RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, li->data);

			if (s == targetgroup_root || s->parent == targetgroup_root) {
				image_target = s;
			}
		}

		if (!image_target) {
			g_warning("No target for class '%s' found!", (gchar *)slotclasses->pdata[i]);
			return NULL;
		}

		g_hash_table_insert(targetgroup, slotclasses->pdata[i], (gchar *)image_target->name);
	}

	g_clear_pointer(&slotclasses, g_ptr_array_unref);
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

static gboolean launch_and_wait_custom_handler(RaucInstallArgs *args, gchar* cwd, RaucManifest *manifest, GHashTable *target_group) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	gchar* handler_name = NULL;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;

	gchar *targetlist = NULL;
	gchar *slotlist = NULL;
	GHashTableIter iter;
	gpointer sname;
	RaucSlot *slot;
	gint slotcnt = 0;

	if (!verify_compatible(manifest)) {
		res = FALSE;
		goto out;
	}

	handler_name = g_build_filename(cwd, manifest->handler_name, NULL);

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	g_subprocess_launcher_setenv(handlelaunch, "RAUC_SYSTEM_CONFIG", r_context()->configpath, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "RAUC_CURRENT_BOOTNAME", bootname_provider(), TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "RAUC_UPDATE_SOURCE", cwd, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "RAUC_MOUNT_PREFIX", r_context()->config->mount_prefix, TRUE);

	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &sname, (gpointer) &slot)) {
		gchar *varname;
		gchar *tmp;
		GHashTableIter iiter;
		gpointer class, member;

		slotcnt++;

		tmp = g_strdup_printf("%s%i ", slotlist ? slotlist : "", slotcnt);
		g_clear_pointer(&slotlist, g_free);
		slotlist = tmp;

		g_hash_table_iter_init(&iiter, target_group);
		while (g_hash_table_iter_next(&iiter, &class, &member)) {
			if (slot->name != member) {
				continue;
			}

			/* for target slots, get image name and add number to list */
			for (GList *l = manifest->images; l != NULL; l = l->next) {
				RaucImage *img = l->data;
				if (g_str_equal(slot->sclass, img->slotclass)) {
					varname = g_strdup_printf("RAUC_IMAGE_NAME_%i", slotcnt);
					g_subprocess_launcher_setenv(handlelaunch, varname, img->filename, TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_DIGEST_%i", slotcnt);
					g_subprocess_launcher_setenv(handlelaunch, varname, img->checksum.digest, TRUE);
					g_clear_pointer(&varname, g_free);

					varname = g_strdup_printf("RAUC_IMAGE_CLASS_%i", slotcnt);
					g_subprocess_launcher_setenv(handlelaunch, varname, img->slotclass, TRUE);
					g_clear_pointer(&varname, g_free);

					break;
				}
			}

			tmp = g_strdup_printf("%s%i ", targetlist ? targetlist : "", slotcnt);
			g_clear_pointer(&targetlist, g_free);
			targetlist = tmp;

		}

		varname = g_strdup_printf("RAUC_SLOT_NAME_%i", slotcnt);
		g_subprocess_launcher_setenv(handlelaunch, varname, slot->name, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_CLASS_%i", slotcnt);
		g_subprocess_launcher_setenv(handlelaunch, varname, slot->sclass, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_DEVICE_%i", slotcnt);
		g_subprocess_launcher_setenv(handlelaunch, varname, slot->device, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_BOOTNAME_%i", slotcnt);
		g_subprocess_launcher_setenv(handlelaunch, varname, slot->bootname, TRUE);
		g_clear_pointer(&varname, g_free);

		varname = g_strdup_printf("RAUC_SLOT_PARENT_%i", slotcnt);
		g_subprocess_launcher_setenv(handlelaunch, varname, slot->parent ? slot->parent->name : "", TRUE);
		g_clear_pointer(&varname, g_free);

	}

	g_subprocess_launcher_setenv(handlelaunch, "RAUC_SLOTS", slotlist, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "RAUC_TARGET_SLOTS", targetlist, TRUE);

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch,
			&error, handler_name,
			manifest->handler_args,
			NULL);

	instream = g_subprocess_get_stdout_pipe(handleproc);
	datainstream = g_data_input_stream_new(instream);

	do {
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline)
			continue;

		parse_handler_output(outline);
	} while (outline);
	

	if (handleproc == NULL) {
		g_warning("failed to start custom handler: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(handleproc, NULL, &error);
	if (!res) {
		g_warning("failed to run custom handler: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = TRUE;
out:
	g_free(handler_name);
	return res;
}

/* Creates a mount subdir in mount path prefix */
static gchar* create_mount_point(const gchar *name, GError **error) {
	gchar* prefix;
	gchar* mountpoint = NULL;

	prefix = r_context()->config->mount_prefix;
	if (!g_file_test (prefix, G_FILE_TEST_IS_DIR)) {
		g_set_error(
				error,
				R_INSTALL_ERROR,
				3,
				"mount prefix path %s does not exist",
				prefix);
		goto out;
	}


	mountpoint = g_build_filename(prefix, name, NULL);

	if (!g_file_test (mountpoint, G_FILE_TEST_IS_DIR)) {
		gint ret;
		ret = g_mkdir(mountpoint, 0777);

		if (ret != 0) {
			g_set_error(
					error,
					R_INSTALL_ERROR,
					3,
					"Failed creating mount path '%s'",
					mountpoint);
			g_free(mountpoint);
			mountpoint = NULL;
			goto out;
		}
	}

out:

	return mountpoint;
}


static gboolean copy_image(GFile *src, GFile *dest, gchar* fs_type) {
	gboolean res = FALSE;
	GError *error = NULL;
	GFileInputStream *instream = NULL;
	GOutputStream *outstream = NULL;
	gssize size;
	int fd_out;
	int ret;
	goffset imgsize;

	/* open source image and determine size */
	instream = g_file_read(src, NULL, &error);
	if (instream == NULL) {
		g_warning("failed to open file for reading: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_seekable_seek(G_SEEKABLE(instream),
			      0, G_SEEK_END, NULL, &error);
	if (!res) {
		g_warning("src image seek failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}
	imgsize = g_seekable_tell(G_SEEKABLE(instream));
	res = g_seekable_seek(G_SEEKABLE(instream),
			      0, G_SEEK_SET, NULL, &error);
	if (!res) {
		g_warning("src image seek failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}
	res = FALSE;

	g_debug("Input image size is %" G_GOFFSET_FORMAT " bytes", imgsize);

	if (imgsize == 0) {
		g_warning("Input image is empty");
		goto out;
	}

	fd_out = open(g_file_get_path(dest), O_WRONLY);
	if (fd_out == -1) {
		g_warning("opening output device failed: %s", strerror(errno));
		goto out;
	}

	outstream = g_unix_output_stream_new(fd_out, TRUE);
	if (outstream == NULL) {
		g_warning("failed to open file for writing: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	if (g_strcmp0(fs_type, "ubifs") == 0) {
		/* set up ubi volume for image copy */
		ret = ioctl(fd_out, UBI_IOCVOLUP, &imgsize);
		if (ret == -1) {
			g_warning("ubi volume update failed: %s", strerror(errno));
			goto out;
		}
	}

	size = g_output_stream_splice(
			outstream,
			(GInputStream*)instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
			NULL,
			&error);
	if (size == -1) {
		g_warning("failed splicing data: %s", error->message);
		g_clear_error(&error);
		goto out;
	} else if (size != imgsize) {
		g_warning("image size and written size differ!");
		goto out;
	}


	res = TRUE;
out:
	g_clear_object(&instream);
	g_clear_object(&outstream);
	return res;
}

static gboolean launch_and_wait_default_handler(RaucInstallArgs *args, gchar* cwd, RaucManifest *manifest, GHashTable *target_group) {

	gboolean res = FALSE;
	gchar *mountpoint = NULL;

	GHashTableIter iter;
	gpointer class, member;

	if (!verify_compatible(manifest)) {
		res = FALSE;
		goto out;
	}

	mountpoint = create_mount_point("image", NULL);
	if (!mountpoint) {
		res = FALSE;
		g_warning("Failed to create image mount point");
		goto out;
	}

	/* Mark all parent destination slots non-bootable */
	g_message("Marking target slot as non-bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, &class, &member)) {
		RaucSlot *dest_slot = g_hash_table_lookup(r_context()->config->slots, member);

		if (dest_slot->parent) {
			continue;
		}

		res = r_boot_set_state(dest_slot, FALSE);

		if (!res) {
			g_warning("Failed marking slot %s non-bootable", dest_slot->name);
			goto out;
		}
	}

	install_args_update(args, "Updating slots...");
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		GError *ierror = NULL;
		gchar *dest_slot_name;
		RaucSlot  *dest_slot;
		RaucImage *mfimage;
		gchar *srcimagepath = NULL;
		GFile *srcimagefile = NULL;
		GFile *destdevicefile = NULL;
		gchar *slotstatuspath = NULL;
		RaucSlotStatus *slot_state = NULL;

		mfimage = l->data;
		dest_slot_name = g_hash_table_lookup(target_group, mfimage->slotclass);
		dest_slot = g_hash_table_lookup(r_context()->config->slots, dest_slot_name);

		if (g_path_is_absolute(mfimage->filename)) {
			srcimagepath = g_strdup(mfimage->filename);
		} else {
			srcimagepath = g_build_filename(cwd, mfimage->filename, NULL);
		}

		if (!g_file_test(srcimagepath, G_FILE_TEST_EXISTS)) {
			res = FALSE;
			g_warning("Source image '%s' not found", srcimagepath);
			goto out;
		}

		if (!g_file_test(dest_slot->device, G_FILE_TEST_EXISTS)) {
			res = FALSE;
			g_warning("Destination device '%s' not found", dest_slot->device);
			goto out;
		}

		install_args_update(args, g_strdup_printf("Checking slot %s", dest_slot->name));
	
		srcimagefile = g_file_new_for_path(srcimagepath);
		destdevicefile = g_file_new_for_path(dest_slot->device);

		/* read slot status */
		slotstatuspath = g_build_filename(mountpoint, "slot.raucs", NULL);

		g_message("mounting %s to %s", dest_slot->device, mountpoint);

		res = r_mount_slot(dest_slot, mountpoint, &ierror);
		if (!res) {
			g_message("Mounting failed: %s", ierror->message);
			g_clear_error(&ierror);

			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
			goto copy;
		}

		res = load_slot_status(slotstatuspath, &slot_state, &ierror);

		if (!res) {
			g_message("Failed to load slot status file: %s", ierror->message);
			g_clear_error(&ierror);

			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
		} else {

			/* skip if slot is up-to-date */
			res = g_str_equal(&mfimage->checksum.digest, slot_state->checksum.digest);
			if (res) {
				install_args_update(args, g_strdup_printf("Skipping update for correct image %s", mfimage->filename));
				g_message("Skipping update for correct image %s", mfimage->filename);
				goto image_out;
			} else {
				g_message("Slot needs to be updated with %s", mfimage->filename);
			}
		}

		res = r_umount(mountpoint, &ierror);
		if (!res) {
			g_warning("Unmounting failed: %s", ierror->message);
			g_clear_error(&ierror);
			goto out;
		}

copy:

		install_args_update(args, g_strdup_printf("Updating slot %s", dest_slot->name));

		/* update slot */
		g_message("Copying %s to %s", srcimagepath, dest_slot->device);

		res = copy_image(
			srcimagefile,
			destdevicefile,
			dest_slot->type);

		if (!res) {
			g_warning("Failed copying image");
			goto out;
		}

		g_debug("Mounting %s to %s", dest_slot->device, mountpoint);

		res = r_mount_slot(dest_slot, mountpoint, &ierror);
		if (!res) {
			g_warning("Mounting failed: %s", ierror->message);
			g_clear_error(&ierror);
			goto out;
		}

		slot_state->status = g_strdup("ok");
		slot_state->checksum.type = mfimage->checksum.type;
		slot_state->checksum.digest = g_strdup(mfimage->checksum.digest);
		
		g_message("Updating slot file %s", slotstatuspath);
		install_args_update(args, g_strdup_printf("Updating slot %s status", dest_slot->name));

		res = save_slot_status(slotstatuspath, slot_state, &ierror);

		if (!res) {
			g_warning("Failed writing status file: %s", ierror->message);
			g_clear_error(&ierror);

			r_umount(mountpoint, NULL);

			goto out;
		}
		
image_out:
		g_clear_pointer(&slot_state, free_slot_status);
		g_clear_pointer(&srcimagepath, g_free);
		g_clear_pointer(&srcimagefile, g_object_unref);
		g_clear_pointer(&destdevicefile, g_object_unref);
		g_clear_pointer(&slotstatuspath, g_free);
		g_debug("Unmounting %s", mountpoint);

		res = r_umount(mountpoint, &ierror);
		if (!res) {
			g_warning("Unmounting failed: %s", ierror->message);
			g_clear_error(&ierror);
			goto out;
		}

		install_args_update(args, g_strdup_printf("Updating slot %s done", dest_slot->name));

	}

	/* Mark all parent destination slots bootable */
	g_message("Marking slots as bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, &class, &member)) {
		RaucSlot *dest_slot = g_hash_table_lookup(r_context()->config->slots, member);

		if (dest_slot->parent)
			continue;

		res = r_boot_set_primary(dest_slot);

		if (!res) {
			g_warning("Failed marking slot %s bootable", dest_slot->name);
			goto out;
		}
	}

	install_args_update(args, "All slots updated");

	res = TRUE;

out:
	g_clear_pointer(&mountpoint, g_free);

	return res;
}

static gboolean launch_and_wait_network_handler(const gchar* base_url,
						RaucManifest *manifest,
						GHashTable *target_group) {
	gboolean res = FALSE, invalid = FALSE;
	GHashTableIter iter;
	gchar *slotclass, *slotname;

	if (!verify_compatible(manifest)) {
		res = FALSE;
		goto out;
	}

	/* Mark all parent destination slots non-bootable */
	g_message("Marking active slot as non-bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, (gpointer* )&slotclass,
				      (gpointer *)&slotname)) {
		RaucSlot *dest_slot = g_hash_table_lookup(r_context()->config->slots, slotname);

		if (dest_slot->state & ST_ACTIVE && !dest_slot->parent) {
			break;
		}

		res = r_boot_set_state(dest_slot, FALSE);

		if (!res) {
			g_warning("Failed marking slot %s non-bootable", dest_slot->name);
			goto out;
		}
	}


	// for slot in target_group
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, (gpointer* )&slotclass,
				      (gpointer *)&slotname)) {
		gchar *mountpoint = create_mount_point(slotname, NULL);
		gchar *slotstatuspath = NULL;
		RaucSlot *slot = NULL;
		RaucSlotStatus *slot_state = NULL;

		if (!mountpoint) {
			goto out;
		}

		slot = g_hash_table_lookup(r_context()->config->slots, slotname);
		g_print(G_STRLOC " I will mount %s to %s\n", slot->device, mountpoint);
		res = r_mount_slot(slot, mountpoint, NULL);
		if (!res) {
			g_warning("Mounting failed");
			goto slot_out;
		}

		// read status
		slotstatuspath = g_build_filename(mountpoint, "slot.raucs", NULL);
		res = load_slot_status(slotstatuspath, &slot_state, NULL);
		if (!res) {
			g_print("Failed to load status file\n");
			slot_state = g_new0(RaucSlotStatus, 1);
			slot_state->status = g_strdup("update");
		}

		// for file targeting this slot
		for (GList *l = manifest->files; l != NULL; l = l->next) {
			RaucFile *mffile = l->data;
			gchar *filename = g_build_filename(mountpoint,
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
		g_print(G_STRLOC " I will unmount %s\n", mountpoint);
		res = r_umount(mountpoint, NULL);
		g_free(mountpoint);
		if (!res) {
			g_warning("Unounting failed");
			goto out;
		}
	}

	if (invalid) {
		res = FALSE;
		goto out;
	}

	/* Mark all parent destination slots bootable */
	g_message("Marking slots as bootable...");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, (gpointer* )&slotclass,
				      (gpointer *)&slotname)) {
		RaucSlot *dest_slot = g_hash_table_lookup(r_context()->config->slots, slotname);

		if (dest_slot->parent)
			continue;

		res = r_boot_set_primary(dest_slot);

		if (!res) {
			g_warning("Failed marking slot %s bootable", dest_slot->name);
			goto out;
		}
	}

	res = TRUE;
out:
	return res;
}

static void print_hash_table(GHashTable *hash_table) {
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, hash_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		g_print("  %s -> %s\n", (gchar *)key, (gchar *)value);
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

	res = determine_slot_states();
	if (!res) {
		g_set_error_literal(error, R_INSTALL_ERROR, 1, "Failed to determine slot states");
		goto out;
	}

	mountpoint = create_mount_point("bundle", &ierror);
	if (!mountpoint) {
		res = FALSE;
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed creating mount point: ");
		goto out;
	}

	// TODO: mount info in context ?
	g_message("Mounting bundle '%s' to '%s'\n", bundlefile, mountpoint);
	install_args_update(args, "Checking and mounting bundle...");
	res = mount_bundle(bundlefile, mountpoint, &ierror);
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
		g_set_error_literal(error, R_INSTALL_ERROR, 3, "Could not determine target group");
		res = FALSE;
		goto umount;
	}

	g_print("Target Group:\n");
	print_hash_table(target_group);

	if (manifest->handler_name) {
		g_print("Using custom handler: %s\n", manifest->handler_name);
		res = launch_and_wait_custom_handler(args, mountpoint, manifest, target_group);
	} else {
		g_print("Using default handler\n");
		res = launch_and_wait_default_handler(args, mountpoint, manifest, target_group);
	}

	if (!res) {
		g_set_error_literal(error, R_INSTALL_ERROR, 3, "Starting handler failed");
		goto umount;
	}

	res = TRUE;

umount:
	umount_bundle(mountpoint, NULL);
	g_rmdir(mountpoint);
	g_clear_pointer(&mountpoint, g_free);
out:
	g_clear_pointer(&manifest, free_manifest);

	return res;

}

gboolean do_install_network(const gchar *url) {
	gboolean res = FALSE;
	gchar *base_url = NULL, *signature_url = NULL;
	GBytes *manifest_data = NULL, *signature_data = NULL;
	RaucManifest *manifest = NULL;
	GHashTable *target_group = NULL;

	g_assert_nonnull(url);

	res = determine_slot_states();
	if (!res) {
		g_warning("Failed to determine slot states");
		goto out;
	}

	res = download_mem(&manifest_data, url, 64*1024);
	if (!res) {
		g_warning("Failed to download manifest");
		goto out;
	}

	signature_url = g_strconcat(url, ".sig", NULL);
	res = download_mem(&signature_data, signature_url, 64*1024);
	if (!res) {
		g_warning("Failed to download manifest signature");
		goto out;
	}

	res = cms_verify(manifest_data, signature_data, NULL);
	if (!res) {
		g_warning("Failed to verify manifest signature");
		goto out;
	}

	res = load_manifest_mem(manifest_data, &manifest, NULL);
	if (!res) {
		g_warning("Failed to verify manifest signature");
		goto out;
	}

	target_group = determine_target_install_group(manifest);
	if (!target_group) {
		g_warning("Could not determine target group");
		goto out;
	}

	g_print("Target Group:\n");
	print_hash_table(target_group);

	base_url = g_path_get_dirname(url);

	g_print("Using network handler for %s\n", base_url);
	res = launch_and_wait_network_handler(base_url, manifest, target_group);
	if (!res) {
		g_warning("Starting handler failed");
		goto out;
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

	g_debug("thread started for %s\n", args->name);
	install_args_update(args, "started");

	if (g_str_has_suffix(args->name, ".raucb")) {
		result = !do_install_bundle(args, &ierror);
		if (result != 0) {
			g_warning("%s", ierror->message);
			install_args_update(args, ierror->message);
			g_clear_error(&ierror);
		}
	} else {
		result = !do_install_network(args->name);
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
