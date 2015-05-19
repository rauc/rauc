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

static const gchar* (*bootname_provider)(void) = get_cmdline_bootname;

const gchar* get_cmdline_bootname(void) {

	GRegex *regex = NULL;
	GMatchInfo *match = NULL;
	char *contents = NULL;
	char *res = NULL;

	if (!g_file_get_contents("/proc/cmdline", &contents, NULL, NULL))
		return NULL;

	regex = g_regex_new("rauc\\.slot=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		res = g_match_info_fetch(match, 1);
		goto out;
	}
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);

	regex = g_regex_new("root=(\\S+)", 0, 0, NULL);
	if (g_regex_match(regex, contents, 0, &match)) {
		res = g_match_info_fetch(match, 1);
		goto out;
	}

out:
	g_clear_pointer(&match, g_match_info_free);
	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&contents, g_free);

	return res;
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
		g_warning("Warning: No bootname found\n");
		goto out;
	}

	slotlist = g_hash_table_get_keys(r_context()->config->slots);

	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *s = (RaucSlot*) g_hash_table_lookup(r_context()->config->slots, l->data);
		if (!s->bootname && s->parent) {
			g_warning("Warning: No bootname configured for %s\n", s->name);
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
		g_warning("Did not find booted slot\n");
		goto out;
	}

	res = TRUE;
	booted->state = ST_ACTIVE;
	g_print("Found booted slot: %s on %s\n", booted->name, booted->device);

	/* Determine active group members */
	for (GList *l = slotlist; l != NULL; l = l->next) {
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
		g_warning("Failed to determine target install group\n");
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
			g_warning("No target for class '%s' found!\n", (gchar *)slotclasses->pdata[i]);
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

	if (!g_str_has_prefix(line, "<< "))
		goto out;

	split = g_strsplit(line, " ", 5);

	if (!split[1])
		goto out;

	if (g_strcmp0(split[1], "handler") == 0) {
		g_print("Handler status: %s\n", split[2]);
	} else if (g_strcmp0(split[1], "image") == 0) {
		g_print("Image '%s' status: %s\n", split[2], split[3]);
	}


out:
	g_strfreev(split);
}

static gboolean launch_and_wait_custom_handler(gchar* cwd, gchar* name) {
	GSubprocessLauncher *handlelaunch = NULL;
	GSubprocess *handleproc = NULL;
	GError *error = NULL;
	gboolean res = FALSE;
	gchar* handler_name;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;

	handler_name = g_build_filename(cwd, name, NULL);

	handlelaunch = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

	g_subprocess_launcher_setenv(handlelaunch, "SYSTEM_CONFIG", r_context()->configpath, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "CURRENT_BOOTNAME", "TODO", TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "TARGET_SLOTS", "TODO", TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "UPDATE_SOURCE", cwd, TRUE);
	g_subprocess_launcher_setenv(handlelaunch, "MOUNT_PREFIX", r_context()->mountprefix ? r_context()->mountprefix : r_context()->config->mount_prefix , TRUE);

	handleproc = g_subprocess_launcher_spawn(
			handlelaunch,
			&error, handler_name,
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


static gboolean copy_image(GFile *src, GFile *dest) {
	gboolean res = FALSE;
	GError *error = NULL;
	GFileInputStream *instream = NULL;
	GFileIOStream *outstream = NULL;
	gssize size;

	instream = g_file_read(src, NULL, &error);
	if (instream == NULL) {
		g_warning("failed to open file for reading: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	outstream = g_file_open_readwrite(dest, NULL, &error);
	if (outstream == NULL) {
		g_warning("failed to open file for writing: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	size = g_output_stream_splice(
			g_io_stream_get_output_stream((GIOStream*)outstream),
			(GInputStream*)instream,
			G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
			NULL,
			&error);
	if (size == -1) {
		g_warning("failed splicing data: %s", error->message);
		g_clear_error(&error);
		goto out;
	}


	res = TRUE;
out:
	g_clear_object(&instream);
	g_clear_object(&outstream);
	return res;
}

static gboolean launch_and_wait_default_handler(gchar* cwd, RaucManifest *manifest, GHashTable *target_group) {

	gboolean res = FALSE;
	GError *error = NULL;
	gchar *mountpoint = NULL;
	gchar *srcimagepath = NULL;
	//gboolean require_mount = FALSE;
	GFile *srcimagefile = NULL;
	GFile *destdevicefile = NULL;

	RaucSlotStatus *slot_state = NULL;
	gchar *slotstatuspath = NULL;

	GHashTableIter iter;
	gpointer class, member;

	mountpoint = create_mount_point("image");

	if (!mountpoint) {
		goto out;
	}

	/* Mark all parent destination slots non-bootable */
	g_print("Marking active slot as non-bootable...\n");
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, &class, &member)) {
		RaucSlot *dest_slot = g_hash_table_lookup(r_context()->config->slots, member);

		if (dest_slot->state == ST_ACTIVE && !dest_slot->parent) {
			break;
		}

		res = r_boot_disable(dest_slot);

		if (!res) {
			g_warning("Failed marking slot %s non-bootable", dest_slot->name);
			goto out;
		}
	}

	g_print("Updating slots...\n");
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		gchar *dest_slot_name;
		RaucSlot  *dest_slot;
		RaucImage *mfimage;

		mfimage = l->data;
		dest_slot_name = g_hash_table_lookup(target_group, mfimage->slotclass);
		dest_slot = g_hash_table_lookup(r_context()->config->slots, dest_slot_name);

		if (g_path_is_absolute(mfimage->filename)) {
			srcimagepath = g_strdup(mfimage->filename);
		} else {
			srcimagepath = g_build_filename(cwd, mfimage->filename, NULL);
		}

		if (!g_file_test(srcimagepath, G_FILE_TEST_EXISTS)) {
			g_warning("Source image '%s' not found", srcimagepath);
			goto out;
		}

		if (!g_file_test(dest_slot->device, G_FILE_TEST_EXISTS)) {
			g_warning("Destination device '%s' not found", dest_slot->device);
			goto out;
		}

		if (g_str_has_suffix(mfimage->filename, ".ext4")) {
			g_print("Is an ext4 image\n");
		} else if (g_str_has_suffix(mfimage->filename, ".img")) {
			g_print("Is a raw image\n");
		}

		g_print(G_STRLOC " I will copy %s to %s\n", srcimagepath, dest_slot->device);

	
		srcimagefile = g_file_new_for_path(srcimagepath);
		destdevicefile = g_file_new_for_path(dest_slot->device);

		res = copy_image(
			srcimagefile,
			destdevicefile);

		if (!res) {
			g_warning("Failed copying image: %s", error->message);
			goto out;
		}

		// TODO: status: copy done

		g_print(G_STRLOC " I will mount %s to %s\n", dest_slot->device, mountpoint);

		res = r_mount_slot(dest_slot, mountpoint);
		if (!res) {
			g_warning("Mounting failed");
			goto out;
		}
		g_print("filename: %s\n", mfimage->filename);
		g_print("digest: %s\n", mfimage->checksum.digest);

		slot_state = g_new0(RaucSlotStatus, 1);

		slot_state->status = g_strdup("ok");
		slot_state->checksum.type = mfimage->checksum.type;
		slot_state->checksum.digest = g_strdup(mfimage->checksum.digest);
		
		slotstatuspath = g_build_filename(mountpoint, "slot.raucs", NULL);

		g_print(G_STRLOC " I will update slot file %s\n", slotstatuspath);

		res = save_slot_status(slotstatuspath, slot_state, NULL);

		if (!res) {
			g_warning("Failed writing status file");

			r_umount(mountpoint);

			goto out;
		}
		
		g_print(G_STRLOC " I will unmount %s\n", mountpoint);
		res = r_umount(mountpoint);
		if (!res) {
			g_warning("Unounting failed");
			goto out;
		}
	}

	/* Mark all parent destination slots non-bootable */
	g_print("Marking slots as bootable...\n");
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

	res = TRUE;

out:
	g_free(mountpoint);
	g_free(srcimagepath);

	g_object_unref(srcimagefile);
	g_object_unref(destdevicefile);

	free_slot_status(slot_state);

	return res;
}

static gboolean launch_and_wait_network_handler(const gchar* base_url,
						RaucManifest *manifest,
						GHashTable *target_group) {
	gboolean res = FALSE;
	GHashTableIter iter;
	gchar *slotclass, *slotname;

	(void)base_url;
	(void)manifest;

	// TODO: mark slots as non-bootable

	// for slot in target_group
	g_hash_table_iter_init(&iter, target_group);
	while (g_hash_table_iter_next(&iter, (gpointer* )&slotclass,
				      (gpointer *)&slotname)) {
		gchar *mountpoint = create_mount_point(slotname);
		gchar *slotstatuspath = NULL;
		RaucSlot *slot = NULL;
		RaucSlotStatus *slot_state = NULL;

		if (!mountpoint) {
			goto out;
		}

		slot = g_hash_table_lookup(r_context()->config->slots, slotname);
		g_print(G_STRLOC " I will mount %s to %s\n", slot->device, mountpoint);
		res = r_mount_slot(slot, mountpoint);
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
			if (!res)
				goto slot_out;
		}

		// write status
		slot_state->status = g_strdup("ok");
		res = save_slot_status(slotstatuspath, slot_state, NULL);
		if (!res) {
			g_warning("Failed to save status file");
			goto slot_out;
		}

slot_out:
		g_clear_pointer(&slotstatuspath, g_free);
		g_clear_pointer(&slot_state, free_slot_status);
		g_print(G_STRLOC " I will unmount %s\n", mountpoint);
		res = r_umount(mountpoint);
		g_free(mountpoint);
		if (!res) {
			g_warning("Unounting failed");
			goto out;
		}
	}

	// TODO: mark slots as bootable

	res = TRUE;
out:
	return res;
}

void set_bootname_provider(const gchar* (*provider)(void)) {
	bootname_provider = provider;
}
static void print_hash_table(GHashTable *hash_table) {
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, hash_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		g_print("  %s -> %s\n", (gchar *)key, (gchar *)value);
	}
}

gboolean do_install_bundle(const gchar* bundlefile) {

	gboolean res = FALSE;
	gchar* mountpoint;
	gchar* bundlelocation = NULL;
	RaucManifest *manifest = NULL;
	GHashTable *target_group;

	g_assert_nonnull(bundlefile);

	res = determine_slot_states();
	if (!res) {
		g_warning("Failed to determine slot states");
		goto out;
	}

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
		g_warning("Failed verifying manifest");
		goto umount;
	}

	target_group = determine_target_install_group(manifest);
	if (!target_group) {
		g_warning("Could not determine target group");
		goto umount;
	}

	g_print("Target Group:\n");
	print_hash_table(target_group);

	if (manifest->handler_name) {
		g_print("Using custom handler: %s\n", manifest->handler_name);
		res = launch_and_wait_custom_handler(mountpoint, manifest->handler_name);
	} else {
		g_print("Using default handler\n");
		res = launch_and_wait_default_handler(mountpoint, manifest, target_group);
	}

	if (!res) {
		g_warning("Starting handler failed");
		goto umount;
	}

	res = TRUE;

umount:
	umount_bundle(mountpoint);
	g_rmdir(mountpoint);
	g_clear_pointer(&mountpoint, g_free);
out:
	g_clear_pointer(&bundlelocation, g_free);
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

	res = cms_verify(manifest_data, signature_data);
	if (!res) {
		g_warning("Failed to verify manifest signature");
		goto out;
	}

	res = load_manifest_mem(manifest_data, &manifest);
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

	g_free(args);

	r_context_set_busy(FALSE);

	return G_SOURCE_REMOVE;
}

static gpointer install_thread(gpointer data) {
	RaucInstallArgs *args = data;

	g_message("thread started for %s\n", args->name);
	if (g_str_has_suffix(args->name, ".raucb")) {
		args->result = do_install_bundle(args->name);
	} else {
		args->result = do_install_network(args->name);
	}

	g_main_context_invoke(NULL, args->notify, args);

	g_message("thread finished for %s\n", args->name);

	g_main_context_invoke(NULL, install_done, args);
	return NULL;
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
