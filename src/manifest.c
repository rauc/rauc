#include "manifest.h"

#include <checksum.h>
#include <config_file.h>
#include <context.h>
#include <signature.h>
#include <utils.h>

#define RAUC_IMAGE_PREFIX	"image"
#define RAUC_FILE_PREFIX	"file"

static gboolean parse_manifest(GKeyFile *key_file, RaucManifest **manifest) {
	RaucManifest *raucm = g_new0(RaucManifest, 1);
	gboolean res = FALSE;
	gchar **groups;
	gsize group_count;

	/* parse [update] section */
	raucm->update_compatible = g_key_file_get_string(key_file, "update", "compatible", NULL);
	if (!raucm->update_compatible) {
		goto free;
	}
	raucm->update_version = g_key_file_get_string(key_file, "update", "version", NULL);

	/* parse [keyring] section */
	raucm->keyring = g_key_file_get_string(key_file, "keyring", "archive", NULL);

	/* parse [handler] section */
	raucm->handler_name = g_key_file_get_string(key_file, "handler", "filename", NULL);

	/* parse [image.<slotclass>] and [file.<slotclass>/<destname>] sections */
	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		gchar **groupsplit = g_strsplit(groups[i], ".", 2);
		if (groupsplit == NULL || g_strv_length(groupsplit) < 2) {
			g_strfreev(groupsplit);
			continue;
		}

		if (g_str_equal(groupsplit[0], RAUC_IMAGE_PREFIX)) {
			RaucImage *image = g_new0(RaucImage, 1);
			gchar *value;

			image->slotclass = g_strdup(groupsplit[1]);

			value = g_key_file_get_string(key_file, groups[i], "sha256", NULL);
			if (value) {
				image->checksum.type = G_CHECKSUM_SHA256;
				image->checksum.digest = value;
			}
			image->checksum.size = g_key_file_get_uint64(key_file,
					groups[i], "size", NULL);

			image->filename = g_key_file_get_string(key_file, groups[i], "filename", NULL);

			raucm->images = g_list_append(raucm->images, image);
		} else if (g_str_equal(groupsplit[0], RAUC_FILE_PREFIX)) {
			gchar **destsplit = g_strsplit(groupsplit[1], "/", 2);
			RaucFile *file;
			gchar *value;

			if (destsplit == NULL || g_strv_length(destsplit) < 2) {
				g_strfreev(destsplit);
				continue;
			}

			file = g_new0(RaucFile, 1);

			file->slotclass = g_strdup(destsplit[0]);
			file->destname = g_strdup(destsplit[1]);

			value = g_key_file_get_string(key_file, groups[i], "sha256", NULL);
			if (value) {
				file->checksum.type = G_CHECKSUM_SHA256;
				file->checksum.digest = value;
			}
			file->checksum.size = g_key_file_get_uint64(key_file,
					groups[i], "size", NULL);


			file->filename = g_key_file_get_string(key_file, groups[i], "filename", NULL);

			raucm->files = g_list_append(raucm->files, file);
		}

		g_strfreev(groupsplit);
	}

	g_strfreev(groups);

	res = TRUE;
free:
	*manifest = raucm;

	return res;
}

gboolean load_manifest_mem(GBytes *mem, RaucManifest **manifest) {
	GKeyFile *key_file = NULL;
	const gchar *data;
	gsize length;
	gboolean res = FALSE;

	data = g_bytes_get_data(mem, &length);
	if (data == NULL)
		goto out;

	key_file = g_key_file_new();

	res = g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto out;

	res = parse_manifest(key_file, manifest);

out:
	g_clear_pointer(&key_file, g_key_file_free);
	return res;
}

gboolean load_manifest_file(const gchar *filename, RaucManifest **manifest) {
	GKeyFile *key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);
	if (!res)
		goto out;

	res = parse_manifest(key_file, manifest);

out:
	g_clear_pointer(&key_file, g_key_file_free);
	return res;
}

gboolean save_manifest_file(const gchar *filename, RaucManifest *mf) {
	GKeyFile *key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	if (mf->update_compatible)
		g_key_file_set_string(key_file, "update", "compatible", mf->update_compatible);

	if (mf->update_version)
		g_key_file_set_string(key_file, "update", "version", mf->update_version);

	if (mf->keyring)
		g_key_file_set_string(key_file, "keyring", "archive", mf->keyring);

	if (mf->handler_name)
		g_key_file_set_string(key_file, "handler", "filename", mf->handler_name);

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;
		gchar *group;

		if (!image || !image->slotclass)
			continue;

		group = g_strconcat(RAUC_IMAGE_PREFIX ".", image->slotclass, NULL);

		if (image->checksum.type == G_CHECKSUM_SHA256)
			g_key_file_set_string(key_file, group, "sha256", image->checksum.digest);
		if (image->checksum.size)
			g_key_file_set_uint64(key_file, group, "size", image->checksum.size);

		if (image->filename)
			g_key_file_set_string(key_file, group, "filename", image->filename);

		g_free(group);
	}

	for (GList *l = mf->files; l != NULL; l = l->next) {
		RaucFile *file = l->data;
		gchar *group;

		if (!file || !file->slotclass || !file->destname)
			continue;

		group = g_strconcat(RAUC_FILE_PREFIX ".", file->slotclass, "/", file->destname, NULL);

		if (file->checksum.type == G_CHECKSUM_SHA256)
			g_key_file_set_string(key_file, group, "sha256", file->checksum.digest);
		if (file->checksum.size)
			g_key_file_set_uint64(key_file, group, "size", file->checksum.size);

		if (file->filename)
			g_key_file_set_string(key_file, group, "filename", file->filename);

		g_free(group);
	}

	res = g_key_file_save_to_file(key_file, filename, NULL);
	if (!res)
		goto free;

free:
	g_key_file_free(key_file);

	return res;
}

static void free_image(gpointer data) {
	RaucImage *image = (RaucImage*) data;

	g_free(image->slotclass);
	g_free(image->checksum.digest);
	g_free(image->filename);
	g_free(image);
}

static void free_file(gpointer data) {
	RaucFile *file = (RaucFile*) data;

	g_free(file->slotclass);
	g_free(file->destname);
	g_free(file->checksum.digest);
	g_free(file->filename);
	g_free(file);
}

void free_manifest(RaucManifest *manifest) {

	g_free(manifest->update_compatible);
	g_free(manifest->update_version);
	g_free(manifest->keyring);
	g_free(manifest->handler_name);
	g_list_free_full(manifest->images, free_image);
	g_list_free_full(manifest->files, free_file);
	g_free(manifest);
}


static gboolean update_manifest_checksums(RaucManifest *manifest, const gchar *dir) {
	gboolean res = TRUE;

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		gchar *filename = g_build_filename(dir, image->filename, NULL);
		res = update_checksum(&image->checksum, filename);
		g_free(filename);
		if (!res)
			break;
	}

	for (GList *elem = manifest->files; elem != NULL; elem = elem->next) {
		RaucFile *file = elem->data;
		gchar *filename = g_build_filename(dir, file->filename, NULL);
		res = update_checksum(&file->checksum, filename);
		g_free(filename);
		if (!res)
			break;
	}

	return res;
}

static gboolean verify_manifest_checksums(RaucManifest *manifest, const gchar *dir) {
	gboolean res = TRUE;

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		gchar *filename = g_build_filename(dir, image->filename, NULL);
		res = verify_checksum(&image->checksum, filename);
		g_free(filename);
		if (!res)
			break;
	}

	for (GList *elem = manifest->files; elem != NULL; elem = elem->next) {
		RaucFile *file = elem->data;
		gchar *filename = g_build_filename(dir, file->filename, NULL);
		res = verify_checksum(&file->checksum, filename);
		g_free(filename);
		if (!res)
			break;
	}

	return res;
}

gboolean update_manifest(const gchar *dir, gboolean signature) {
	gchar* manifestpath = g_build_filename(dir, "manifest.raucm", NULL);
	gchar* signaturepath = g_build_filename(dir, "manifest.raucm.sig", NULL);
	RaucManifest *manifest = NULL;
	GBytes *sig = NULL;
	gboolean res = FALSE;

	if (signature) {
		g_assert_nonnull(r_context()->certpath);
		g_assert_nonnull(r_context()->keypath);
	}

	res = load_manifest_file(manifestpath, &manifest);
	if (!res)
		goto out;

	res = update_manifest_checksums(manifest, dir);
	if (!res)
		goto out;

	res = save_manifest_file(manifestpath, manifest);
	if (!res)
		goto out;

	if (signature) {
		sig = cms_sign_file(manifestpath,
				    r_context()->certpath,
				    r_context()->keypath);
		if (sig == NULL)
			goto out;

		res = write_file(signaturepath, sig);
		if (!res)
			goto out;
	}

out:
	g_clear_pointer(&sig, g_bytes_unref);
	g_clear_pointer(&manifest, free_manifest);
	g_free(signaturepath);
	g_free(manifestpath);
	return res;
}

static gboolean check_compatible(RaucManifest *manifest) {
	g_assert_nonnull(r_context()->config);
	g_assert_nonnull(r_context()->config->system_compatible);

	return (g_strcmp0(r_context()->config->system_compatible, manifest->update_compatible) == 0);
}

gboolean verify_manifest(const gchar *dir, RaucManifest **output, gboolean signature) {
	gchar* manifestpath = g_build_filename(dir, "manifest.raucm", NULL);
	gchar* signaturepath = g_build_filename(dir, "manifest.raucm.sig", NULL);
	RaucManifest *manifest = NULL;
	GBytes *sig = NULL;
	gboolean res = FALSE;

	if (signature) {
		sig = read_file(signaturepath);
		if (sig == NULL)
			goto out;

		res = cms_verify_file(manifestpath, sig, 0);
		if (!res)
			goto out;

	}

	res = load_manifest_file(manifestpath, &manifest);
	if (!res) {
		g_warning("Failed opening manifest");
		goto out;
	}

	res = verify_manifest_checksums(manifest, dir);
	if (!res) {
		g_warning("Invalid checksums");
		goto out;
	}

	res = check_compatible(manifest);
	if (!res) {
		g_warning("Invalid compatible");
		goto out;
	}

	if (output != NULL) {
		*output = manifest;
		manifest = NULL;
	}


out:
	g_clear_pointer(&sig, g_bytes_unref);
	g_clear_pointer(&manifest, free_manifest);
	g_free(signaturepath);
	g_free(manifestpath);
	return res;
}
