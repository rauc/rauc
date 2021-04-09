#include "checksum.h"
#include "config_file.h"
#include "context.h"
#include "manifest.h"
#include "signature.h"
#include "utils.h"

#define RAUC_IMAGE_PREFIX	"image"
#define RAUC_FILE_PREFIX	"file"

#define R_MANIFEST_ERROR r_manifest_error_quark()
GQuark r_manifest_error_quark(void)
{
	return g_quark_from_static_string("r_manifest_error_quark");
}

static gboolean parse_image(GKeyFile *key_file, const gchar *group, RaucImage **image, GError **error)
{
	g_autoptr(RaucImage) iimage = g_new0(RaucImage, 1);
	g_auto(GStrv) groupsplit = NULL;
	gchar *value;
	g_auto(GStrv) hooks = NULL;
	gsize entries;
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(key_file != NULL, FALSE);
	g_return_val_if_fail(group != NULL, FALSE);
	g_return_val_if_fail(image == NULL || *image == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	groupsplit = g_strsplit(group, ".", 3);
	g_assert_cmpint(g_strv_length(groupsplit), >=, 2);

	iimage->slotclass = g_strdup(groupsplit[1]);

	/* if we have a variant part in group, store it here */
	if (g_strv_length(groupsplit) == 3)
		iimage->variant = g_strdup(groupsplit[2]);
	else
		iimage->variant = NULL;

	value = key_file_consume_string(key_file, group, "sha256", NULL);
	if (value) {
		iimage->checksum.type = G_CHECKSUM_SHA256;
		iimage->checksum.digest = value;
	}
	iimage->checksum.size = g_key_file_get_uint64(key_file,
			group, "size", NULL);
	g_key_file_remove_key(key_file, group, "size", NULL);

	iimage->filename = key_file_consume_string(key_file, group, "filename", &ierror);
	if (iimage->filename == NULL) {
		g_propagate_error(error, ierror);
		goto out;
	}

	hooks = g_key_file_get_string_list(key_file, group, "hooks", &entries, NULL);
	for (gsize j = 0; j < entries; j++) {
		if (g_strcmp0(hooks[j], "pre-install") == 0) {
			iimage->hooks.pre_install = TRUE;
		} else if (g_strcmp0(hooks[j], "install") == 0) {
			iimage->hooks.install = TRUE;
		} else if (g_strcmp0(hooks[j], "post-install") == 0) {
			iimage->hooks.post_install = TRUE;
		} else {
			g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
					"slot hook type '%s' not supported", hooks[j]);
			goto out;
		}
	}
	g_key_file_remove_key(key_file, group, "hooks", NULL);

	if (!check_remaining_keys(key_file, group, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}
	g_key_file_remove_group(key_file, group, NULL);

	res = TRUE;
	*image = g_steal_pointer(&iimage);

out:
	return res;
}

/* Parses key_file into RaucManifest structure
 *
 * key_file - input key file
 * manifest - address of manifest pointer, pointer must be NULL and will be set
 *            to point to a newly allocated RaucManifest if parsing succeeded.
 *            Otherwise it will remain untouched.
 * error    - Return location for GError
 *
 * Returns TRUE if manifest was parsed without error, otherwise FALSE
 */
static gboolean parse_manifest(GKeyFile *key_file, RaucManifest **manifest, GError **error)
{
	GError *ierror = NULL;
	RaucManifest *raucm = g_new0(RaucManifest, 1);
	gboolean res = FALSE;
	g_autofree gchar *tmp = NULL;
	gchar **groups;
	gsize group_count;
	g_auto(GStrv) bundle_hooks = NULL;
	gsize hook_entries;

	g_assert_null(*manifest);

	/* parse [update] section */
	raucm->update_compatible = key_file_consume_string(key_file, "update", "compatible", &ierror);
	if (!raucm->update_compatible) {
		g_propagate_error(error, ierror);
		goto free;
	}
	raucm->update_version = key_file_consume_string(key_file, "update", "version", NULL);
	raucm->update_description = key_file_consume_string(key_file, "update", "description", NULL);
	raucm->update_build = key_file_consume_string(key_file, "update", "build", NULL);
	if (!check_remaining_keys(key_file, "update", &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}
	g_key_file_remove_group(key_file, "update", NULL);

	/* parse [bundle] section */
	tmp = key_file_consume_string(key_file, "bundle", "format", NULL);
	if (tmp == NULL || g_strcmp0(tmp, "plain") == 0) {
		raucm->bundle_format = R_MANIFEST_FORMAT_PLAIN;
	} else if (g_strcmp0(tmp, "verity") == 0) {
		/* only SHA256 is supported for now */
		raucm->bundle_format = R_MANIFEST_FORMAT_VERITY;
		raucm->bundle_verity_hash = key_file_consume_string(key_file, "bundle", "verity-hash", NULL);
		raucm->bundle_verity_salt = key_file_consume_string(key_file, "bundle", "verity-salt", NULL);
		raucm->bundle_verity_size = g_key_file_get_uint64(key_file, "bundle", "verity-size", NULL);
		/* values are checked in check_manifest */
		g_key_file_remove_key(key_file, "bundle", "verity-size", NULL);
	} else {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Invalid format value '%s' in group '[bundle]'", tmp);
		goto free;
	}
	if (!check_remaining_keys(key_file, "bundle", &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}
	g_key_file_remove_group(key_file, "bundle", NULL);

	/* parse [keyring] section */
	raucm->keyring = key_file_consume_string(key_file, "keyring", "archive", NULL);
	if (!check_remaining_keys(key_file, "keyring", &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}
	g_key_file_remove_group(key_file, "keyring", NULL);

	/* parse [handler] section */
	raucm->handler_name = key_file_consume_string(key_file, "handler", "filename", NULL);
	raucm->handler_args = key_file_consume_string(key_file, "handler", "args", NULL);
	if (!check_remaining_keys(key_file, "handler", &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}
	g_key_file_remove_group(key_file, "handler", NULL);

	/* parse [hooks] section */
	raucm->hook_name = key_file_consume_string(key_file, "hooks", "filename", NULL);
	bundle_hooks = g_key_file_get_string_list(key_file, "hooks", "hooks", &hook_entries, NULL);
	g_key_file_remove_key(key_file, "hooks", "hooks", NULL);
	for (gsize j = 0; j < hook_entries; j++) {
		if (g_strcmp0(bundle_hooks[j], "install-check") == 0) {
			raucm->hooks.install_check = TRUE;
		} else {
			g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
					"install hook type '%s' not supported", bundle_hooks[j]);
			goto free;
		}
	}

	if (!check_remaining_keys(key_file, "hooks", &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}
	g_key_file_remove_group(key_file, "hooks", NULL);

	/* parse [image.<slotclass>] and [file.<slotclass>/<destname>] sections */
	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		if (g_str_has_prefix(groups[i], RAUC_IMAGE_PREFIX ".")) {
			RaucImage *image = NULL;

			if (!parse_image(key_file, groups[i], &image, &ierror)) {
				g_propagate_error(error, ierror);
				goto free;
			}

			raucm->images = g_list_append(raucm->images, image);
		} else if (g_str_has_prefix(groups[i], RAUC_FILE_PREFIX ".")) {
			RaucFile *file;
			gchar *value;
			gchar **groupsplit = g_strsplit(groups[i], ".", 2);
			gchar **destsplit = NULL;
			if (groupsplit == NULL || g_strv_length(groupsplit) < 2) {
				g_strfreev(groupsplit);
				continue;
			}
			destsplit = g_strsplit(groupsplit[1], "/", 2);
			g_strfreev(groupsplit);

			if (destsplit == NULL || g_strv_length(destsplit) < 2) {
				g_strfreev(destsplit);
				continue;
			}

			file = g_new0(RaucFile, 1);

			file->slotclass = g_strdup(destsplit[0]);
			file->destname = g_strdup(destsplit[1]);

			value = key_file_consume_string(key_file, groups[i], "sha256", NULL);
			if (value) {
				file->checksum.type = G_CHECKSUM_SHA256;
				file->checksum.digest = value;
			}
			file->checksum.size = g_key_file_get_uint64(key_file,
					groups[i], "size", NULL);
			g_key_file_remove_key(key_file, groups[i], "size", NULL);


			file->filename = key_file_consume_string(key_file, groups[i], "filename", &ierror);
			if (file->filename == NULL) {
				g_propagate_error(error, ierror);
				goto free;
			}

			raucm->files = g_list_append(raucm->files, file);

			if (!check_remaining_keys(key_file, groups[i], &ierror)) {
				g_propagate_error(error, ierror);
				goto free;
			}
			g_key_file_remove_group(key_file, groups[i], NULL);
		}
	}

	if (!check_remaining_groups(key_file, &ierror)) {
		g_propagate_error(error, ierror);
		goto free;
	}

	g_strfreev(groups);

	res = TRUE;
	*manifest = g_steal_pointer(&raucm);
free:
	return res;
}

gboolean load_manifest_mem(GBytes *mem, RaucManifest **manifest, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	const gchar *data;
	gsize length;
	gboolean res = FALSE;

	data = g_bytes_get_data(mem, &length);
	if (data == NULL) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_NO_DATA, "No data available");
		goto out;
	}

	key_file = g_key_file_new();

	res = g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = parse_manifest(key_file, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

gboolean load_manifest_file(const gchar *filename, RaucManifest **manifest, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	gboolean res = FALSE;

	key_file = g_key_file_new();

	res = g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = parse_manifest(key_file, manifest, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	return res;
}

static gboolean check_manifest_common(const RaucManifest *mf, GError **error)
{
	gboolean have_hooks = FALSE;
	gboolean res = FALSE;

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
			break; /* no additional data needed */
		case R_MANIFEST_FORMAT_VERITY:
			break; /* data checked in _detached/_inline */
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format");
			goto out;
		}
	}

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;

		g_assert(image);
		g_assert(image->filename);

		if (image->checksum.type != G_CHECKSUM_SHA256) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported checksum algorithm for image %s", image->filename);
			goto out;
		}
		if (!image->checksum.digest) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing digest for image %s", image->filename);
			goto out;
		}
		if (!image->checksum.size) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing size for image %s", image->filename);
			goto out;
		}
	}

	/* Check for hook file set if hooks are enabled */

	if (mf->hooks.install_check == TRUE)
		have_hooks = TRUE;

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;
		if (image->hooks.pre_install == TRUE) {
			have_hooks = TRUE;
			break;
		}
		if (image->hooks.install == TRUE) {
			have_hooks = TRUE;
			break;
		}
		if (image->hooks.post_install == TRUE) {
			have_hooks = TRUE;
			break;
		}
	}

	if (have_hooks && !mf->hook_name) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Hooks used, but no hook 'filename' defined in [hooks] section");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

gboolean check_manifest_internal(const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	r_context_begin_step("check_manifest", "Checking manifest contents", 0);

	if (!check_manifest_common(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
			break; /* no additional data needed */
		case R_MANIFEST_FORMAT_VERITY: {
			if (mf->bundle_verity_hash) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected hash for verity bundle in internal manifest");
				goto out;
			}
			if (mf->bundle_verity_salt) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected hash for verity bundle in internal manifest");
				goto out;
			}
			if (mf->bundle_verity_size) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected hash for verity bundle in internal manifest");
				goto out;
			}

			break;
		};
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format");
			goto out;
		}
	}

	res = TRUE;
out:
	r_context_end_step("check_manifest", res);
	return res;
}

gboolean check_manifest_external(const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	r_context_begin_step("check_manifest", "Checking manifest contents", 0);

	if (!check_manifest_common(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format 'plain' for external manifest");
			goto out;
		}
		case R_MANIFEST_FORMAT_VERITY: {
			guint8 *tmp;

			if (!mf->bundle_verity_hash) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing hash for verity bundle");
				goto out;
			}
			tmp = r_hex_decode(mf->bundle_verity_hash, 32);
			if (!tmp) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Invalid hash for verity bundle");
				goto out;
			}
			g_free(tmp);

			if (!mf->bundle_verity_salt) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing salt for verity bundle");
				goto out;
			}
			tmp = r_hex_decode(mf->bundle_verity_salt, 32);
			if (!tmp) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Invalid salt for verity bundle");
				goto out;
			}
			g_free(tmp);

			if (!mf->bundle_verity_size) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing size for verity bundle");
				goto out;
			}

			if (mf->bundle_verity_size % 4096) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unaligned size for verity bundle");
				goto out;
			}

			break;
		};
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format");
			goto out;
		}
	}

	res = TRUE;
out:
	r_context_end_step("check_manifest", res);
	return res;
}

static GKeyFile *prepare_manifest(const RaucManifest *mf)
{
	g_autoptr(GKeyFile) key_file = NULL;
	GPtrArray *hooks = g_ptr_array_new_full(3, g_free);

	key_file = g_key_file_new();

	if (mf->update_compatible)
		g_key_file_set_string(key_file, "update", "compatible", mf->update_compatible);

	if (mf->update_version)
		g_key_file_set_string(key_file, "update", "version", mf->update_version);

	if (mf->update_description)
		g_key_file_set_string(key_file, "update", "description", mf->update_description);

	if (mf->update_build)
		g_key_file_set_string(key_file, "update", "build", mf->update_build);

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
			break;
		case R_MANIFEST_FORMAT_VERITY: {
			g_key_file_set_string(key_file, "bundle", "format", "verity");
			if (mf->bundle_verity_hash)
				g_key_file_set_string(key_file, "bundle", "verity-hash", mf->bundle_verity_hash);
			if (mf->bundle_verity_salt)
				g_key_file_set_string(key_file, "bundle", "verity-salt", mf->bundle_verity_salt);
			if (mf->bundle_verity_size)
				g_key_file_set_uint64(key_file, "bundle", "verity-size", mf->bundle_verity_size);

			break;
		};
		default:
			break;
	}

	if (mf->keyring)
		g_key_file_set_string(key_file, "keyring", "archive", mf->keyring);

	if (mf->handler_name)
		g_key_file_set_string(key_file, "handler", "filename", mf->handler_name);

	if (mf->handler_args)
		g_key_file_set_string(key_file, "handler", "args", mf->handler_args);

	if (mf->hook_name)
		g_key_file_set_string(key_file, "hooks", "filename", mf->hook_name);

	if (mf->hooks.install_check == TRUE) {
		g_ptr_array_add(hooks, g_strdup("install-check"));
	}
	g_ptr_array_add(hooks, NULL);
	if (hooks->pdata && *hooks->pdata) {
		g_key_file_set_string_list(key_file, "hooks", "hooks",
				(const gchar **)hooks->pdata, hooks->len);
	}
	g_ptr_array_unref(hooks);

	for (GList *l = mf->images; l != NULL; l = l->next) {
		g_autoptr(GPtrArray) hooklist = g_ptr_array_new_full(3, g_free);
		RaucImage *image = l->data;
		g_autofree gchar *group = NULL;

		if (!image || !image->slotclass)
			continue;

		group = g_strconcat(RAUC_IMAGE_PREFIX ".", image->slotclass, NULL);

		if (image->variant) {
			gchar *tmp = group;
			group = g_strconcat(group, ".", image->variant, NULL);
			g_free(tmp);
		}

		if (image->checksum.type == G_CHECKSUM_SHA256)
			g_key_file_set_string(key_file, group, "sha256", image->checksum.digest);
		if (image->checksum.size)
			g_key_file_set_uint64(key_file, group, "size", image->checksum.size);

		if (image->filename)
			g_key_file_set_string(key_file, group, "filename", image->filename);

		if (image->hooks.pre_install == TRUE) {
			g_ptr_array_add(hooklist, g_strdup("pre-install"));
		}
		if (image->hooks.install == TRUE) {
			g_ptr_array_add(hooklist, g_strdup("install"));
		}
		if (image->hooks.post_install == TRUE) {
			g_ptr_array_add(hooklist, g_strdup("post-install"));
		}
		g_ptr_array_add(hooklist, NULL);

		if (hooklist->pdata && *hooklist->pdata) {
			g_key_file_set_string_list(key_file, group, "hooks",
					(const gchar **)hooklist->pdata, hooklist->len);
		}
	}

	for (GList *l = mf->files; l != NULL; l = l->next) {
		RaucFile *file = l->data;
		g_autofree gchar *group = NULL;

		if (!file || !file->slotclass || !file->destname)
			continue;

		group = g_strconcat(RAUC_FILE_PREFIX ".", file->slotclass, "/", file->destname, NULL);

		if (file->checksum.type == G_CHECKSUM_SHA256)
			g_key_file_set_string(key_file, group, "sha256", file->checksum.digest);
		if (file->checksum.size)
			g_key_file_set_uint64(key_file, group, "size", file->checksum.size);

		if (file->filename)
			g_key_file_set_string(key_file, group, "filename", file->filename);
	}

	return g_steal_pointer(&key_file);
}

gboolean save_manifest_mem(GBytes **mem, const RaucManifest *mf)
{
	g_autoptr(GKeyFile) key_file = NULL;
	guint8 *data = NULL;
	gsize length = 0;

	g_return_val_if_fail(mem != NULL && *mem == NULL, FALSE);
	g_return_val_if_fail(mf != NULL, FALSE);

	key_file = prepare_manifest(mf);

	/* according to the docs, this never fails */
	data = (guint8*)g_key_file_to_data(key_file, &length, NULL);
	g_assert(data != NULL);
	g_assert(length > 0);

	*mem = g_bytes_new(data, length);

	return TRUE;
}

gboolean save_manifest_file(const gchar *filename, const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	gboolean res = FALSE;

	key_file = prepare_manifest(mf);

	res = g_key_file_save_to_file(key_file, filename, &ierror);
	if (!res)
		g_propagate_error(error, ierror);

	return res;
}

void r_free_image(gpointer data)
{
	RaucImage *image = (RaucImage*) data;

	g_return_if_fail(image);

	g_free(image->slotclass);
	g_free(image->variant);
	g_free(image->checksum.digest);
	g_free(image->filename);
	g_free(image);
}

void r_free_file(gpointer data)
{
	RaucFile *file = (RaucFile*) data;

	g_return_if_fail(file);

	g_free(file->slotclass);
	g_free(file->destname);
	g_free(file->checksum.digest);
	g_free(file->filename);
	g_free(file);
}

void free_manifest(RaucManifest *manifest)
{
	g_return_if_fail(manifest);

	g_free(manifest->update_compatible);
	g_free(manifest->update_version);
	g_free(manifest->update_description);
	g_free(manifest->update_build);
	g_free(manifest->bundle_verity_hash);
	g_free(manifest->bundle_verity_salt);
	g_free(manifest->keyring);
	g_free(manifest->handler_name);
	g_free(manifest->handler_args);
	g_free(manifest->hook_name);
	g_list_free_full(manifest->images, r_free_image);
	g_list_free_full(manifest->files, r_free_file);
	g_free(manifest);
}

/**
 * Updates checksums for files and images listed in the manifest and found in
 * the bundle directory.
 *
 * @param manifest pointer to the manifest
 * @param dir Directory with the bundle content
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
static gboolean update_manifest_checksums(RaucManifest *manifest, const gchar *dir, GError **error)
{
	GError *ierror = NULL;
	gboolean res = TRUE;
	gboolean had_errors = FALSE;

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		g_autofree gchar *filename = g_build_filename(dir, image->filename, NULL);
		res = compute_checksum(&image->checksum, filename, &ierror);
		if (!res) {
			g_warning("Failed updating checksum: %s", ierror->message);
			g_clear_error(&ierror);
			had_errors = TRUE;
			break;
		}
	}

	for (GList *elem = manifest->files; elem != NULL; elem = elem->next) {
		RaucFile *file = elem->data;
		g_autofree gchar *filename = g_build_filename(dir, file->filename, NULL);
		res = compute_checksum(&file->checksum, filename, &ierror);
		if (!res) {
			g_warning("Failed updating checksum: %s", ierror->message);
			g_clear_error(&ierror);
			had_errors = TRUE;
			break;
		}
	}

	if (had_errors) {
		res = FALSE;
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_CHECKSUM, "Failed updating all checksums");
	}

	return res;
}

gboolean sync_manifest_with_contentdir(RaucManifest *manifest, const gchar *dir, GError **error)
{
	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(dir, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Check for missing image files */
	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		g_autofree gchar *filename = g_build_filename(dir, image->filename, NULL);
		if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_CHECKSUM, "image file '%s' for slot '%s' does not exist in bundle content dir (%s)", image->filename, image->slotclass, dir);
			return FALSE;
		}
	}

	/* Check for missing hook file */
	if (manifest->hook_name) {
		g_autofree gchar *hookpath = NULL;
		hookpath = g_build_filename(dir, manifest->hook_name, NULL);
		if (!g_file_test(hookpath, G_FILE_TEST_EXISTS)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_CHECKSUM, "hook file '%s' does not exist in bundle content dir (%s)", manifest->hook_name, dir);
			return FALSE;
		}
	}

	return update_manifest_checksums(manifest, dir, error);
}
