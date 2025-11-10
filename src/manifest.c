#include <string.h>

#include "checksum.h"
#include "config_file.h"
#include "context.h"
#include "manifest.h"
#include "glib.h"
#include "signature.h"
#include "update_handler.h"
#include "utils.h"

#define RAUC_IMAGE_PREFIX	"image"

#define R_MANIFEST_ERROR r_manifest_error_quark()

GQuark r_manifest_error_quark(void)
{
	return g_quark_from_static_string("r_manifest_error_quark");
}

static gboolean handle_missing_type(RaucImage *image, GError **error)
{
	/* When using custom install hooks, having no type is okay */
	if (image->hooks.install)
		return TRUE;

	const gchar *derived_type = derive_image_type_from_filename_pattern(image->filename);
	if (!derived_type) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE,
				"No 'type=' set and unable to map extension of file '%s' to known image type",
				image->filename);
		return FALSE;
	}

	image->type_from_fileext = TRUE;
	image->type = g_strdup(derived_type);
	return TRUE;
}

static gboolean validate_filename_requirements(RaucImage *image, GError **error)
{
	gboolean has_filename = (image->filename != NULL);
	gboolean has_install_hook = image->hooks.install;

	/* Combining 'type=emptyfs' with an image filename would be contradictory */
	if (g_strcmp0(image->type, "emptyfs") == 0) {
		if (has_filename) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_PARSE_ERROR,
					"It is not supported setting 'filename' when 'type=emptyfs' is set");
			return FALSE;
		}
	} else {
		/* All other image types require either a source file
		 * or custom install hooks. */
		if (!has_filename && !has_install_hook) {
			g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND,
					"Missing required 'filename'");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean parse_image(GKeyFile *key_file, const gchar *group, RaucImage **image, GError **error)
{
	g_autoptr(RaucImage) iimage = r_new_image();
	g_auto(GStrv) groupsplit = NULL;
	gchar *value;
	g_auto(GStrv) hooks = NULL;
	gsize entries;
	g_auto(GStrv) converted = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(key_file != NULL, FALSE);
	g_return_val_if_fail(group != NULL, FALSE);
	g_return_val_if_fail(image == NULL || *image == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* We support several formats:
	 * - [image.rootfs]
	 * - [image.rootfs.product-a]
	 * - [image.appfs/app-1]
	 * - [image.appfs/app-1.product-a]
	 */

	groupsplit = g_strsplit(group, ".", 3);
	g_assert_cmpint(g_strv_length(groupsplit), >=, 2);
	g_assert_cmpstr(groupsplit[0], ==, "image");

	g_auto(GStrv) targetsplit = NULL;
	targetsplit = g_strsplit(groupsplit[1], "/", 2);
	iimage->slotclass = g_strdup(targetsplit[0]);

	/* Do we have an artifact name for this image? */
	if (g_strv_length(targetsplit) == 2)
		iimage->artifact = g_strdup(targetsplit[1]);

	/* Do we have a variant name for this image? */
	if (g_strv_length(groupsplit) == 3)
		iimage->variant = g_strdup(groupsplit[2]);

	value = key_file_consume_string(key_file, group, "sha256", NULL);
	if (value) {
		iimage->checksum.type = G_CHECKSUM_SHA256;
		iimage->checksum.digest = value;
	}
	iimage->checksum.size = g_key_file_get_uint64(key_file,
			group, "size", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		/* restore size to the default of -1 */
		iimage->checksum.size = -1;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, group, "size", NULL);

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
			return FALSE;
		}
	}
	g_key_file_remove_key(key_file, group, "hooks", NULL);

	iimage->filename = key_file_consume_string(key_file, group, "filename", &ierror);
	/* A missing 'filename' can be correct, as it is optional for 'install' hooks and 'type=emptyfs'.
	 * So we collect all requirements first and check their validity afterwards */
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Setting the 'type' option for artifacts is not supported.
	 * For regular images (non-artifacts), we need to determine the image 'type'
	 * to select the appropriate update handler. The image 'type' can be determined either
	 * by the corresponding variable in the manifest, or derived by the file name extension. */
	if (!iimage->artifact) {
		iimage->type_from_fileext = FALSE;
		iimage->type = key_file_consume_string(key_file, group, "type", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			g_clear_error(&ierror);
			g_clear_pointer(&iimage->type, g_free);
			if (!handle_missing_type(iimage, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		/* Custom install hooks can skip validation of supported image types
		 * since they implement their own logic */
		if (!iimage->hooks.install && !is_image_type_supported(iimage->type)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_INVALID_IMAGE_TYPE,
					"Unsupported image type '%s'", iimage->type);
			return FALSE;
		}
	}

	/* All requirements to check if a filename is necessary have been collected,
	 * so we can now check if the current state is valid */
	if (!validate_filename_requirements(iimage, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	g_key_file_remove_key(key_file, group, "version", NULL);
	g_key_file_remove_key(key_file, group, "description", NULL);
	g_key_file_remove_key(key_file, group, "build", NULL);

	iimage->adaptive = g_key_file_get_string_list(key_file, group, "adaptive", NULL, NULL);
	g_key_file_remove_key(key_file, group, "adaptive", NULL);

	iimage->convert = g_key_file_get_string_list(key_file, group, "convert", NULL, NULL);
	g_key_file_remove_key(key_file, group, "convert", NULL);

	converted = g_key_file_get_string_list(key_file, group, "converted", NULL, NULL);
	g_key_file_remove_key(key_file, group, "converted", NULL);
	if (converted) {
		iimage->converted = g_ptr_array_new_with_free_func(g_free);
		r_ptr_array_addv(iimage->converted, converted, TRUE);
	}

	if (!check_remaining_keys(key_file, group, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, group, NULL);

	*image = g_steal_pointer(&iimage);

	return TRUE;
}

static gboolean parse_meta(GKeyFile *key_file, const gchar *group, RaucManifest *raucm, GError **error)
{
	g_auto(GStrv) groupsplit = NULL;
	g_auto(GStrv) keys = NULL;
	g_autoptr(GHashTable) kvs = NULL;
	g_autofree gchar *env_section = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(key_file != NULL, FALSE);
	g_return_val_if_fail(group != NULL, FALSE);
	g_return_val_if_fail(raucm != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	groupsplit = g_strsplit(group, ".", 2);
	if ((g_strv_length(groupsplit) != 2) || strchr(groupsplit[1], '.')) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"invalid metadata section name '%s' (must contain a single '.')", group);
		return FALSE;
	}

	env_section = r_prepare_env_key(groupsplit[1], &ierror);
	if (!env_section) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Invalid metadata section name '%s': ", groupsplit[1]);
		return FALSE;
	}

	kvs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	keys = g_key_file_get_keys(key_file, group, NULL, NULL);
	for (GStrv key = keys; *key; key++) {
		g_autofree gchar *value = key_file_consume_string(key_file, group, *key, &ierror);
		g_autofree gchar *env_key = NULL;

		if (!value) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		env_key = r_prepare_env_key(*key, &ierror);
		if (!env_key) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"Invalid metadata key name '%s': ", *key);
			return FALSE;
		}

		g_hash_table_insert(kvs, g_strdup(*key), g_steal_pointer(&value));
	}

	g_hash_table_insert(raucm->meta, g_strdup(groupsplit[1]), g_steal_pointer(&kvs));
	g_key_file_remove_group(key_file, group, NULL);

	return TRUE;
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
	g_autoptr(RaucManifest) raucm = g_new0(RaucManifest, 1);
	g_autofree gchar *tmp = NULL;
	g_auto(GStrv) groups = NULL;
	gsize group_count;
	g_auto(GStrv) bundle_hooks = NULL;
	gsize hook_entries;

	g_return_val_if_fail(key_file != NULL, FALSE);
	g_return_val_if_fail(manifest != NULL && *manifest == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* initialize empty warnings array */
	raucm->warnings = g_ptr_array_new_with_free_func(g_free);

	/* parse [update] section */
	raucm->update_compatible = key_file_consume_string(key_file, "update", "compatible", &ierror);
	if (!raucm->update_compatible) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	raucm->update_version = key_file_consume_string(key_file, "update", "version", NULL);
	raucm->update_description = key_file_consume_string(key_file, "update", "description", NULL);
	raucm->update_build = key_file_consume_string(key_file, "update", "build", NULL);
	raucm->update_min_rauc_version = key_file_consume_string(key_file, "update", "min-rauc-version", NULL);
	if (!check_remaining_keys(key_file, "update", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "update", NULL);

	/* parse [bundle] section */
	tmp = key_file_consume_string(key_file, "bundle", "format", NULL);
	if (tmp == NULL) {
		g_ptr_array_add(raucm->warnings, g_strdup(
				"WARNING: The manifest does not specify a bundle format, defaulting to 'plain'."));
		g_ptr_array_add(raucm->warnings, g_strdup(
				"  We recommend using the 'verity' format instead, if possible."));
		g_ptr_array_add(raucm->warnings, g_strdup(
				"  To silence this warning, select the 'plain' format explicitly."));
		g_ptr_array_add(raucm->warnings, g_strdup(
				"  See https://rauc.readthedocs.io/en/latest/reference.html#sec-ref-formats for details.'"));
	} else {
		raucm->bundle_format_explicit = TRUE;
	}
	if (tmp == NULL || g_strcmp0(tmp, "plain") == 0) {
		raucm->bundle_format = R_MANIFEST_FORMAT_PLAIN;
	} else if ((g_strcmp0(tmp, "verity") == 0) || (g_strcmp0(tmp, "crypt") == 0)) {
		/* only SHA256 is supported for now */
		raucm->bundle_format = g_strcmp0(tmp, "crypt") == 0 ? R_MANIFEST_FORMAT_CRYPT : R_MANIFEST_FORMAT_VERITY;
		raucm->bundle_verity_hash = key_file_consume_string(key_file, "bundle", "verity-hash", NULL);
		raucm->bundle_verity_salt = key_file_consume_string(key_file, "bundle", "verity-salt", NULL);
		raucm->bundle_verity_size = g_key_file_get_uint64(key_file, "bundle", "verity-size", NULL);
		/* values are checked in check_manifest */
		g_key_file_remove_key(key_file, "bundle", "verity-size", NULL);
	} else {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Invalid format value '%s' in group '[bundle]'", tmp);
		return FALSE;
	}
	/* crypt format requires additional dm-crypt key */
	if (g_strcmp0(tmp, "crypt") == 0) {
		raucm->bundle_crypt_key = key_file_consume_string(key_file, "bundle", "crypt-key", NULL);
	}
	if (!check_remaining_keys(key_file, "bundle", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "bundle", NULL);

	/* parse [handler] section */
	raucm->handler_name = key_file_consume_string(key_file, "handler", "filename", NULL);
	raucm->handler_args = key_file_consume_string(key_file, "handler", "args", NULL);
	raucm->preinstall_handler = key_file_consume_string(key_file, "handler", "pre-install", NULL);
	raucm->postinstall_handler = key_file_consume_string(key_file, "handler", "post-install", NULL);
	if (raucm->handler_args && !raucm->handler_name) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Setting 'args' requires a full custom handler to be defined under 'filename' in group '[handler]'.");
		return FALSE;
	}
	if (!check_remaining_keys(key_file, "handler", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
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
			return FALSE;
		}
	}

	if (!check_remaining_keys(key_file, "hooks", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "hooks", NULL);

	raucm->meta = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		/* parse [image.<slotclass>] sections */
		if (g_str_has_prefix(groups[i], RAUC_IMAGE_PREFIX ".")) {
			RaucImage *image = NULL;

			if (!parse_image(key_file, groups[i], &image, &ierror)) {
				g_propagate_prefixed_error(error, ierror, "Cannot parse [%s]: ", groups[i]);
				return FALSE;
			}

			raucm->images = g_list_append(raucm->images, image);
		}
		/* parse [meta.<label>] sections */
		if (g_str_has_prefix(groups[i], "meta.")) {
			if (!parse_meta(key_file, groups[i], raucm, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
		}
	}

	/* ignore [rollout] section for now, so that we can add hints/overrides
	 * for rollout/polling behaviour later */
	g_key_file_remove_group(key_file, "rollout", NULL);

	if (!check_remaining_groups(key_file, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	*manifest = g_steal_pointer(&raucm);

	return TRUE;
}

gboolean load_manifest_mem(GBytes *mem, RaucManifest **manifest, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	const gchar *data;
	gsize length;
	g_autofree gchar *manifest_checksum = NULL;

	g_return_val_if_fail(mem, FALSE);
	g_return_val_if_fail(manifest != NULL && *manifest == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	data = g_bytes_get_data(mem, &length);
	if (data == NULL) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_NO_DATA, "No data available");
		return FALSE;
	}

	manifest_checksum = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar*) data, length);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!parse_manifest(key_file, manifest, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	(*manifest)->hash = g_steal_pointer(&manifest_checksum);

	return TRUE;
}

gboolean load_manifest_file(const gchar *filename, RaucManifest **manifest, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *data = NULL;
	gsize length;
	g_autoptr(GKeyFile) key_file = NULL;
	g_autofree gchar *manifest_checksum = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(manifest != NULL && *manifest == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_file_get_contents(filename, &data, &length, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	manifest_checksum = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar*) data, length);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!parse_manifest(key_file, manifest, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	(*manifest)->hash = g_steal_pointer(&manifest_checksum);

	return TRUE;
}

static gboolean check_manifest_common(const RaucManifest *mf, GError **error)
{
	gboolean have_hooks = FALSE;

	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (mf->update_min_rauc_version) {
		if (!r_semver_less_equal("0", mf->update_min_rauc_version, NULL)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Failed to parse 'min-rauc-version'. Expected 'Major[.Minor[.Patch]][-pre_release]]', got '%s'",
					mf->update_min_rauc_version
					);
			return FALSE;
		}
		if (!r_semver_less_equal(mf->update_min_rauc_version, RAUC_MESON_VERSION, NULL)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Minimum RAUC version in manifest (%s) is newer than current version (%s)",
					mf->update_min_rauc_version, RAUC_MESON_VERSION
					);
			return FALSE;
		}
		if (r_semver_less_equal(mf->update_min_rauc_version, "1.13", NULL)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Minimum RAUC version field in manifest is only supported since 1.14 (not '%s')",
					mf->update_min_rauc_version
					);
			return FALSE;
		}
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
			break; /* no additional data needed */
		case R_MANIFEST_FORMAT_VERITY:
		case R_MANIFEST_FORMAT_CRYPT:
			break; /* data checked in _detached/_inline */
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format");
			return FALSE;
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
		return FALSE;
	}

	return TRUE;
}

static gboolean check_manifest_plain(const RaucManifest *mf, GError **error)
{
	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(mf->bundle_format == R_MANIFEST_FORMAT_PLAIN);

	for (GList *elem = mf->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;

		/* Check for features not supported in plain bundles */
		if (image->artifact) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Artifacts are not supported in plain bundles");
			return FALSE;
		}
		if (image->convert || (image->converted && image->converted->len)) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Image converters are not supported in plain bundles");
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Check a loaded manifest for consistency. Manifests generated by 'rauc bundle'
 * should pass this check if they are compatible with the running version.
 *
 * This function is called for both internal and external manifests.
 */
static gboolean check_manifest_bundled(const RaucManifest *mf, GError **error)
{
	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;

		g_assert(image);

		/* Having no 'filename' set is valid for 'install' hook only.
		 * This is already ensured during manifest parsing, thus simply
		 * skip further checks here */
		if (!image->filename)
			continue;

		if (image->checksum.type != G_CHECKSUM_SHA256) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported checksum algorithm for image %s", image->filename);
			return FALSE;
		}
		if (!image->checksum.digest) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing digest for image %s", image->filename);
			return FALSE;
		}
		if (image->checksum.size < 0) {
			/* RAUC versions before v1.5 allowed zero-size images but did not handle this explicitly.
			 * Thus, bundles created did have a valid 'filename=' manifest entry
			 * but the 'size=' entry was considered as empty and not set at all.
			 * Retain support for this case, at least for the 'install' per-slot hook use-case
			 * where an image file can be optional. */
			if (image->hooks.install) {
				g_message("Missing size parameter for image '%s'", image->filename);
				image->checksum.size = 0;
			} else {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing size for image %s", image->filename);
				return FALSE;
			}
		}

		if (image->convert) {
			guint expected_len = g_strv_length(image->convert);

			if (!image->converted) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing converted outputs for image %s", image->filename);
				return FALSE;
			}

			if (expected_len != image->converted->len) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Inconsistent number of converted inputs/outputs for image %s", image->filename);
				return FALSE;
			}
		}
	}

	return TRUE;
}

gboolean check_manifest_input(const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!check_manifest_common(mf, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
		case R_MANIFEST_FORMAT_CRYPT:
		case R_MANIFEST_FORMAT_VERITY:
			break;
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format in input manifest");
			return FALSE;
		}
	}

	if (mf->bundle_format == R_MANIFEST_FORMAT_PLAIN) {
		if (!check_manifest_plain(mf, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;

		g_assert(image);

		if (image->filename && strchr(image->filename, '/')) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Image filename %s must not contain '/'", image->filename);
			return FALSE;
		}
		if (image->checksum.digest) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Unexpected digest for image %s in input manifest", image->filename);
			return FALSE;
		}
		if (image->checksum.size != -1) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Unexpected size %"G_GOFFSET_FORMAT " for image %s in input manifest", image->checksum.size, image->filename);
			return FALSE;
		}
		if (image->converted && image->converted->len) {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"Unexpected 'converted' option in input manifest");
			return FALSE;
		}
	}

	return TRUE;
}

gboolean check_manifest_internal(const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("check_manifest", "Checking manifest contents", 0);

	if (!check_manifest_common(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN:
			break; /* no additional data needed */
		case R_MANIFEST_FORMAT_CRYPT:
		case R_MANIFEST_FORMAT_VERITY:
		default: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Bundle format '%s' not allowed for internal manifest", r_manifest_bundle_format_to_str(mf->bundle_format));
			goto out;
		}
	}

	if (!check_manifest_bundled(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (!check_manifest_plain(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	if (mf->bundle_crypt_key) {
		g_set_error_literal(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected key for crypt bundle in internal manifest");
		goto out;
	}
	if (mf->bundle_verity_hash) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected verity hash for %s bundle in internal manifest", r_manifest_bundle_format_to_str(mf->bundle_format));
		goto out;
	}
	if (mf->bundle_verity_salt) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected verity salt for %s bundle in internal manifest", r_manifest_bundle_format_to_str(mf->bundle_format));
		goto out;
	}
	if (mf->bundle_verity_size) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unexpected verity size for %s bundle in internal manifest", r_manifest_bundle_format_to_str(mf->bundle_format));
		goto out;
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
	const gchar *format = NULL;

	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	r_context_begin_step("check_manifest", "Checking manifest contents", 0);

	format = r_manifest_bundle_format_to_str(mf->bundle_format);
	if (g_strcmp0(format, "invalid") == 0) {
		g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format");
		goto out;
	}

	if (!check_manifest_common(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	switch (mf->bundle_format) {
		case R_MANIFEST_FORMAT_PLAIN: {
			g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unsupported bundle format 'plain' for external manifest");
			goto out;
		}
		case R_MANIFEST_FORMAT_CRYPT: {
			guint8 *tmp;

			if (!mf->bundle_crypt_key) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing key for crypt bundle");
				goto out;
			}
			tmp = r_hex_decode(mf->bundle_crypt_key, 32);
			if (!tmp) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Invalid key for crypt bundle");
				goto out;
			}
			g_free(tmp);
		};
		/* Fallthrough */
		case R_MANIFEST_FORMAT_VERITY: {
			guint8 *tmp;

			if (!mf->bundle_verity_hash) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing hash for %s bundle", format);
				goto out;
			}
			tmp = r_hex_decode(mf->bundle_verity_hash, 32);
			if (!tmp) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Invalid hash for %s bundle", format);
				goto out;
			}
			g_free(tmp);

			if (!mf->bundle_verity_salt) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing salt for %s bundle", format);
				goto out;
			}
			tmp = r_hex_decode(mf->bundle_verity_salt, 32);
			if (!tmp) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Invalid salt for %s bundle", format);
				goto out;
			}
			g_free(tmp);

			if (!mf->bundle_verity_size) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Missing size for %s bundle", format);
				goto out;
			}

			if (mf->bundle_verity_size % 4096) {
				g_set_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR, "Unaligned size for %s bundle", format);
				goto out;
			}

			break;
		};
		default: {
			/* should not be reached as this is checked before */
			g_error("Unsupported bundle format");
			goto out;
		}
	}

	if (!check_manifest_bundled(mf, &ierror)) {
		g_propagate_error(error, ierror);
		goto out;
	}

	res = TRUE;
out:
	r_context_end_step("check_manifest", res);
	return res;
}

gboolean check_manifest_create(const RaucManifest *mf, GError **error)
{
	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	for (GList *l = mf->images; l != NULL; l = l->next) {
		RaucImage *image = l->data;

		g_assert(image);

		if (image->hooks.install && (image->hooks.pre_install || image->hooks.post_install)) {
			g_set_error_literal(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR,
					"An 'install' hook must not be combined with 'pre-install' or 'post-install' hooks");
			return FALSE;
		}
	}

	return TRUE;
}

static GKeyFile *prepare_manifest(const RaucManifest *mf)
{
	g_autoptr(GKeyFile) key_file = NULL;
	GPtrArray *hooks = g_ptr_array_new_full(3, g_free);
	GHashTableIter iter;
	GHashTable *meta_kvs;
	const gchar *meta_group;

	g_return_val_if_fail(mf, FALSE);

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
			if (mf->bundle_format_explicit)
				g_key_file_set_string(key_file, "bundle", "format", "plain");
			break;
		case R_MANIFEST_FORMAT_CRYPT: {
			if (mf->bundle_crypt_key)
				g_key_file_set_string(key_file, "bundle", "crypt-key", mf->bundle_crypt_key);
		};
		/* Fallthrough */
		case R_MANIFEST_FORMAT_VERITY: {
			g_key_file_set_string(key_file, "bundle", "format", r_manifest_bundle_format_to_str(mf->bundle_format));
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

	if (mf->handler_name)
		g_key_file_set_string(key_file, "handler", "filename", mf->handler_name);

	if (mf->handler_args)
		g_key_file_set_string(key_file, "handler", "args", mf->handler_args);

	if (mf->preinstall_handler)
		g_key_file_set_string(key_file, "handler", "pre-install", mf->preinstall_handler);

	if (mf->postinstall_handler)
		g_key_file_set_string(key_file, "handler", "post-install", mf->postinstall_handler);

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

		if (image->artifact) {
			gchar *tmp = group;
			group = g_strconcat(group, "/", image->artifact, NULL);
			g_free(tmp);
		}

		if (image->variant) {
			gchar *tmp = group;
			group = g_strconcat(group, ".", image->variant, NULL);
			g_free(tmp);
		}

		if (image->checksum.type == G_CHECKSUM_SHA256)
			g_key_file_set_string(key_file, group, "sha256", image->checksum.digest);
		if (image->checksum.size >= 0)
			g_key_file_set_uint64(key_file, group, "size", image->checksum.size);

		if (image->filename)
			g_key_file_set_string(key_file, group, "filename", image->filename);

		if (image->type && !image->type_from_fileext)
			g_key_file_set_string(key_file, group, "type", image->type);

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

		if (image->adaptive)
			g_key_file_set_string_list(key_file, group, "adaptive",
					(const gchar * const *)image->adaptive, g_strv_length(image->adaptive));

		if (image->convert)
			g_key_file_set_string_list(key_file, group, "convert",
					(const gchar * const *)image->convert, g_strv_length(image->convert));
		if (image->converted && image->converted->len)
			g_key_file_set_string_list(key_file, group, "converted",
					(const gchar * const *)image->converted->pdata, image->converted->len);
	}

	if (mf->meta) {
		g_hash_table_iter_init(&iter, mf->meta);
		while (g_hash_table_iter_next(&iter, (gpointer*)&meta_group, (gpointer*)&meta_kvs)) {
			GHashTableIter kvs_iter;
			const gchar *key, *value;

			g_hash_table_iter_init(&kvs_iter, meta_kvs);
			while (g_hash_table_iter_next(&kvs_iter, (gpointer*)&key, (gpointer*)&value)) {
				g_autofree gchar *group = g_strdup_printf("meta.%s", meta_group);
				g_key_file_set_string(key_file, group, key, value);
			}
		}
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

	*mem = g_bytes_new_take(data, length);

	return TRUE;
}

gboolean save_manifest_file(const gchar *filename, const RaucManifest *mf, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GKeyFile) key_file = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(mf, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	key_file = prepare_manifest(mf);

	res = g_key_file_save_to_file(key_file, filename, &ierror);
	if (!res)
		g_propagate_error(error, ierror);

	return res;
}

GVariant* r_manifest_to_dict(const RaucManifest *manifest)
{
	GVariantDict root_dict;
	GVariantDict grp_dict;
	g_auto(GVariantBuilder) builder = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE_ARRAY);
	GHashTableIter iter;
	GHashTable *kvs;
	const gchar *group;

	g_return_val_if_fail(manifest, NULL);

	g_variant_dict_init(&root_dict, NULL);

	if (manifest->hash)
		g_variant_dict_insert(&root_dict, "manifest-hash", "s", manifest->hash);

	/* construct 'update' dict */
	g_variant_dict_init(&grp_dict, NULL);
	if (manifest->update_compatible)
		g_variant_dict_insert(&grp_dict, "compatible", "s", manifest->update_compatible);
	if (manifest->update_version)
		g_variant_dict_insert(&grp_dict, "version", "s", manifest->update_version);
	if (manifest->update_description)
		g_variant_dict_insert(&grp_dict, "description", "s", manifest->update_description);
	if (manifest->update_build)
		g_variant_dict_insert(&grp_dict, "build", "s", manifest->update_build);
	g_variant_dict_insert(&root_dict, "update", "v", g_variant_dict_end(&grp_dict));

	/* construct 'bundle' dict */
	g_variant_dict_init(&grp_dict, NULL);
	g_variant_dict_insert(&grp_dict, "format", "s", r_manifest_bundle_format_to_str(manifest->bundle_format));

	if (manifest->bundle_verity_hash)
		g_variant_dict_insert(&grp_dict, "verity-hash", "s", manifest->bundle_verity_hash);
	if (manifest->bundle_verity_salt)
		g_variant_dict_insert(&grp_dict, "verity-salt", "s", manifest->bundle_verity_salt);
	if (manifest->bundle_verity_size)
		g_variant_dict_insert(&grp_dict, "verity-size", "t", manifest->bundle_verity_size);
	g_variant_dict_insert(&root_dict, "bundle", "v", g_variant_dict_end(&grp_dict));

	/* construct 'hooks' dict */
	if (manifest->hook_name) {
		g_variant_dict_init(&grp_dict, NULL);
		if (manifest->hook_name)
			g_variant_dict_insert(&grp_dict, "filename", "s", manifest->hook_name);
		g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));
		if (manifest->hooks.install_check)
			g_variant_builder_add(&builder, "s", "install-check");
		g_variant_dict_insert(&grp_dict, "hooks", "v", g_variant_builder_end(&builder));
		g_variant_dict_insert(&root_dict, "hooks", "v", g_variant_dict_end(&grp_dict));
	}

	/* construct 'handler' dict */
	if (manifest->handler_name) {
		g_variant_dict_init(&grp_dict, NULL);
		if (manifest->handler_name)
			g_variant_dict_insert(&grp_dict, "filename", "s", manifest->handler_name);
		if (manifest->handler_args)
			g_variant_dict_insert(&grp_dict, "args", "s", manifest->handler_args);
		if (manifest->preinstall_handler)
			g_variant_dict_insert(&grp_dict, "pre-install", "s", manifest->preinstall_handler);
		if (manifest->postinstall_handler)
			g_variant_dict_insert(&grp_dict, "post-install", "s", manifest->postinstall_handler);
		g_variant_dict_insert(&root_dict, "handler", "v", g_variant_dict_end(&grp_dict));
	}

	/* construct 'images' array of dicts */
	g_variant_builder_init(&builder, G_VARIANT_TYPE("aa{sv}"));
	for (GList *l = manifest->images; l != NULL; l = l->next) {
		const RaucImage *img = l->data;
		g_auto(GVariantBuilder) hooks = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE("as"));

		g_variant_builder_open(&builder, G_VARIANT_TYPE("a{sv}"));
		g_variant_builder_add(&builder, "{sv}", "slot-class", g_variant_new_string(img->slotclass));
		if (img->artifact)
			g_variant_builder_add(&builder, "{sv}", "artifact", g_variant_new_string(img->artifact));
		if (img->variant)
			g_variant_builder_add(&builder, "{sv}", "variant", g_variant_new_string(img->variant));
		if (img->filename)
			g_variant_builder_add(&builder, "{sv}", "filename", g_variant_new_string(img->filename));
		if (img->type)
			g_variant_builder_add(&builder, "{sv}", "type", g_variant_new_string(img->type));
		if (img->checksum.digest)
			g_variant_builder_add(&builder, "{sv}", "checksum", g_variant_new_string(img->checksum.digest));
		if (img->checksum.size)
			g_variant_builder_add(&builder, "{sv}", "size", g_variant_new_uint64(img->checksum.size));

		if (img->hooks.pre_install)
			g_variant_builder_add(&hooks, "s", "pre-install");
		if (img->hooks.install)
			g_variant_builder_add(&hooks, "s", "install");
		if (img->hooks.post_install)
			g_variant_builder_add(&hooks, "s", "post-install");
		g_variant_builder_add(&builder, "{sv}", "hooks", g_variant_builder_end(&hooks));

		if (img->adaptive)
			g_variant_builder_add(&builder, "{sv}", "adaptive", g_variant_new_strv((const gchar * const*)(img->adaptive), -1));

		if (img->convert)
			g_variant_builder_add(&builder, "{sv}", "convert", g_variant_new_strv((const gchar * const*)(img->convert), -1));
		if (img->converted)
			g_variant_builder_add(&builder, "{sv}", "converted", g_variant_new_strv((const gchar * const*)(img->converted->pdata), img->converted->len));

		g_variant_builder_close(&builder);
	}
	g_variant_dict_insert(&root_dict, "images", "v", g_variant_builder_end(&builder));

	/* construct 'meta' nested dicts */
	g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sa{ss}}"));
	g_hash_table_iter_init(&iter, manifest->meta);
	while (g_hash_table_iter_next(&iter, (gpointer*)&group, (gpointer*)&kvs)) {
		GHashTableIter kvs_iter;
		const gchar *key, *value;

		g_variant_builder_open(&builder, G_VARIANT_TYPE("{sa{ss}}"));
		g_variant_builder_add(&builder, "s", group);

		g_variant_builder_open(&builder, G_VARIANT_TYPE("a{ss}"));
		g_hash_table_iter_init(&kvs_iter, kvs);
		while (g_hash_table_iter_next(&kvs_iter, (gpointer*)&key, (gpointer*)&value)) {
			g_variant_builder_open(&builder, G_VARIANT_TYPE("{ss}"));
			g_variant_builder_add(&builder, "s", key);
			g_variant_builder_add(&builder, "s", value);
			g_variant_builder_close(&builder);
		}
		g_variant_builder_close(&builder);

		g_variant_builder_close(&builder);
	}
	g_variant_dict_insert(&root_dict, "meta", "v", g_variant_builder_end(&builder));

	return g_variant_dict_end(&root_dict);
}

gboolean r_manifest_has_artifact_image(const RaucManifest *manifest, const gchar *repo, const gchar *artifact)
{
	g_return_val_if_fail(manifest != NULL, FALSE);
	g_return_val_if_fail((!repo && !artifact) ||
			(repo && !artifact) ||
			(repo && artifact), FALSE);

	for (GList *l = manifest->images; l != NULL; l = l->next) {
		const RaucImage *img = l->data;

		/* skip images which are not an artifact */
		if (!img->artifact)
			continue;

		/* skip images for different repos */
		if (repo && g_strcmp0(repo, img->slotclass) != 0)
			continue;

		/* skip images with different artifact names */
		if (artifact && g_strcmp0(artifact, img->artifact) != 0)
			continue;

		return TRUE;
	}

	return FALSE;
}

RaucImage *r_new_image(void)
{
	RaucImage *image = g_new0(RaucImage, 1);

	image->checksum.size = -1;

	return image;
}

void r_free_image(gpointer data)
{
	RaucImage *image = (RaucImage*) data;

	if (!image)
		return;

	g_free(image->slotclass);
	g_free(image->artifact);
	g_free(image->variant);
	g_free(image->checksum.digest);
	g_free(image->filename);
	g_free(image->type);
	g_strfreev(image->adaptive);
	g_strfreev(image->convert);
	g_clear_pointer(&image->converted, g_ptr_array_unref);
	g_free(image);
}

void free_manifest(RaucManifest *manifest)
{
	if (!manifest)
		return;

	g_free(manifest->update_compatible);
	g_free(manifest->update_version);
	g_free(manifest->update_description);
	g_free(manifest->update_build);
	g_free(manifest->update_min_rauc_version);
	g_free(manifest->bundle_verity_hash);
	g_free(manifest->bundle_verity_salt);
	g_free(manifest->bundle_crypt_key);
	g_free(manifest->handler_name);
	g_free(manifest->handler_args);
	g_free(manifest->hook_name);
	g_list_free_full(manifest->images, r_free_image);
	g_clear_pointer(&manifest->meta, g_hash_table_destroy);
	g_free(manifest->hash);
	g_clear_pointer(&manifest->warnings, g_ptr_array_unref);
	g_free(manifest);
}

/**
 * Updates checksums for images listed in the manifest and found in
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

	g_return_val_if_fail(manifest, FALSE);
	g_return_val_if_fail(dir, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	for (GList *elem = manifest->images; elem != NULL; elem = elem->next) {
		RaucImage *image = elem->data;
		g_autofree gchar *filename = NULL;

		/* If no filename is set (valid for 'install' hook) explicitly set size to -1 */
		if (!image->filename) {
			image->checksum.size = -1;
			continue;
		}

		filename = g_build_filename(dir, image->filename, NULL);
		res = compute_checksum(&image->checksum, filename, &ierror);
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
