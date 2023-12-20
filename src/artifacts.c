#include <errno.h>

#include "artifacts.h"

#include "context.h"
#include "glib/gstdio.h"
#include "slot.h"
#include "update_utils.h"
#include "utils.h"

G_DEFINE_QUARK(r-artifacts-error-quark, r_artifacts_error);

G_GNUC_UNUSED
static void show_repo(RArtifactRepo *repo)
{
	GHashTableIter iter;
	const gchar *a_name = NULL;
	GHashTable *inner = NULL;

	g_return_if_fail(repo);

	g_debug("repo %s:", repo->name);
	g_debug("  artifacts:");

	g_hash_table_iter_init(&iter, repo->artifacts);
	while (g_hash_table_iter_next(&iter, (gpointer*)&a_name, (gpointer*)&inner)) {
		GHashTableIter inner_iter;
		const gchar *a_digest = NULL;
		RArtifact *artifact = NULL;

		g_debug("    %s (%p):", a_name, a_name);
		g_assert(a_name == g_intern_string(a_name));

		g_hash_table_iter_init(&inner_iter, inner);
		while (g_hash_table_iter_next(&inner_iter, (gpointer*)&a_digest, (gpointer*)&artifact)) {
			g_debug("      %s (%p):", a_digest, a_digest);

			g_assert(a_name == artifact->name); /* intern strings */
			g_assert(a_digest == g_intern_string(artifact->checksum.digest)); /* intern strings */

			for (guint i = 0; i < artifact->references->len; i++) {
				const gchar *parent = g_ptr_array_index(artifact->references, i);
				g_debug("        referenced by: %s", parent);
				g_assert(parent == g_intern_string(parent));
			}
		}
	}
}

void r_artifact_free(gpointer value)
{
	RArtifact *artifact = (RArtifact*)value;

	if (!artifact)
		return;

	g_free(artifact->bundle_compatible);
	g_free(artifact->bundle_version);
	g_free(artifact->bundle_description);
	g_free(artifact->bundle_build);
	g_free(artifact->bundle_hash);
	g_free(artifact->checksum.digest);
	g_ptr_array_free(artifact->references, TRUE);
	g_free(artifact->path);
	g_free(artifact);
}

void r_artifact_repo_free(gpointer value)
{
	RArtifactRepo *repo = (RArtifactRepo*)value;

	if (!repo)
		return;

	g_free(repo->description);
	g_free(repo->path);
	g_free(repo->type);
	g_free(repo->data_directory);
	g_clear_pointer(&repo->artifacts, (GDestroyNotify)g_hash_table_destroy);
	if (repo->possible_references)
		g_ptr_array_free(repo->possible_references, TRUE);
	g_free(repo);
}

typedef struct {
	const gchar *name;
} RArtifactRepoType;

RArtifactRepoType supported_repo_types[] = {
	{"files"},
	{"trees"},
};

gboolean r_artifact_repo_is_valid_type(const gchar *type)
{
	for (RArtifactRepoType *repo_type = supported_repo_types; repo_type->name != NULL; repo_type++) {
		if (g_strcmp0(type, repo_type->name) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean r_artifact_repo_insert(RArtifactRepo *repo, RArtifact *artifact, GError **error)
{
	GHashTable *inner = NULL;
	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(repo->artifacts);
	g_assert(artifact->repo == NULL);
	g_assert(artifact->path == NULL);
	g_assert(g_quark_try_string(artifact->name));

	artifact->repo = repo;
	artifact->path = g_strdup_printf("%s/.artifact-%s-%s", repo->path, artifact->name, artifact->checksum.digest);

	// FIXME how to get the proper path to store the artifiact before calling this function?
	//g_assert(g_file_test(artifact->path, G_FILE_TEST_EXISTS));
	g_assert(!g_file_test(artifact->path, G_FILE_TEST_IS_SYMLINK));

	inner = g_hash_table_lookup(repo->artifacts, artifact->name);
	if (!inner) {
		inner = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)r_artifact_free);
		g_hash_table_insert(repo->artifacts, (gpointer)artifact->name, inner);
	}

	if (g_hash_table_lookup(inner, g_intern_string(artifact->checksum.digest))) {
		g_set_error(
				error,
				R_ARTIFACTS_ERROR,
				R_ARTIFACTS_ERROR_DUPLICATE,
				"Failed to insert artifact %s into repo %s, as it exists already.",
				artifact->name, repo->name);
		return FALSE;
	}
	g_hash_table_insert(inner, (gpointer)g_intern_string(artifact->checksum.digest), artifact);

	g_message("inserted into %s: %s %s", repo->name, artifact->name, artifact->checksum.digest);

	return TRUE;
}

static gboolean r_artifact_repo_read_links(RArtifactRepo *repo, const gchar *parent, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *path = g_build_filename(repo->path, parent, NULL);
	g_autoptr(GDir) dir = NULL;
	g_autoptr(GRegex) artifact_regex = NULL;
	const gchar *name;

	parent = g_intern_string(parent);

	artifact_regex = g_regex_new(
			strlen(parent) ? "\\.\\./\\.artifact-(.*)-([0-9a-f]+)" : "\\.artifact-(.*)-([0-9a-f]+)",
			G_REGEX_ANCHORED,
			G_REGEX_MATCH_ANCHORED,
			&ierror);
	g_assert_no_error(ierror);

	dir = g_dir_open(path, 0, &ierror);
	if (dir == NULL) {
		/* all parent directories need to exist */
		g_propagate_error(error, ierror);
		return FALSE;
	}

	show_repo(repo);
	while ((name = g_dir_read_name(dir))) {
		g_autofree gchar *entry_path = g_build_filename(path, name, NULL);
		g_autofree gchar *target = NULL;
		g_autoptr(GMatchInfo) match = NULL;
		g_autofree gchar *a_name = NULL;
		g_autofree gchar *a_digest = NULL;
		GHashTable *inner = NULL;
		RArtifact *artifact = NULL;

		if (g_str_has_prefix(name, "."))
			continue;

		target = g_file_read_link(entry_path, &ierror);
		if (target == NULL) {
			g_warning("invalid artifact link %s in repository %s (%s)", entry_path, repo->name, ierror->message);
			g_clear_error(&ierror);
			continue;
		}

		if (!g_regex_match(artifact_regex, target, 0, &match)) {
			g_warning("invalid artifact link %s in repository %s (invalid target %s)", entry_path, repo->name, target);
			continue;
		}

		a_name = g_match_info_fetch(match, 1);
		a_digest = g_match_info_fetch(match, 2);

		inner = g_hash_table_lookup(repo->artifacts, g_intern_string(a_name));
		g_debug("a_name %p", g_intern_string(a_name));
		if (inner == NULL) {
			g_warning("invalid artifact link %s in repository %s (unknown name %s)", entry_path, repo->name, a_name);
			continue;
		}

		artifact = g_hash_table_lookup(inner, g_intern_string(a_digest));
		if (artifact == NULL) {
			g_warning("invalid artifact link %s in repository %s (unknown digest %s)", entry_path, repo->name, a_digest);
			continue;
		}

		g_ptr_array_add(artifact->references, (gpointer)parent);
	}

	return TRUE;
}

gboolean r_artifact_repo_prepare(RArtifactRepo *repo, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GDir) dir = NULL;
	g_autoptr(GRegex) artifact_regex = NULL;
	const gchar *entry_name;

	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (repo->artifacts)
		g_hash_table_destroy(repo->artifacts);
	if (repo->possible_references)
		g_ptr_array_free(repo->possible_references, TRUE);

	artifact_regex = g_regex_new(
			"\\.artifact-(.*)-([0-9a-f]+)",
			G_REGEX_ANCHORED,
			G_REGEX_MATCH_ANCHORED,
			&ierror);
	g_assert_no_error(ierror);

	dir = g_dir_open(repo->path, 0, &ierror);
	if (dir == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	repo->artifacts = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)g_hash_table_destroy);

	/* build RArtifacts from .artifact-<name>-<digest> entries */
	while ((entry_name = g_dir_read_name(dir))) {
		g_autoptr(GMatchInfo) match = NULL;
		g_autoptr(RArtifact) artifact = NULL;
		g_autofree gchar *name = NULL;

		if (!g_regex_match(artifact_regex, entry_name, 0, &match))
			continue;

		artifact = g_new0(RArtifact, 1);
		name = g_match_info_fetch(match, 1);
		artifact->name = g_intern_string(name);
		artifact->checksum.digest = g_match_info_fetch(match, 2);
		artifact->references = g_ptr_array_new();

		/* TODO load status information */

		if (r_artifact_repo_insert(repo, artifact, &ierror)) {
			artifact = NULL;
		} else {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	repo->possible_references = g_ptr_array_new();

	if (repo->parent_class) {
		g_autoptr(GList) parent_slots = r_slot_get_all_of_class(r_context()->config->slots, repo->parent_class);

		for (GList *l = parent_slots; l != NULL; l = l->next) {
			const RaucSlot *parent_slot = l->data;
			g_autofree gchar *symlink_dir = g_build_filename(repo->path, parent_slot->name, NULL);

			/* mode 0755, as access can be controlled at the repo directory level */
			if (g_mkdir_with_parents(symlink_dir, 0755) != 0) {
				int err = errno;
				g_set_error(
						error,
						G_FILE_ERROR,
						g_file_error_from_errno(err),
						"Failed to create artifact directory '%s': %s",
						symlink_dir,
						g_strerror(err));
				return FALSE;
			}

			if (!r_artifact_repo_read_links(repo, parent_slot->name, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}

			g_ptr_array_add(repo->possible_references, (gpointer)g_intern_string(parent_slot->name));
		}
	} else { /* no parent */
		if (!r_artifact_repo_read_links(repo, "", &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		g_ptr_array_add(repo->possible_references, (gpointer)g_intern_static_string(""));
	}

	return TRUE;
}

static gboolean r_artifact_repo_prune_subdir(RArtifactRepo *repo, const gchar *parent, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *path = g_build_filename(repo->path, parent, NULL);
	g_autoptr(GDir) dir = NULL;
	const gchar *name;

	parent = g_intern_string(parent);

	dir = g_dir_open(path, 0, &ierror);
	if (dir == NULL) {
		return TRUE;
	}

	while ((name = g_dir_read_name(dir))) {
		g_autofree gchar *full_name = g_build_filename(path, name, NULL);

		/* symlinks are expected */
		if (g_file_test(full_name, G_FILE_TEST_IS_SYMLINK))
			continue;

		g_message("Removing unexpected data in artifact repo: %s", full_name);
		if (!rm_tree(full_name, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean r_artifact_repo_prune(RArtifactRepo *repo, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GDir) dir = NULL;
	g_autoptr(GRegex) artifact_regex = NULL;
	const gchar *name;

	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	artifact_regex = g_regex_new(
			"\\.artifact-(.*)-([0-9a-f]+)",
			G_REGEX_ANCHORED,
			G_REGEX_MATCH_ANCHORED,
			&ierror);
	g_assert_no_error(ierror);

	if (repo->parent_class) {
		g_autoptr(GList) parent_slots = r_slot_get_all_of_class(r_context()->config->slots, repo->parent_class);

		for (GList *l = parent_slots; l != NULL; l = l->next) {
			const RaucSlot *parent_slot = l->data;

			if (!r_artifact_repo_prune_subdir(repo, parent_slot->name, &ierror)) {
				g_propagate_prefixed_error(
						error,
						ierror,
						"Failed to prune parent subdirectory '%s' in repo '%s':",
						parent_slot->name,
						repo->name
						);
				return FALSE;
			}
		}
	}

	dir = g_dir_open(repo->path, 0, &ierror);
	if (dir == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	while ((name = g_dir_read_name(dir))) {
		g_autofree gchar *full_name = g_build_filename(repo->path, name, NULL);
		g_autoptr(GMatchInfo) match = NULL;

		if (g_regex_match(artifact_regex, name, 0, &match))
			continue;

		if (repo->parent_class) {
			/* only parent subdir should remain */
			if (g_ptr_array_find(repo->possible_references, g_intern_string(name), NULL) &&
			    g_file_test(full_name, G_FILE_TEST_IS_DIR) &&
			    !g_file_test(full_name, G_FILE_TEST_IS_SYMLINK))
				continue;
		} else { /* no parent */
			/* symlinks are expected */
			if (g_file_test(full_name, G_FILE_TEST_IS_SYMLINK))
				continue;
		}

		/* TODO allow repo type specfic files here */

		g_message("Removing unexpected data in artifact repo: %s", full_name);
		if (!rm_tree(full_name, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	/* TODO remove unused artifacts */

	return TRUE;
}

gboolean r_artifact_repo_commit(RArtifactRepo *repo, GError **error)
{
	GError *ierror = NULL;
	GHashTableIter iter;
	GHashTable *inner = NULL;

	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_hash_table_iter_init(&iter, repo->artifacts);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*)&inner)) {
		GHashTableIter inner_iter;
		RArtifact *artifact = NULL;

		g_hash_table_iter_init(&inner_iter, inner);
		while (g_hash_table_iter_next(&inner_iter, NULL, (gpointer*)&artifact)) {
			g_assert(artifact->references != NULL);

			/* update symlink for each parent*/
			for (guint i = 0; i < repo->possible_references->len; i++) {
				const gchar *parent = g_ptr_array_index(repo->possible_references, i);
				gboolean enabled = g_ptr_array_find(artifact->references, parent, NULL);
				gboolean has_parent = g_strcmp0(parent, "") != 0;
				g_autofree gchar *symlink = NULL;
				g_autofree gchar *target = NULL;

				/* build symlink name */
				symlink = g_build_filename(
						repo->path,
						parent, /* can be "" if repo has no parent and is ignored in that case */
						artifact->name,
						NULL
						);

				if (enabled) {
					/* build artifact target name */
					target = g_strdup_printf(
							"%s.artifact-%s-%s",
							has_parent ? "../" : "",
							artifact->name,
							artifact->checksum.digest
							);

					if (!r_update_symlink(target, symlink, &ierror)) {
						g_propagate_error(error, ierror);
						return FALSE;
					}
				} else {
					if (unlink(symlink) == -1) {
						int err = errno;
						if (err == ENOENT)
							continue;
						g_set_error(error,
								G_FILE_ERROR,
								g_file_error_from_errno(err),
								"Failed to remove symlink: %s", g_strerror(err));
						return FALSE;
					}
				}
			}
		}
	}

	if (!r_syncfs(repo->path, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	show_repo(repo);

	return TRUE;
}

gboolean r_artifacts_init(gboolean prune, GError **error)
{
	GError *ierror = NULL;
	GHashTableIter iter;
	RArtifactRepo *repo;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(r_context()->config);
	g_assert(r_context()->config->artifact_repos);

	g_hash_table_iter_init(&iter, r_context()->config->artifact_repos);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*)&repo)) {
		if (!r_artifact_repo_prepare(repo, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		if (prune && !r_artifact_repo_prune(repo, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	return TRUE;
}

GVariant *r_artifacts_to_dict(void)
{
	g_auto(GVariantBuilder) repos_builder = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE("aa{sv}"));
	GHashTableIter repo_iter;
	RArtifactRepo *repo;

	g_message("test");

	g_assert(r_context()->config);
	g_assert(r_context()->config->artifact_repos);

	g_hash_table_iter_init(&repo_iter, r_context()->config->artifact_repos);
	while (g_hash_table_iter_next(&repo_iter, NULL, (gpointer*)&repo)) {
		g_auto(GVariantBuilder) artifacts_builder = G_VARIANT_BUILDER_INIT(G_VARIANT_TYPE("aa{sv}"));
		GHashTableIter a_iter_name;
		GHashTable *inner = NULL;

		g_variant_builder_open(&repos_builder, G_VARIANT_TYPE("a{sv}"));

		g_variant_builder_add(&repos_builder, "{sv}", "name", g_variant_new_string(repo->name));
		if (repo->description)
			g_variant_builder_add(&repos_builder, "{sv}", "description", g_variant_new_string(repo->description));
		if (repo->path)
			g_variant_builder_add(&repos_builder, "{sv}", "path", g_variant_new_string(repo->path));
		if (repo->type)
			g_variant_builder_add(&repos_builder, "{sv}", "type", g_variant_new_string(repo->type));
		if (repo->parent_class)
			g_variant_builder_add(&repos_builder, "{sv}", "parent-class", g_variant_new_string(repo->parent_class));

		g_hash_table_iter_init(&a_iter_name, repo->artifacts);
		while (g_hash_table_iter_next(&a_iter_name, NULL, (gpointer*)&inner)) {
			GHashTableIter a_iter_digest;
			RArtifact *artifact = NULL;

			g_hash_table_iter_init(&a_iter_digest, inner);
			while (g_hash_table_iter_next(&a_iter_digest, NULL, (gpointer*)&artifact)) {
				g_variant_builder_open(&artifacts_builder, G_VARIANT_TYPE("a{sv}"));

				g_variant_builder_add(&artifacts_builder, "{sv}", "name", g_variant_new_string(artifact->name));
				g_variant_builder_add(&artifacts_builder, "{sv}", "checksum", g_variant_new_string(artifact->checksum.digest));
				/* TODO add bundle metadata */
				g_variant_builder_add(&artifacts_builder, "{sv}", "references",
						g_variant_new_strv((const gchar **)artifact->references->pdata, artifact->references->len));

				g_variant_builder_close(&artifacts_builder);
			}
		}
		g_variant_builder_add(&repos_builder, "{sv}", "artifacts", g_variant_builder_end(&artifacts_builder));

		g_variant_builder_close(&repos_builder);
	}

	return g_variant_builder_end(&repos_builder);
}

static gboolean files_artifact_install(const RArtifact *artifact, const RaucImage *image, GError **error)
{
	GError *ierror = NULL;
	int in_fd = -1, out_fd = -1;
	g_autoptr(GUnixInputStream) in_stream = NULL;
	g_autoptr(GUnixOutputStream) out_stream = NULL;

	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* open input image as stream */
	in_stream = r_open_unix_input_stream(image->filename, &in_fd, &ierror);
	if (!in_stream) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* open output artifact as stream */
	out_stream = r_unix_output_stream_create_file(artifact->path, &out_fd, &ierror);
	if (!out_stream) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* call copy with progress */
	if (!r_copy_stream_with_progress(G_INPUT_STREAM(in_stream), G_OUTPUT_STREAM(out_stream), image->checksum.size, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* flush to output before closing to assure content is written to disk */
	if (fsync(out_fd) == -1) {
		int err = errno;
		g_set_error(error, R_ARTIFACTS_ERROR, R_ARTIFACTS_ERROR_INSTALL, "Syncing content to disk failed: %s", strerror(err));
		return FALSE;
	}
	if (!g_output_stream_close(G_OUTPUT_STREAM(out_stream), NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean tree_artifact_install_tar(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);

	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(name, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (g_mkdir(artifact->path, S_IRWXU)) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err),
				"failed to create directory '%s': %s", artifact->path, g_strerror(err));
		return FALSE;
	}

	g_ptr_array_add(args, g_strdup("tar"));
	g_ptr_array_add(args, g_strdup("--numeric-owner"));
	g_ptr_array_add(args, g_strdup("--acl"));
	g_ptr_array_add(args, g_strdup("--selinux"));
	g_ptr_array_add(args, g_strdup("--xattrs"));
	g_ptr_array_add(args, g_strdup("-xf"));
	g_ptr_array_add(args, g_strdup(name));
	g_ptr_array_add(args, g_strdup("-C"));
	g_ptr_array_add(args, g_strdup(artifact->path));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "failed to extract archive (tar -xf): ");
		return FALSE;
	}
	return TRUE;
}

static gboolean tree_artifact_install_extracted(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(GPtrArray) args = g_ptr_array_new_full(10, g_free);

	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(name, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_ptr_array_add(args, g_strdup("cp"));
	g_ptr_array_add(args, g_strdup("-a"));
	g_ptr_array_add(args, g_strdup(name));
	g_ptr_array_add(args, g_strdup(artifact->path));
	g_ptr_array_add(args, NULL);

	if (!r_subprocess_runv(args, G_SUBPROCESS_FLAGS_NONE, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "failed to copy tree (cp -a): ");
		return FALSE;
	}
	return TRUE;
}

/* Try to find the converted output for the given method. */
static gboolean artifact_get_converted(const RaucImage *image, const gchar *method, gchar **name)
{
	/* TODO check that converter/converted have the same length during manifest checking */
	guint len;

	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(method, FALSE);
	g_return_val_if_fail(name != NULL && *name == NULL, FALSE);

	if (!image->convert || image->converted->len == 0)
		return FALSE;

	len = g_strv_length(image->convert);

	if (len != image->converted->len)
		return FALSE;

	/* search for the correct method */
	for (guint i = 0; i < len; i++) {
		/* return the corresponding converted name */
		if (g_strcmp0(image->convert[i], method) == 0) {
			*name = g_strdup(image->converted->pdata[i]);
			return TRUE;
		}
	}

	/* FIXME return full path? */

	return FALSE;
}

gboolean r_artifact_install(const RArtifact *artifact, const RaucImage *image, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(!g_file_test(artifact->path, G_FILE_TEST_EXISTS));
	g_print("image filename %s\n", image->filename);
	g_assert(g_path_is_absolute(image->filename));

	/* TODO support other types besides files */
	if (g_strcmp0(artifact->repo->type, "files") == 0) {
		if (!files_artifact_install(artifact, image, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	} else if (g_strcmp0(artifact->repo->type, "trees") == 0) {
		g_autofree gchar *converted = NULL;
		if (artifact_get_converted(image, "tar-extract", &converted)) {
			if (!tree_artifact_install_extracted(artifact, image, converted, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
		} else {
			/* FIXME add a 'keep' method? */
			/* fall back to either the 'keep' method or the original file */
			if (!artifact_get_converted(image, "keep", &converted) &&
			    g_file_test(image->filename, G_FILE_TEST_EXISTS)) {
				converted = g_strdup(image->filename);
			}

			if (!tree_artifact_install_tar(artifact, image, converted, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
		}
	} else {
		/* should never happen, as this is checked during startup */
		g_error("Unsupported artifacts repo type '%s'", artifact->repo->type);
		return FALSE;
	}

	/* TODO fsync the containing directory, with a helper */

	return TRUE;
}
