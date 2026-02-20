#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib/gstdio.h>
#include <libcomposefs/lcfs-writer.h>

#include "artifacts_composefs.h"
#include "utils.h"

static gint strcmp0_p(gconstpointer a, gconstpointer b)
{
	const gchar *str1 = *((gchar **) a);
	const gchar *str2 = *((gchar **) b);

	return g_strcmp0(str1, str2);
}

/*
 * To access the objects in the image in sequential order, we need to sort them
 * by name.
 */
static GPtrArray *get_objects_sorted(GHashTable *objects)
{
	GPtrArray *result = g_ptr_array_sized_new(g_hash_table_size(objects));
	gchar *object_name = NULL;

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, objects);
	while (g_hash_table_iter_next(&iter, (gpointer *)&object_name, NULL)) {
		g_ptr_array_add(result, object_name);
	}

	g_ptr_array_sort(result, strcmp0_p);

	return result;
}

/*
 * Recursively walk the composefs tree and collect the payload names (hashes).
 */
static void composefs_collect_objects(GHashTable *objects, struct lcfs_node_s *node)
{
	g_return_if_fail(objects);
	g_return_if_fail(node);

	for (size_t i = 0; i < lcfs_node_get_n_children(node); i++) {
		struct lcfs_node_s *child = lcfs_node_get_child(node, i);
		g_assert(child != NULL);

		uint32_t type = lcfs_node_get_mode(child) & S_IFMT;
		const gchar *payload = lcfs_node_get_payload(child);
		if (type == S_IFREG && payload)
			g_hash_table_add(objects, g_strdup(payload));

		composefs_collect_objects(objects, child);
	}
}

static gboolean composefs_objects_from_image(GHashTable *objects, const gchar *image_path, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *image_bytes = NULL;
	gsize image_length = 0;

	g_return_val_if_fail(objects, FALSE);
	g_return_val_if_fail(image_path, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* load image into memory */
	if (!g_file_get_contents(image_path, &image_bytes, &image_length, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	struct lcfs_node_s *node = lcfs_load_node_from_image((uint8_t *)image_bytes, image_length);
	composefs_collect_objects(objects, node);
	g_clear_pointer(&node, lcfs_node_unref);

	return TRUE;
}

gboolean r_composefs_artifact_repo_prepare(RArtifactRepo *repo, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(g_strcmp0(repo->type, "composefs") == 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (repo->composefs.local_store_objects)
		g_hash_table_destroy(repo->composefs.local_store_objects);
	repo->composefs.local_store_objects = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	g_autofree gchar *object_store_path = g_build_filename(repo->path, ".rauc-cfs-store", NULL);
	if (g_mkdir_with_parents(object_store_path, 0700) != 0) {
		int err = errno;
		g_set_error(
				error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to create composefs object store '%s': %s",
				object_store_path,
				g_strerror(err));
		return FALSE;
	}

	g_autoptr(GDir) dir = g_dir_open(object_store_path, 0, &ierror);
	if (dir == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Walk nested dirs to find objects like
	 * a8/a6f5cb65e83a3404096a90d97be401503380f64440d5ee3fd4c41b7a776ebd */
	const gchar *entry_name;
	while ((entry_name = g_dir_read_name(dir))) {
		g_autofree gchar *full_inner_path = g_build_filename(object_store_path, entry_name, NULL);
		g_autoptr(GDir) inner_dir = NULL;
		const gchar *inner_entry_name;

		/* we look for directories */
		if (!g_file_test(full_inner_path, G_FILE_TEST_IS_DIR)) {
			g_message("Unexpected data in artifact repo: %s", full_inner_path);
			continue;
		}

		inner_dir = g_dir_open(full_inner_path, 0, &ierror);
		if (inner_dir == NULL) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		while ((inner_entry_name = g_dir_read_name(inner_dir))) {
			/* TODO do we want to check hashes here, separately or during installation? */
			g_autofree gchar *object_name = g_strdup_printf("%s/%s", entry_name, inner_entry_name);
			g_autofree gchar *full_object_path = g_build_filename(object_store_path, object_name, NULL);

			if (!g_file_test(full_object_path, G_FILE_TEST_IS_REGULAR)) {
				g_message("Unexpected data in composefs artifact repo: %s", full_object_path);
				continue;
			}

			g_hash_table_add(repo->composefs.local_store_objects, g_steal_pointer(&object_name));
		}
	}

	g_message("Found %d objects in composefs repo '%s'",
			g_hash_table_size(repo->composefs.local_store_objects),
			repo->name
			);

	return TRUE;
}

gboolean r_composefs_artifact_repo_prune(RArtifactRepo *repo, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(repo, FALSE);
	g_return_val_if_fail(g_strcmp0(repo->type, "composefs") == 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GHashTable) required_objects = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	GHashTableIter iter;
	GHashTable *inner = NULL;
	g_hash_table_iter_init(&iter, repo->artifacts);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&inner)) {
		GHashTableIter inner_iter;
		RArtifact *artifact = NULL;

		g_hash_table_iter_init(&inner_iter, inner);
		while (g_hash_table_iter_next(&inner_iter, NULL, (gpointer *)&artifact)) {
			g_autofree const gchar *image_path = g_build_filename(artifact->path, "image.cfs", NULL);
			if (!composefs_objects_from_image(required_objects, image_path, &ierror)) {
				g_propagate_error(error, ierror);
				return FALSE;
			}
		}
	}

	/* remove missing objects */
	guint missing = 0;
	const gchar *object_name = NULL;
	g_hash_table_iter_init(&iter, required_objects);
	while (g_hash_table_iter_next(&iter, (gpointer *)&object_name, NULL)) {
		if (g_hash_table_contains(repo->composefs.local_store_objects, object_name))
			continue;

		g_debug("Failed to find required object '%s' in local composefs object store of repo '%s'",
				object_name, repo->name);
		g_hash_table_iter_remove(&iter);
		missing++;
	}
	if (missing)
		g_warning("Failed to find %d required objects in local composefs object store of repo '%s'",
				missing, repo->name);

	/* remove unused objects */
	guint removed = 0;
	g_autofree gchar *object_store_path = g_build_filename(repo->path, ".rauc-cfs-store", NULL);
	g_hash_table_iter_init(&iter, repo->composefs.local_store_objects);
	while (g_hash_table_iter_next(&iter, (gpointer *)&object_name, NULL)) {
		if (g_hash_table_contains(required_objects, object_name))
			continue;

		g_autofree gchar *object_path = g_build_filename(object_store_path, object_name, NULL);
		if (unlink(object_path) == -1) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to remove unused composefs object '%s': %s",
					object_name, g_strerror(err));
			return FALSE;
		}

		g_hash_table_iter_remove(&iter);
		removed++;
	}
	g_info("Removed %d unused objects in local composefs object store of repo '%s'",
			removed, repo->name);

	/* remove empty directories */
	g_autoptr(GDir) dir = g_dir_open(object_store_path, 0, &ierror);
	if (dir == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	const gchar *entry_name;
	while ((entry_name = g_dir_read_name(dir))) {
		g_autofree gchar *full_inner_path = g_build_filename(object_store_path, entry_name, NULL);

		if (!g_file_test(full_inner_path, G_FILE_TEST_IS_DIR))
			continue;

		if (rmdir(full_inner_path) == -1) {
			int err = errno;
			if (err == ENOTEMPTY || err == EEXIST)
				continue;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to remove empty composefs object directory: %s", g_strerror(err));
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean remove_existing(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *reference = user_data;

	return g_hash_table_contains(reference, key);
}

gboolean r_composefs_artifact_install(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(artifact, FALSE);
	g_return_val_if_fail(artifact->repo, FALSE);
	g_return_val_if_fail(g_strcmp0(artifact->repo->type, "composefs") == 0, FALSE);
	g_return_val_if_fail(image, FALSE);
	g_return_val_if_fail(name, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* copy image */
	if (!r_tree_artifact_install_extracted(artifact, image, name, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* get required objects from image */
	g_autofree const gchar *image_path = g_build_filename(artifact->path_tmp, "image.cfs", NULL);
	g_autoptr(GHashTable) image_objects = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	if (!composefs_objects_from_image(image_objects, image_path, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* compute missing objects */
	/* TODO perhaps use g_hash_table_iter_remove? */
	const guint removed = g_hash_table_foreach_remove(image_objects, remove_existing,
			artifact->repo->composefs.local_store_objects);
	if (removed)
		g_message("Skipping copy of %d existing composefs objects for image %s\n", removed, image->filename);

	g_message("Need to get %d new composefs objects from bundle", g_hash_table_size(image_objects));

	/* copy missing objects */
	g_autofree const gchar *local_object_store_path = g_build_filename(artifact->repo->path, ".rauc-cfs-store", NULL);
	g_autofree const gchar *bundle_path = g_path_get_dirname(name);
	g_autofree const gchar *bundle_object_store_path = g_build_filename(bundle_path, ".rauc-cfs-store", NULL);
	g_autoptr(GPtrArray) image_objects_sorted = get_objects_sorted(image_objects);
	for (guint i = 0; i < image_objects_sorted->len; i++) {
		const gchar *object_name = image_objects_sorted->pdata[i];
		g_autofree const gchar *object_subdir = g_path_get_dirname(object_name);
		g_autofree const gchar *local_object_store_subdir_path = g_build_filename(local_object_store_path, object_subdir, NULL);
		if (g_mkdir_with_parents(local_object_store_subdir_path, 0700) != 0) {
			int err = errno;
			g_set_error(
					error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to create composefs object store subdir '%s': %s",
					local_object_store_subdir_path,
					g_strerror(err));
			return FALSE;
		}
		if (!copy_file(bundle_object_store_path, object_name, local_object_store_path, object_name, &ierror)) {
			g_propagate_prefixed_error(error, ierror, "Failed to copy composefs object from bundle to local store: ");
			return FALSE;
		}
		g_hash_table_add(artifact->repo->composefs.local_store_objects, g_strdup(object_name));
	}

	return TRUE;
}
