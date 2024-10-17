#pragma once

#include <glib.h>

#include "checksum.h"
#include "manifest.h"

#define R_ARTIFACTS_ERROR r_artifacts_error_quark()
GQuark r_artifacts_error_quark(void);

#define R_ARTIFACTS_ERROR_DUPLICATE 0
#define R_ARTIFACTS_ERROR_INSTALL 1

typedef struct _RArtifactRepo RArtifactRepo;

typedef struct _RArtifact {
	/** name of the artifact. A glib intern string. */
	const gchar *name;

	/** details of the source bundle */
	gchar *bundle_compatible;
	gchar *bundle_version;
	gchar *bundle_description;
	gchar *bundle_build;
	gchar *bundle_hash;

	/** original contents of the artifact */
	RaucChecksum checksum;

	/** referenced by parents (intern strings), "" for activated without parent */
	GPtrArray *references;

	/** internally managed pointer to containing repo */
	RArtifactRepo *repo;

	/** internally managed path to the artifact */
	gchar *path;
	/** internally managed temporary path during installation */
	gchar *path_tmp;
} RArtifact;

typedef struct _RArtifactRepo {
	/** name of the repo. (intern string) */
	const gchar *name;
	/** user-friendly description */
	gchar *description;
	/** path this repo uses */
	gchar *path;
	/** type of the repo */
	gchar *type;
	/** associated parent class for redundant repos, may be NULL (intern string) */
	const gchar *parent_class;

	/** the name of the per-repo data subdirectory */
	gchar *data_directory;

	/** nested hash table for artifacts, using interned strings as keys **/
	GHashTable *artifacts;

	/** possible parents (intern strings), "" without parent */
	GPtrArray *possible_references;

	/** runtime information for different repo types */
	union {
		struct {
			GHashTable *local_store_objects;
		} composefs;
	};
} RArtifactRepo;

/**
 * Frees the memory allocated by a RArtifactRepo
 */
void r_artifact_free(gpointer value);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RArtifact, r_artifact_free);

/**
 * Frees the memory allocated by a RArtifactRepo
 */
void r_artifact_repo_free(gpointer value);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RArtifactRepo, r_artifact_repo_free);

/**
 * Check if artifact repo type name is valid.
 *
 * @param type Name of type as string
 *
 * @return TRUE if it is a valid (known) slot type, otherwise FALSE
 */
gboolean r_artifact_repo_is_valid_type(const gchar *type)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Insert an existing RArtifact structure into the repository.
 *
 * The path property of the new to be inserted artifact must be NULL, as this is
 * filled out by this function. During r_artifact_repo_prepare, it is used with
 * artifacts on disk. During installation, the actual copying only happens after
 * inserting it into the repository.
 *
 * @param repo RArtifactRepo to insert into
 * @param artifact RArtifact to insert
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the insertion was successful, otherwise FALSE
 */
gboolean r_artifact_repo_insert(RArtifactRepo *repo, RArtifact *artifact, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Scan the repo on disk for installed artifacts and load their information.
 *
 * @param repo RArtifactRepo to prepare
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the perparation was successful, otherwise FALSE
 */
gboolean r_artifact_repo_prepare(RArtifactRepo *repo, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Remove unreferenced artifacts and inconsistent data such as partial
 * downloads.
 *
 * @param repo RArtifactRepo to prune
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the pruning was successful, otherwise FALSE
 */
gboolean r_artifact_repo_prune(RArtifactRepo *repo, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Update the persistent state from the current configuration in memory.
 *
 * This will create and remove links to artifacts as needed.
 *
 * @param repo RArtifactRepo to commit
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the commit was successful, otherwise FALSE
 */
gboolean r_artifact_repo_commit(RArtifactRepo *repo, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Initialize artifact functionality by calling r_artifact_repo_prepare for all
 * configured repositories.
 *
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the initialization was successful, otherwise FALSE
 */
gboolean r_artifacts_init(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Call r_artifact_repo_prune for all configured repositories.
 *
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the pruning was successful, otherwise FALSE
 */
gboolean r_artifacts_prune(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Converts information on all artifact repos to a GVariant dict.
 *
 * This can be used by the D-Bus service and also for the 'rauc status' CLI
 * command (by converting it to JSON).
 *
 * @return new GVariant containing the dict
 */
GVariant *r_artifacts_to_dict(void)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Install a tree artifact from the bundle into the repo.
 *
 * @param artifact RArtifact to install to
 * @param image RaucImage to install from
 * @param name the converted directory name in the bundle
 * @param error a GError, or NULL
 *
 * @return TRUE if the installation was successful, otherwise FALSE
 */
gboolean r_tree_artifact_install_extracted(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Try to find an existing artifact given a name and checksum.
 *
 * @param repo RArtifactRepo to search
 * @param name the name to search for
 * @param digest the hash to search for
 *
 * @return the artifact if found, otherwise NULL
 */
RArtifact *r_artifact_find(const RArtifactRepo *repo, const gchar *name, const gchar *digest)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Install from an image to the intended artifact location.
 *
 * The actual mechanism for the installation depends on the repo type.
 *
 * @param artifact RArtifact to install to
 * @param image RaucImage to install from
 * @param[out] error Return location for a GError, or NULL
 *
 * @return TRUE if the installation was successful, otherwise FALSE
 */
gboolean r_artifact_install(const RArtifact *artifact, const RaucImage *image, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Activate an artifact for the given parent.
 *
 * Other versions of this artifact are deactivated. This change must be
 * separately persisted by r_artifact_repo_commit().
 *
 * @param artifact RArtifact to activate
 * @param parent "" or name of the parent slot
 * @param[out] error Return location for a GError, or NULL
 */
void r_artifact_activate(const RArtifact *artifact, const gchar *parent);

/**
 * Deactivate an artifact for the given parent.
 *
 * This change must be separately persisted by r_artifact_repo_commit().
 *
 * @param artifact RArtifact to deactivate
 * @param parent NULL or name of the parent slot
 * @param[out] error Return location for a GError, or NULL
 */
void r_artifact_deactivate(const RArtifact *artifact, const gchar *parent);
