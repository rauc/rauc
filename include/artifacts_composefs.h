#pragma once

#include <glib.h>

#include "artifacts.h"

#if ENABLE_COMPOSEFS
/**
 * Scan the compose repo on disk for installed artifacts and load their information.
 *
 * This also scans the object store.
 *
 * @param repo RArtifactRepo to prepare
 * @param error a GError, or NULL
 *
 * @return TRUE if the perparation was successful, otherwise FALSE
 *
 */
gboolean r_artifact_repo_prepare_composefs(RArtifactRepo *repo, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Remove unreferenced artifacts and inconsistent data such as partial
 * downloads.
 *
 * This also removes unused objects from the object store.
 *
 * @param repo RArtifactRepo to prune
 * @param error a GError, or NULL
 *
 * @return TRUE if the pruning was successful, otherwise FALSE
 */
gboolean r_artifact_repo_prune_composefs(RArtifactRepo *repo, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Install a composefs artifact from the bundle into the repo.
 *
 * This also copies missing objects from the bundle into the local object store.
 *
 * @param artifact RArtifact to install to
 * @param image RaucImage to install from
 * @param name the converted directory name in the bundle
 * @param error a GError, or NULL
 *
 * @return TRUE if the installation was successful, otherwise FALSE
 */
gboolean r_composefs_artifact_install(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
#else
static inline gboolean r_artifact_repo_prepare_composefs(RArtifactRepo *repo, GError **error)
{
	g_error("composefs support not enabled at compile time");
	return FALSE;
}

static inline gboolean r_artifact_repo_prune_composefs(RArtifactRepo *repo, GError **error)
{
	g_error("composefs support not enabled at compile time");
	return FALSE;
}

static inline gboolean r_composefs_artifact_install(const RArtifact *artifact, const RaucImage *image, const gchar *name, GError **error)
{
	g_error("composefs support not enabled at compile time");
	return FALSE;
}
#endif
