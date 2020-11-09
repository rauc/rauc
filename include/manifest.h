#pragma once

#include <glib.h>

#include "checksum.h"

#define R_MANIFEST_ERROR r_manifest_error_quark()
GQuark r_manifest_error_quark(void);

#define R_MANIFEST_ERROR_NO_DATA	0
#define R_MANIFEST_ERROR_CHECKSUM	1
#define R_MANIFEST_ERROR_COMPATIBLE	2
#define R_MANIFEST_PARSE_ERROR		3
#define R_MANIFEST_EMPTY_STRING		4

typedef struct {
	gboolean install_check;
} InstallHooks;

typedef struct {
	gboolean pre_install;
	gboolean install;
	gboolean post_install;
} SlotHooks;

typedef struct {
	gchar* slotclass;
	gchar* variant;
	RaucChecksum checksum;
	gchar* filename;
	SlotHooks hooks;
} RaucImage;

typedef struct {
	gchar* slotclass;
	RaucChecksum checksum;
	gchar* filename;
	gchar* destname;
} RaucFile;

typedef struct {
	gchar *update_compatible;
	gchar *update_version;
	gchar *update_description;
	gchar *update_build;

	gchar *keyring;

	gchar *handler_name;
	gchar *handler_args;

	gchar *hook_name;
	InstallHooks hooks;

	GList *images;
	GList *files;
} RaucManifest;

/**
 * Loads a manifest from memory.
 *
 * Use free_manifest() to free the returned manifest.
 *
 * @param mem Input data
 * @param manifest location to store manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean load_manifest_mem(GBytes *mem, RaucManifest **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Loads a manifest file.
 *
 * Use free_manifest() to free the returned manifest.
 *
 * @param filename Name of manifest file to load
 * @param manifest Location to store manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean load_manifest_file(const gchar *filename, RaucManifest **manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a manifest file.
 *
 * @param filename Name of manifest file to save
 * @param manifest location to store manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean save_manifest_file(const gchar *filename, RaucManifest *manifest, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Frees the memory allocated by a RaucManifest.
 */
void free_manifest(RaucManifest *manifest);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucManifest, free_manifest);

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
gboolean update_manifest_checksums(RaucManifest *manifest, const gchar *dir, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Frees a rauc image
 */
void r_free_image(gpointer data);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucImage, r_free_image);

/**
 * Frees a rauc file
 */
void r_free_file(gpointer data);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucFile, r_free_file);
