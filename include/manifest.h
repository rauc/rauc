#pragma once

#include <glib.h>

#include <config_file.h>

typedef struct {
	gchar* slotclass;
	RaucChecksum checksum;
	gchar* filename;
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
gboolean load_manifest_mem(GBytes *mem, RaucManifest **manifest, GError **error);

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
gboolean load_manifest_file(const gchar *filename, RaucManifest **manifest, GError **error);

/**
 * Creates a manifest file.
 *
 * @param filename Name of manifest file to save
 * @param manifest location to store manifest
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean save_manifest_file(const gchar *filename, RaucManifest *manifest, GError **error);

/**
 * Frees the memory allocated by a RaucManifest.
 */
void free_manifest(RaucManifest *manifest);

/**
 * Updates a manifest file in the given bundle directory.
 *
 * This means updating checksums for files and images listed in the manifestx
 * and placed in the bundle directory
 *
 * @param dir Directory with the bundle content
 * @param signature If true, a signature file is created
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean update_manifest(const gchar *dir, gboolean signature, GError **error);

/**
 * Loads and verifies manifest in directory.
 *
 * The manifest itself must be named 'manifest.raucm'.
 * An optional signature file must be named 'manifest.raucm.sig'
 *
 * @param dir Directory the manifest is located in
 * @param output Returns newly allocated manifest if RaucManifest pointerpointer
 *        is provided.
 *        If output is NULL, manifest will be freed an nothing returned.
 * @param signature If true, manifest ist validated using the provided signature
 *        file.
 *        If false, no further signature validation is performed.
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean verify_manifest(const gchar *dir, RaucManifest **output, gboolean signature, GError **error);
