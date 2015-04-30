#include "manifest.h"

#include <checksum.h>
#include <config_file.h>
#include <context.h>
#include <signature.h>
#include <utils.h>

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

	return res;
}

gboolean update_manifest(const gchar *dir, gboolean signature) {
	gchar* manifestpath = g_build_filename(dir, "manifest.raucm", NULL);
	gchar* signaturepath = g_build_filename(dir, "manifest.raucm.sig", NULL);
	RaucManifest *manifest = NULL;
	GBytes *sig = NULL;
	gboolean res = FALSE;

        g_assert_nonnull(r_context()->certpath);
        g_assert_nonnull(r_context()->keypath);

	res = load_manifest(manifestpath, &manifest);
	if (!res)
		goto out;

	res = update_manifest_checksums(manifest, dir);
	if (!res)
		goto out;

	res = save_manifest(manifestpath, manifest);
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

gboolean verify_manifest(const gchar *dir, gboolean signature) {
	gchar* manifestpath = g_build_filename(dir, "manifest.raucm", NULL);
	gchar* signaturepath = g_build_filename(dir, "manifest.raucm.sig", NULL);
	RaucManifest *manifest = NULL;
	GBytes *sig = NULL;
	gboolean res = FALSE;

        g_assert_nonnull(r_context()->certpath);
        g_assert_nonnull(r_context()->keypath);

	if (signature) {
		sig = read_file(signaturepath);
		if (sig == NULL)
			goto out;

		res = cms_verify_file(manifestpath, sig, 0);
		if (!res)
			goto out;

	}

	res = load_manifest(manifestpath, &manifest);
	if (!res)
		goto out;

	res = verify_manifest_checksums(manifest, dir);
	if (!res)
		goto out;

out:
	g_clear_pointer(&sig, g_bytes_unref);
	g_clear_pointer(&manifest, free_manifest);
	g_free(signaturepath);
	g_free(manifestpath);
	return res;
}
