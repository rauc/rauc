#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <config_file.h>
#include <context.h>
#include <manifest.h>

#include "common.h"
#include "utils.h"

typedef struct {
	gchar *tmpdir;
	gchar *contentdir;
} ManifestFixture;

static void manifest_check_common(RaucManifest *rm)
{
	g_assert_nonnull(rm);
	g_assert_cmpstr(rm->update_compatible, ==, "FooCorp Super BarBazzer");
	g_assert_cmpstr(rm->update_version, ==, "2015.04-1");
	g_assert_cmpstr(rm->handler_name, ==, "custom_handler.sh");
	g_assert_cmpstr(rm->handler_args, ==, NULL);
	g_assert_cmpstr(rm->hook_name, ==, "hook.sh");
	g_assert_nonnull(rm->images);

	g_assert_cmpuint(g_list_length(rm->images), ==, 2);

	for (GList *l = rm->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		g_assert_nonnull(img);
		g_assert_nonnull(img->slotclass);
		g_assert_nonnull(img->checksum.digest);
		g_assert_nonnull(img->filename);
	}

	g_assert_false(r_manifest_has_artifact_image(rm, NULL, NULL));
	g_assert_false(r_manifest_has_artifact_image(rm, "repo", NULL));
	g_assert_false(r_manifest_has_artifact_image(rm, "repo", "artifact"));
}

/* Test manifest/load:
 *
 * Tests loading manifest from file: *
 * Test cases:
 * - load a valid manifest file
 * - load a non-exisiting manifest file
 * - load a broken manifest file
 */
static void test_load_manifest(void)
{
	g_autoptr(RaucManifest) rm = NULL;
	GError *error = NULL;
	gboolean res;

	// Load valid manifest file
	res = load_manifest_file("test/manifest.raucm", &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	manifest_check_common(rm);
	g_assert_false(rm->bundle_format_explicit);
	g_assert_cmpuint(rm->warnings->len, ==, 4);

	g_clear_pointer(&rm, free_manifest);
	g_assert_null(rm);

	// Load non-existing manifest file
	res = load_manifest_file("test/nonexisting.raucm", &rm, &error);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_assert_false(res);

	g_clear_pointer(&rm, free_manifest);
	g_clear_error(&error);
	g_assert_null(rm);

	// Load broken manifest file
	res = load_manifest_file("test/broken-manifest.raucm", &rm, &error);
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
	g_assert_false(res);

	g_clear_error(&error);
	g_assert_null(rm);
}

static void check_manifest_contents(const RaucManifest *rm)
{
	GHashTable *kvs = NULL;
	RaucImage *image = NULL;

	g_assert_nonnull(rm);
	g_assert_cmpstr(rm->update_compatible, ==, "BarCorp FooBazzer");
	g_assert_cmpstr(rm->update_version, ==, "2011.03-1");
	g_assert_cmpstr(rm->handler_name, ==, "myhandler.sh");
	g_assert_cmpstr(rm->handler_args, ==, "--foo");
	g_assert_cmpstr(rm->hook_name, ==, "hook.sh");

	g_assert_cmpuint(g_list_length(rm->images), ==, 3);

	image = g_list_nth_data(rm->images, 0);
	g_assert_nonnull(image);
	g_assert_cmpstr(image->slotclass, ==, "rootfs");
	g_assert_cmpstr(image->checksum.digest, ==, "c8af04e62bad4ab75dafd22119026e5e3943f385bdcbe7731a4938102453754c");
	g_assert_cmpstr(image->filename, ==, "myrootimg.ext4");
	g_assert_true(image->hooks.pre_install);
	g_assert_true(image->hooks.post_install);

	image = g_list_nth_data(rm->images, 1);
	g_assert_nonnull(image);
	g_assert_cmpstr(image->slotclass, ==, "rootfs");
	g_assert_cmpstr(image->variant, ==, "variant-1");
	g_assert_cmpstr(image->checksum.digest, ==, "768c36e72bedd35dac67c39b6145f97ef174179f5903a31c4c03abc0eb5d954c");
	g_assert_cmpstr(image->filename, ==, "myrootimg_variant1.ext4");
	g_assert_cmpint(g_strv_length(image->adaptive), ==, 2);
	g_assert_cmpstr(image->adaptive[0], ==, "invalid-method");
	g_assert_cmpstr(image->adaptive[1], ==, "another-invalid-method");

	image = g_list_nth_data(rm->images, 2);
	g_assert_nonnull(image);
	g_assert_cmpstr(image->slotclass, ==, "appfs");
	g_assert_cmpstr(image->artifact, ==, "app-a");
	g_assert_cmpstr(image->checksum.digest, ==, "4e7e45db749b073eda450d30c978c7e2f6035b057d3e33ac4c61d69ce5155313");
	g_assert_cmpstr(image->filename, ==, "myappimg.ext4");
	g_assert_cmpint(g_strv_length(image->convert), ==, 2);
	g_assert_cmpstr(image->convert[0], ==, "invalid-convert");
	g_assert_cmpstr(image->convert[1], ==, "another-invalid-convert");
	g_assert_nonnull(image->converted);
	g_assert_cmpint(image->converted->len, ==, 2);
	g_assert_cmpstr(image->converted->pdata[0], ==, "invalid-converted");
	g_assert_cmpstr(image->converted->pdata[1], ==, "another-invalid-converted");

	g_assert_true(r_manifest_has_artifact_image(rm, NULL, NULL));
	g_assert_false(r_manifest_has_artifact_image(rm, "repo", NULL));
	g_assert_false(r_manifest_has_artifact_image(rm, "repo", "app-a"));
	g_assert_true(r_manifest_has_artifact_image(rm, "appfs", NULL));
	g_assert_false(r_manifest_has_artifact_image(rm, "appfs", "artifact"));
	g_assert_true(r_manifest_has_artifact_image(rm, "appfs", "app-a"));

	g_assert_true(rm->hooks.install_check);
	g_assert_true(rm->hooks.pre_install);
	g_assert_true(rm->hooks.post_install);

	g_assert_cmpuint(g_hash_table_size(rm->meta), ==, 2);

	kvs = g_hash_table_lookup(rm->meta, "foocorp");
	g_assert_nonnull(kvs);
	g_assert_cmpstr((g_hash_table_lookup(kvs, "release-type")), ==, "beta");
	g_assert_cmpstr((g_hash_table_lookup(kvs, "release-notes")), ==, "https://foocorp.example/releases/release-notes-2015.04-1.rst");

	kvs = g_hash_table_lookup(rm->meta, "example");
	g_assert_nonnull(kvs);
	g_assert_cmpstr((g_hash_table_lookup(kvs, "counter")), ==, "42");
}

/* Test manifest/save_load:
 *
 * Tests saving manifest structure to file and load again.
 *
 * Test cases:
 * - save a valid manifest to file and load
 */
static void test_save_load_manifest(void)
{
	GError *error = NULL;
	gboolean res = FALSE;
	g_autoptr(RaucManifest) rm = g_new0(RaucManifest, 1);
	RaucImage *new_image;
	GHashTable *kvs = NULL;

	rm->update_compatible = g_strdup("BarCorp FooBazzer");
	rm->update_version = g_strdup("2011.03-1");
	rm->bundle_format_explicit = TRUE;
	rm->handler_name = g_strdup("myhandler.sh");
	rm->handler_args = g_strdup("--foo");
	rm->hook_name = g_strdup("hook.sh");
	rm->hooks.install_check = TRUE;
	rm->hooks.pre_install = TRUE;
	rm->hooks.post_install = TRUE;

	new_image = r_new_image();
	new_image->slotclass = g_strdup("rootfs");
	new_image->checksum.type = G_CHECKSUM_SHA256;
	new_image->checksum.digest = g_strdup("c8af04e62bad4ab75dafd22119026e5e3943f385bdcbe7731a4938102453754c");
	new_image->filename = g_strdup("myrootimg.ext4");
	new_image->type = g_strdup("ext4");
	new_image->hooks.pre_install = TRUE;
	new_image->hooks.post_install = TRUE;
	rm->images = g_list_append(rm->images, new_image);

	new_image = r_new_image();
	new_image->slotclass = g_strdup("rootfs");
	new_image->variant = g_strdup("variant-1");
	new_image->checksum.type = G_CHECKSUM_SHA256;
	new_image->checksum.digest = g_strdup("768c36e72bedd35dac67c39b6145f97ef174179f5903a31c4c03abc0eb5d954c");
	new_image->filename = g_strdup("myrootimg_variant1.ext4");
	new_image->type = g_strdup("ext4");
	new_image->hooks.pre_install = TRUE;
	new_image->hooks.post_install = TRUE;
	new_image->adaptive = g_strsplit("invalid-method;another-invalid-method", ";", 0);
	rm->images = g_list_append(rm->images, new_image);

	new_image = r_new_image();
	new_image->slotclass = g_strdup("appfs");
	new_image->artifact = g_strdup("app-a");
	new_image->checksum.type = G_CHECKSUM_SHA256;
	new_image->checksum.digest = g_strdup("4e7e45db749b073eda450d30c978c7e2f6035b057d3e33ac4c61d69ce5155313");
	new_image->filename = g_strdup("myappimg.ext4");
	new_image->convert = g_strsplit("invalid-convert;another-invalid-convert", ";", 0);
	new_image->converted = test_ptr_array_from_strsplit("invalid-converted;another-invalid-converted");
	rm->images = g_list_append(rm->images, new_image);

	g_assert_cmpuint(g_list_length(rm->images), ==, 3);

	rm->meta = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);

	kvs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert(kvs, g_strdup("release-type"), g_strdup("beta"));
	g_hash_table_insert(kvs, g_strdup("release-notes"), g_strdup("https://foocorp.example/releases/release-notes-2015.04-1.rst"));
	g_hash_table_insert(rm->meta, g_strdup("foocorp"), kvs);

	kvs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert(kvs, g_strdup("counter"), g_strdup("42"));
	g_hash_table_insert(rm->meta, g_strdup("example"), kvs);

	g_assert_cmpuint(g_hash_table_size(rm->meta), ==, 2);

	res = save_manifest_file("test/savedmanifest.raucm", rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_pointer(&rm, free_manifest);

	res = load_manifest_file("test/savedmanifest.raucm", &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_cmpuint(rm->bundle_format, ==, R_MANIFEST_FORMAT_PLAIN);
	g_assert_true(rm->bundle_format_explicit);
	check_manifest_contents(rm);

	g_autoptr(GBytes) mem = NULL;
	res = save_manifest_mem(&mem, rm);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_pointer(&rm, free_manifest);

	/* with bundle_format_explicit set, we need to find the format=plain */
	g_assert_nonnull(g_strstr_len(g_bytes_get_data(mem, NULL), -1, "[bundle]\nformat=plain\n"));

	g_message("manifest in memory:\n%s", (gchar*)g_bytes_get_data(mem, NULL));
	res = load_manifest_mem(mem, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_cmpuint(rm->bundle_format, ==, R_MANIFEST_FORMAT_PLAIN);
	g_assert_true(rm->bundle_format_explicit);
	check_manifest_contents(rm);
}

/* Test manifest/save/writefail:
 *
 * Tests error handling for saving a manifest file
 *
 * Test cases:
 * - try to save a manifest file to a non-existing directory
 */
static void test_save_manifest_writefail(void)
{
	g_autoptr(GError) error = NULL;
	gboolean res;
	g_autoptr(RaucManifest) rm = g_new0(RaucManifest, 1);

	res = save_manifest_file("test/nonexistingdir/savedmanifest.raucm", rm, &error);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_assert_false(res);
}

/* Test manifest/load_mem:
 *
 * Tests loading manifest from memory.
 *
 * Test cases:
 * - load a valid manifest from memory
 */
static void test_load_manifest_mem(void)
{
	g_autoptr(GBytes) data = NULL;
	g_autoptr(RaucManifest) rm = NULL;

	data = read_file("test/manifest.raucm", NULL);
	g_assert_true(load_manifest_mem(data, &rm, NULL));
	manifest_check_common(rm);
}

static void test_manifest_load_variants(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	RaucImage *test_img = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[handler]\n\
filename=custom_handler.sh\n\
\n\
[hooks]\n\
filename=hook.sh\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
\n\
[image.rootfs.variant,1]\n\
filename=rootfs-var1.ext4\n\
\n\
[image.rootfs.variant,2]\n\
filename=rootfs-var2.ext4\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);

	for (GList *l = rm->images; l != NULL; l = l->next) {
		RaucImage *img = l->data;
		/* All variants must be detected as the same slot class */
		g_assert_cmpstr(img->slotclass, ==, "rootfs");
	}

	test_img = (RaucImage*)g_list_nth_data(rm->images, 0);
	g_assert_nonnull(test_img);
	g_assert_null(test_img->variant);

	test_img = (RaucImage*)g_list_nth_data(rm->images, 1);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->variant, ==, "variant,1");

	test_img = (RaucImage*)g_list_nth_data(rm->images, 2);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->variant, ==, "variant,2");
}

static void test_manifest_load_types(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	RaucImage *test_img = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
type=ext4\n\
filename=rootfs-default.something\n\
\n\
[image.appfs]\n\
type=vfat\n\
filename=appfs.vfat\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);

	test_img = (RaucImage*)g_list_nth_data(rm->images, 0);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->type, ==, "ext4");

	test_img = (RaucImage*)g_list_nth_data(rm->images, 1);
	g_assert_nonnull(test_img);
	g_assert_cmpstr(test_img->type, ==, "vfat");
}

static void test_manifest_load_types_invalid(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
type=invalid\n\
filename=rootfs-default.ext4\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_error(error, R_MANIFEST_ERROR, R_MANIFEST_ERROR_INVALID_IMAGE_TYPE);
	g_assert_false(res);

	g_clear_error(&error);
}

static void test_manifest_load_types_fileext_not_mapped(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.invalid\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);

	g_clear_error(&error);
}

static void test_manifest_load_missing_type_and_filename(void)
{
	g_autofree gchar *tmpdir;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar* manifestpath = NULL;
	gboolean res;
	g_autoptr(GError) error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2025.10-1\n\
\n\
[image.rootfs]\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_INVALID_VALUE);
	g_assert_false(res);
}

static void test_manifest_load_types_emptyfs_with_imagename_invalid(void)
{
	gchar *tmpdir;
	g_autoptr(RaucManifest) rm = NULL;
	gchar* manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
type=ext4\n\
filename=rootfs-default.something\n\
\n\
[image.appfs]\n\
type=emptyfs\n\
filename=appfs.vfat\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	g_free(tmpdir);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_error(error, R_MANIFEST_ERROR, R_MANIFEST_PARSE_ERROR);
	g_assert_false(res);

	g_clear_error(&error);
	g_free(manifestpath);
}

static void test_manifest_load_types_emptyfs_valid(void)
{
	gchar *tmpdir;
	g_autoptr(RaucManifest) rm = NULL;
	gchar* manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
type=ext4\n\
filename=rootfs-default.something\n\
\n\
[image.appfs]\n\
type=emptyfs\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	g_free(tmpdir);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);
	g_free(manifestpath);
}

static void test_manifest_load_adaptive(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	RaucImage *test_img = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
adaptive=invalid-method;another-invalid-method\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);

	test_img = (RaucImage*)g_list_nth_data(rm->images, 0);
	g_assert_nonnull(test_img);
	g_assert_nonnull(test_img->adaptive);
	g_assert_cmpint(g_strv_length(test_img->adaptive), ==, 2);
	g_assert_cmpstr(test_img->adaptive[0], ==, "invalid-method");
	g_assert_cmpstr(test_img->adaptive[1], ==, "another-invalid-method");
}

static void test_manifest_load_meta(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	RaucImage *test_img = NULL;
	GHashTable *kvs = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
\n\
[meta.foocorp]\n\
release-type=beta\n\
release-notes=https://foocorp.example/releases/release-notes-2015.04-1.rst\n\
\n\
[meta.example]\n\
counter=42\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);

	test_img = (RaucImage*)g_list_nth_data(rm->images, 0);
	g_assert_nonnull(test_img);

	g_assert_cmpuint(g_hash_table_size(rm->meta), ==, 2);

	kvs = g_hash_table_lookup(rm->meta, "foocorp");
	g_assert_nonnull(kvs);
	g_assert_cmpstr((g_hash_table_lookup(kvs, "release-type")), ==, "beta");
	g_assert_cmpstr((g_hash_table_lookup(kvs, "release-notes")), ==, "https://foocorp.example/releases/release-notes-2015.04-1.rst");

	kvs = g_hash_table_lookup(rm->meta, "example");
	g_assert_nonnull(kvs);
	g_assert_cmpstr((g_hash_table_lookup(kvs, "counter")), ==, "42");
}

static void test_manifest_load_details(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	g_autofree gchar *manifestpath = NULL;
	gboolean res;
	GError *error = NULL;
	RaucImage *test_img = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
type=ext4\n\
version=2015.04.1\n\
description=image description\n\
build=123456789\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_clear_error(&error);

	test_img = (RaucImage*)g_list_nth_data(rm->images, 0);
	/* image details are currently ignored during parsing */
	g_assert_nonnull(test_img);
}

static void test_manifest_invalid_hook_name(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *manifestpath = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	gboolean res = FALSE;
	g_autoptr(GError) error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
hooks=doesnotexist\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_assert_false(res);
	g_assert_null(rm);
}

static void test_manifest_invalid_hook_combination(void)
{
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
sha256=0815\n\
size=1\n\
hooks=install;pre-install\n\
";

	g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	g_autofree gchar *manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	g_autoptr(RaucManifest) rm = NULL;
	g_autoptr(GError) error = NULL;
	gboolean res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = check_manifest_create(rm, &error);
	g_assert_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR);
	g_assert_cmpstr("An 'install' hook must not be combined with 'pre-install' or 'post-install' hooks", ==, error->message);
	g_assert_false(res);
}

static void test_manifest_missing_hook_name(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *manifestpath = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	gboolean res = FALSE;
	g_autoptr(GError) error = NULL;
	const gchar *mffile = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
sha256=0815\n\
size=1\n\
hooks=install\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "manifest.raucm", mffile, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = check_manifest_internal(rm, &error);
	g_assert_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR);
	g_assert_false(res);
}

/* Check if missing 'size=' parameter in manifest image section causes and error.
 * Also check that this does NOT cause an error when using a custom 'install'
 * hook (to stay compatible with bundles having zero-size images generated with
 * RAUC <1.5)
 */
static void test_manifest_missing_image_size(void)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *manifestpath = NULL;
	g_autoptr(RaucManifest) rm = NULL;
	gboolean res = FALSE;
	g_autoptr(GError) error = NULL;
	const gchar *mffile_invalid = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[hooks]\n\
filename=demo.hook\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
sha256=0815\n\
";
	const gchar *mffile_valid = "\
[update]\n\
compatible=FooCorp Super BarBazzer\n\
version=2015.04-1\n\
\n\
[hooks]\n\
filename=demo.hook\n\
\n\
[image.rootfs]\n\
filename=rootfs-default.ext4\n\
sha256=0815\n\
hooks=install\n\
";

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	manifestpath = write_tmp_file(tmpdir, "invalid-manifest.raucm", mffile_invalid, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = check_manifest_internal(rm, &error);
	g_assert_error(error, R_MANIFEST_ERROR, R_MANIFEST_CHECK_ERROR);
	g_assert_false(res);

	/* free */
	g_free(manifestpath);
	g_clear_pointer(&rm, free_manifest);
	g_clear_error(&error);

	manifestpath = write_tmp_file(tmpdir, "valid-manifest.raucm", mffile_valid, NULL);
	g_assert_nonnull(manifestpath);

	res = load_manifest_file(manifestpath, &rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = check_manifest_internal(rm, &error);
	g_assert_no_error(error);
	g_assert_true(res);
}

/* Test manifest/invalid_data:
 *
 * Tests parsing invalid data: *
 * Test cases:
 * - file does not start with a group
 * - compatible is missing
 * - compatible has no value
 * - invalid key
 * - invalid group
 */
static void test_invalid_data(void)
{
	GBytes *data = NULL;
	GError *error = NULL;
	g_autoptr(RaucManifest) rm = NULL;

	// file does not start with a group
#define MANIFEST1 "\
compatible=SuperBazzer\n\
"

	// compatible is missing
#define MANIFEST2 "\
[update]\n\
"

	// compatible has no value
#define MANIFEST3 "\
[update]\n\
compatible=\n\
"

	// invalid key
#define MANIFEST4 "\
[update]\n\
compatible=SuperBazzer\n\
evilkey=foo\n\
"

	// invalid group
#define MANIFEST5 "\
[update]\n\
compatible=SuperBazzer\n\
\n\
[evilgroup]\n\
"

	// invalid meta group
#define MANIFEST6 "\
[update]\n\
compatible=SuperBazzer\n\
\n\
[meta.foo/]\n\
"

	// invalid meta key
#define MANIFEST7 "\
[update]\n\
compatible=SuperBazzer\n\
\n\
[meta.foo]\n\
bar!=baz\n\
"

	data = g_bytes_new_static(MANIFEST1, sizeof(MANIFEST1));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_nonnull(error);
	g_assert_cmpstr("Key file does not start with a group", ==, error->message);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST2, sizeof(MANIFEST2));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST3, sizeof(MANIFEST3));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST4, sizeof(MANIFEST4));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST5, sizeof(MANIFEST5));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST6, sizeof(MANIFEST6));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, R_UTILS_ERROR, R_UTILS_ERROR_INVALID_ENV_KEY);
	g_assert_cmpstr("Invalid metadata section name 'foo/': Character '/' is unsuitable for environment variables", ==, error->message);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);

	data = g_bytes_new_static(MANIFEST7, sizeof(MANIFEST7));
	g_assert_false(load_manifest_mem(data, &rm, &error));
	g_assert_error(error, R_UTILS_ERROR, R_UTILS_ERROR_INVALID_ENV_KEY);
	g_assert_cmpstr("Invalid metadata key name 'bar!': Character '!' is unsuitable for environment variables", ==, error->message);
	g_clear_error(&error);
	g_assert_null(rm);
	g_clear_pointer(&data, g_bytes_unref);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	r_context_conf()->certpath = g_strdup("test/openssl-ca/rel/release-1.cert.pem");
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context_conf()->handlerextra = g_strdup("--dummy1 --dummy2");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/rel/private/release-1.pem");
	r_context();

	g_test_add_func("/manifest/load", test_load_manifest);
	g_test_add_func("/manifest/save_load", test_save_load_manifest);
	g_test_add_func("/manifest/save/writefail", test_save_manifest_writefail);
	g_test_add_func("/manifest/load_mem", test_load_manifest_mem);
	g_test_add_func("/manifest/load_variants", test_manifest_load_variants);
	g_test_add_func("/manifest/load_types", test_manifest_load_types);
	g_test_add_func("/manifest/load_types_invalid", test_manifest_load_types_invalid);
	g_test_add_func("/manifest/load_types_filenext_not_mapped", test_manifest_load_types_fileext_not_mapped);
	g_test_add_func("/manifest/missing_type_and_filename", test_manifest_load_missing_type_and_filename);
	g_test_add_func("/manifest/load_types_emptyfs_valid", test_manifest_load_types_emptyfs_valid);
	g_test_add_func("/manifest/load_types_emptyfs_with_filename_invalid", test_manifest_load_types_emptyfs_with_imagename_invalid);
	g_test_add_func("/manifest/load_adaptive", test_manifest_load_adaptive);
	g_test_add_func("/manifest/load_meta", test_manifest_load_meta);
	g_test_add_func("/manifest/load_details", test_manifest_load_details);
	g_test_add_func("/manifest/invalid_hook_name", test_manifest_invalid_hook_name);
	g_test_add_func("/manifest/invalid_hook_combination", test_manifest_invalid_hook_combination);
	g_test_add_func("/manifest/missing_hook_name", test_manifest_missing_hook_name);
	g_test_add_func("/manifest/missing_image_size", test_manifest_missing_image_size);
	g_test_add_func("/manifest/invalid_data", test_invalid_data);

	return g_test_run();
}
