#pragma once

#include <glib.h>

#include "glib/gstdio.h"
#include "manifest.h"

typedef struct {
	gboolean custom_handler;
	gboolean hooks;
	gboolean slots;

	const gchar *artifact_file;
	const gchar *artifact_slotclass;
	const gchar *artifact_convert;

	RManifestBundleFormat format;
	gboolean no_bundle_version;
	const gchar *bundle_version;
} ManifestTestOptions;

typedef struct {
	const gchar *min_bundle_version;
	gboolean artifact_repos;
} SystemTestOptions;

guint8 *random_bytes(gsize size, guint32 seed);
gchar *write_random_file(const gchar *tmpdir, const gchar *filename,
		gsize size, const guint32 seed);
gchar *write_tmp_file(const gchar *tmpdir, const gchar *filename, const gchar *content, GError **error);
int test_prepare_dummy_file(const gchar *dirname, const gchar *filename,
		gsize size, const gchar *source);
int test_mkdir_relative(const gchar *dirname, const gchar *filename, int mode);
int test_rmdir(const gchar *dirname, const gchar *filename);
int test_remove(const gchar *dirname, const gchar *filename);
int test_lstat(const gchar *dirname, const gchar *filename, GStatBuf *buf);
gboolean test_rm_tree(const gchar *dirname, const gchar *filename);
int test_prepare_system_conf(const gchar *dirname, const gchar *filename, const SystemTestOptions *options);
int test_prepare_manifest_file(const gchar *dirname, const gchar *filename, const ManifestTestOptions *options);
gboolean test_make_filesystem(const gchar *dirname, const gchar *filename);
gboolean test_mount(const gchar *src, const gchar *dest);
gboolean test_umount(const gchar *dirname, const gchar *mountpoint);
gboolean test_do_chmod(const gchar *path);
gboolean test_copy_file(const gchar *srcprefix, const gchar *srcfile, const gchar *dstprefix, const gchar *dstfile);
gboolean test_make_slot_user_writable(const gchar *path, const gchar *file);
void test_create_content(gchar *contentdir, const ManifestTestOptions *options);
void test_create_bundle(gchar *contentdir, gchar *bundlename);
gboolean test_running_as_root(void);
void test_show_tree(const gchar *path, gboolean inodes);
gsize get_file_size(gchar *filename, GError **error);
void flip_bits_fd(int fd, off_t offset, guint8 mask);
void flip_bits_filename(gchar *filename, off_t offset, guint8 mask);
void replace_strdup(gchar **dst, const gchar *src);

/**
 * Build a GPtrArray from a ;-separated string. The elements in the array are
 * freed with the array itself.
 */
GPtrArray *test_ptr_array_from_strsplit(const gchar *input);

void *dup_test_mem(GPtrArray *ptrs, const void *mem, gsize len);
void *dup_test_printf(GPtrArray *ptrs, const gchar *str, ...)
__attribute__((__format__(__printf__, 2, 3)));
#define dup_test_data(ptrs, x) (dup_test_mem(ptrs, x, sizeof(*x)))
