#pragma once

#include <glib.h>

gchar* random_bytes(gsize size, guint32 seed);
gchar* write_random_file(const gchar *tmpdir, const gchar *filename,
		gsize size, const guint32 seed);
gchar* write_tmp_file(const gchar* tmpdir, const gchar* filename, const gchar* content, GError **error);
int test_prepare_dummy_file(const gchar *dirname, const gchar *filename,
		gsize size, const gchar *source);
int test_mkdir_relative(const gchar *dirname, const gchar *filename, int mode);
int test_rmdir(const gchar *dirname, const gchar *filename);
int test_remove(const gchar *dirname, const gchar *filename);
gboolean test_rm_tree(const gchar *dirname, const gchar *filename);
int test_prepare_manifest_file(const gchar *dirname, const gchar *filename, gboolean custom_handler, gboolean hook);
gboolean test_make_filesystem(const gchar *dirname, const gchar *filename);
gboolean test_mount(const gchar *src, const gchar *dest);
gboolean test_umount(const gchar *dirname, const gchar *mountpoint);
gboolean test_do_chmod(const gchar *path);
gboolean test_copy_file(const gchar *srcprefix, const gchar *srcfile, const gchar *dstprefix, const gchar *dstfile);
gboolean test_make_slot_user_writable(const gchar* path, const gchar* file);
void test_create_content(gchar *contentdir);
void test_create_bundle(gchar *contentdir, gchar *bundlename);
gboolean test_running_as_root(void);
