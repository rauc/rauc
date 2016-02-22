#pragma once

#include <config.h>
#include <glib.h>

int test_prepare_dummy_file(const gchar *dirname, const gchar *filename,
			    gsize size, const gchar *source);
int test_mkdir_relative(const gchar *dirname, const gchar *filename, int mode);
int test_rmdir(const gchar *dirname, const gchar *filename);
gboolean test_rm_tree(const gchar *dirname, const gchar *filename);
int test_prepare_manifest_file(const gchar *dirname, const gchar *filename, gboolean custom_handler);
gboolean test_make_filesystem(const gchar *dirname, const gchar *filename);
gboolean test_mount(const gchar *src, const gchar *dest);
gboolean test_umount(const gchar *dirname, const gchar *mountpoint);
gboolean test_do_chmod(const gchar *path);
gboolean test_copy_file(const gchar *srcprefix, const gchar *srcfile, const gchar *dstprefix, const gchar *dstfile);
gboolean test_make_slot_user_writable(const gchar* path, const gchar* file);
const gchar* test_bootname_provider(void);
