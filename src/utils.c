#include <errno.h>
#include <ftw.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"

GSubprocess *r_subprocess_new(GSubprocessFlags flags, GError **error, const gchar *argv0, ...)
{
	GSubprocess *result;
	g_autoptr(GPtrArray) args = NULL;
	const gchar *arg;
	va_list ap;

	g_return_val_if_fail(argv0 != NULL && argv0[0] != '\0', NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	args = g_ptr_array_new();

	va_start(ap, argv0);
	g_ptr_array_add(args, (gchar *) argv0);
	while ((arg = va_arg(ap, const gchar *)))
		g_ptr_array_add(args, (gchar *) arg);
	g_ptr_array_add(args, NULL);
	va_end(ap);

	result = r_subprocess_newv(args, flags, error);

	return result;
}

void close_preserve_errno(int fd)
{
	int err;

	err = errno;
	(void) close(fd);
	errno = err;
}

GBytes *read_file(const gchar *filename, GError **error)
{
	gchar *contents;
	gsize length;

	if (!g_file_get_contents(filename, &contents, &length, error))
		return NULL;

	return g_bytes_new_take(contents, length);
}

gchar *read_file_str(const gchar *filename, GError **error)
{
	gchar *contents;
	gsize length;
	gchar *res = NULL;

	if (!g_file_get_contents(filename, &contents, &length, error))
		return NULL;

	res = g_strndup(contents, length);
	g_free(contents);

	return res;
}

gboolean write_file(const gchar *filename, GBytes *bytes, GError **error)
{
	const gchar *contents;
	gsize length;

	contents = g_bytes_get_data(bytes, &length);

	return g_file_set_contents(filename, contents, length, error);
}

gboolean copy_file(const gchar *srcprefix, const gchar *srcfile,
		const gchar *dstprefix, const gchar *dstfile, GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	g_autofree gchar *srcpath = g_build_filename(srcprefix, srcfile, NULL);
	g_autofree gchar *dstpath = g_build_filename(dstprefix, dstfile, NULL);
	g_autoptr(GFile) src = g_file_new_for_path(srcpath);
	g_autoptr(GFile) dst = g_file_new_for_path(dstpath);

	res = g_file_copy(src, dst, G_FILE_COPY_NONE, NULL, NULL, NULL,
			&ierror);
	if (!res)
		g_propagate_error(error, ierror);

	return res;
}

static int rm_tree_cb(const char *fpath, const struct stat *sb,
		int typeflag, struct FTW *ftwbuf)
{
	switch (typeflag) {
		case FTW_F:
		case FTW_SL:
			return g_unlink(fpath);
		case FTW_DP:
			return g_rmdir(fpath);
		default:
			return -1;
	}
}

gboolean rm_tree(const gchar *path, GError **error)
{
	int flags = FTW_DEPTH | FTW_MOUNT | FTW_PHYS;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(strlen(path) > 1, FALSE);
	g_return_val_if_fail(path[0] == '/', FALSE);

	if (nftw(path, &rm_tree_cb, 20, flags)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "failed to remove tree at %s: %s", path, g_strerror(errno));
		return FALSE;
	}

	return TRUE;
}


gchar *resolve_path(const gchar *basefile, gchar *path)
{
	g_autofree gchar *cwd = NULL;
	g_autofree gchar *dir = NULL;

	if (path == NULL)
		return NULL;

	if (g_path_is_absolute(path))
		return g_strdup(path);

	cwd = g_get_current_dir();

	if (!basefile)
		return g_build_filename(cwd, path, NULL);

	dir = g_path_get_dirname(basefile);
	if (g_path_is_absolute(dir))
		return g_build_filename(dir, path, NULL);

	return g_build_filename(cwd, dir, path, NULL);
}

gboolean check_remaining_groups(GKeyFile *key_file, GError **error)
{
	gsize rem_num_groups;
	gchar **rem_groups;

	rem_groups = g_key_file_get_groups(key_file, &rem_num_groups);
	if (rem_num_groups != 0) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Invalid group '[%s]'", rem_groups[0]);
		return FALSE;
	}

	return TRUE;
}

gboolean check_remaining_keys(GKeyFile *key_file, const gchar *groupname, GError **error)
{
	gsize rem_num_keys;
	gchar **rem_keys;

	rem_keys = g_key_file_get_keys(key_file, groupname, &rem_num_keys, NULL);
	if (rem_keys && rem_num_keys != 0) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Invalid key '%s' in group '[%s]'", rem_keys[0],
				groupname);
		return FALSE;
	}

	return TRUE;
}

/* get string argument from key and remove key from key_file */
gchar * key_file_consume_string(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
{
	gchar *result = NULL;
	GError *ierror = NULL;

	result = g_key_file_get_string(key_file, group_name, key, &ierror);
	if (!result) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	g_key_file_remove_key(key_file, group_name, key, NULL);

	if (result[0] == '\0') {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Missing value for key '%s'", key);
		return NULL;
	}

	return result;
}

guint64 key_file_consume_binary_suffixed_string(GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
{
	g_autofree gchar *string = NULL;
	guint64 result;
	gchar *scale;
	guint scale_shift = 0;
	GError *ierror = NULL;

	string = key_file_consume_string(key_file, group_name, key, &ierror);
	if (!string) {
		g_propagate_error(error, ierror);
		return 0;
	}

	result = g_ascii_strtoull(string, &scale, 10);

	if (result == 0)
		return result;

	switch (*scale | 0x20) {
		case 'k':
			scale_shift = 10;
			break;
		case 'm':
			scale_shift = 20;
			break;
		case 'g':
			scale_shift = 30;
			break;
		case 't':
			scale_shift = 40;
			break;
		default:
			scale_shift = 0;
			break;
	}

	return (result << scale_shift);
}
