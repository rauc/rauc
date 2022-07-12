#include <errno.h>
#include <ftw.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(bytes != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

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

gchar *resolve_path(const gchar *basefile, const gchar *path)
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

gchar *resolve_path_take(const char *basefile, gchar *path)
{
	gchar *result = resolve_path(basefile, path);
	g_free(path);
	return result;
}

gboolean check_remaining_groups(GKeyFile *key_file, GError **error)
{
	gsize rem_num_groups;
	g_auto(GStrv) rem_groups = NULL;

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
	g_auto(GStrv) rem_keys = NULL;

	rem_keys = g_key_file_get_keys(key_file, groupname, &rem_num_keys, NULL);
	if (rem_keys && rem_num_keys != 0) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"Invalid key '%s' in group '[%s]'", rem_keys[0],
				groupname);
		return FALSE;
	}

	return TRUE;
}

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
		g_free(result);
		return NULL;
	}

	return result;
}

gint key_file_consume_integer(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
{
	gint result;
	GError *ierror = NULL;

	result = g_key_file_get_integer(key_file, group_name, key, &ierror);
	if (ierror == NULL)
		g_key_file_remove_key(key_file, group_name, key, NULL);
	else
		g_propagate_error(error, ierror);

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

	return result << scale_shift;
}

gchar * r_realpath(const gchar *path)
{
	gchar buf[PATH_MAX + 1];
	gchar *rpath;

	rpath = realpath(path, buf);

	return g_strdup(rpath);
}

gboolean r_whitespace_removed(gchar *str)
{
	gsize len;

	if (str == NULL)
		return FALSE;

	len = strlen(str);

	if (len == 0)
		return FALSE;

	g_strstrip(str);

	return strlen(str) != len;
}

guint8 *r_hex_decode(const gchar *hex, size_t len)
{
	g_autofree guint8 *raw = NULL;
	size_t input_len = 0;

	g_assert(hex != NULL);

	input_len = strlen(hex);
	if (input_len != (len * 2))
		return NULL;

	raw = g_malloc0(len);
	for (size_t i = 0; i < len; i++) {
		gint upper = g_ascii_xdigit_value(hex[i*2]);
		gint lower = g_ascii_xdigit_value(hex[i*2+1]);

		if ((upper < 0) || (lower < 0))
			return NULL;

		raw[i] = upper << 4 | lower;
	}

	return g_steal_pointer(&raw);
}

gchar *r_hex_encode(const guint8 *raw, size_t len)
{
	const char hex_chars[] = "0123456789abcdef";
	gchar *hex = NULL;

	g_assert(raw != NULL);
	g_assert(len > 0);

	len *= 2;
	hex = g_malloc0(len+1);
	for (size_t i = 0; i < len; i += 2) {
		hex[i] = hex_chars[(raw[i/2] >> 4)];
		hex[i+1] = hex_chars[(raw[i/2] & 0xf)];
	}

	return hex;
}

gboolean r_read_exact(const int fd, guint8 *data, size_t size, GError **error)
{
	size_t pos = 0;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	while (pos < size) {
		size_t remaining = size - pos;
		ssize_t ret = TEMP_FAILURE_RETRY(read(fd, data+pos, remaining));
		if (ret < 0) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to read: %s", g_strerror(err));
			return FALSE;
		} else if (ret == 0) { /* end of file */
			return FALSE;
		} else if ((size_t)ret <= remaining) {
			pos += ret;
		} else if ((size_t)ret > remaining) {
			g_assert_not_reached();
			return FALSE;
		}
	}

	return TRUE;
}

gboolean r_write_exact(const int fd, const guint8 *data, size_t size, GError **error)
{
	size_t pos = 0;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	while (pos < size) {
		size_t remaining = size - pos;
		ssize_t ret = TEMP_FAILURE_RETRY(write(fd, data+pos, remaining));
		if (ret < 0) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to write: %s", g_strerror(err));
			return FALSE;
		} else if ((size_t)ret <= remaining) {
			pos += ret;
		} else if ((size_t)ret > remaining) {
			g_assert_not_reached();
			return FALSE;
		}
	}

	return TRUE;
}

gboolean r_pread_exact(const int fd, guint8 *data, size_t size, off_t offset, GError **error)
{
	size_t pos = 0;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	while (pos < size) {
		size_t remaining = size - pos;
		ssize_t ret = TEMP_FAILURE_RETRY(pread(fd, data+pos, remaining, offset+pos));
		if (ret < 0) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to read: %s", g_strerror(err));
			return FALSE;
		} else if (ret == 0) { /* end of file */
			return FALSE;
		} else if ((size_t)ret <= remaining) {
			pos += ret;
		} else if ((size_t)ret > remaining) {
			g_assert_not_reached();
			return FALSE;
		}
	}

	return TRUE;
}

gboolean r_pwrite_exact(const int fd, const guint8 *data, size_t size, off_t offset, GError **error)
{
	size_t pos = 0;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	while (pos < size) {
		size_t remaining = size - pos;
		ssize_t ret = TEMP_FAILURE_RETRY(pwrite(fd, data+pos, remaining, offset+pos));
		if (ret < 0) {
			int err = errno;
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to write: %s", g_strerror(err));
			return FALSE;
		} else if ((size_t)ret <= remaining) {
			pos += ret;
		} else if ((size_t)ret > remaining) {
			g_assert_not_reached();
			return FALSE;
		}
	}

	return TRUE;
}

gboolean r_pwrite_lazy(const int fd, const guint8 *data, size_t size, off_t offset, GError **error)
{
	g_autofree guint8 *read_data = g_malloc(size);
	GError *ierror = NULL;

	if (!r_pread_exact(fd, read_data, size, offset, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Failed to read existing data: ");
		return FALSE;
	}

	if (memcmp(data, read_data, size) == 0) {
		return TRUE;
	}

	return r_pwrite_exact(fd, data, size, offset, error);
}

guint get_sectorsize(gint fd)
{
	guint sector_size;

	if (ioctl(fd, BLKSSZGET, &sector_size) != 0)
		return 512;

	return sector_size;
}
