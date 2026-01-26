#include <errno.h>
#include <fcntl.h>
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
#include <time.h>

#include "utils.h"

GQuark r_utils_error_quark(void)
{
	return g_quark_from_static_string("r_utils_error_quark");
}

GSubprocess *r_subprocess_new(GSubprocessFlags flags, GError **error, const gchar *argv0, ...)
{
	g_return_val_if_fail(argv0 != NULL && argv0[0] != '\0', NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autoptr(GPtrArray) args = g_ptr_array_new();

	va_list ap;
	va_start(ap, argv0);
	g_ptr_array_add(args, (gchar *) argv0);
	const gchar *arg;
	while ((arg = va_arg(ap, const gchar *)))
		g_ptr_array_add(args, (gchar *) arg);
	g_ptr_array_add(args, NULL);
	va_end(ap);

	return r_subprocess_newv(args, flags, error);
}

gboolean r_subprocess_runv(GPtrArray *args, GSubprocessFlags flags, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(args != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GSubprocess) sproc = r_subprocess_newv(args, flags, &ierror);
	if (sproc == NULL) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!g_subprocess_wait_check(sproc, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

void close_preserve_errno(int fd)
{
	int err = errno;
	(void) close(fd);
	errno = err;
}

void r_ptr_array_add_printf(GPtrArray *ptrarray, const gchar *format, ...)
{
	va_list args;

	g_return_if_fail(ptrarray != NULL);
	g_return_if_fail(format != NULL);

	va_start(args, format);
	g_ptr_array_add(ptrarray, g_strdup_vprintf(format, args));
	va_end(args);
}

gchar *r_ptr_array_env_to_shell(const GPtrArray *ptrarray)
{
	g_return_val_if_fail(ptrarray != NULL, NULL);

	g_autoptr(GString) text = g_string_new(NULL);

	for (guint i = 0; i < ptrarray->len; i++) {
		const gchar *element = g_ptr_array_index(ptrarray, i);
		gchar *eq = strchr(element, '=');

		if (!eq) {
			g_error("missing '=' in '%s'", element);
			return NULL;
		}

		g_autofree gchar *k = g_strndup(element, eq-element);
		g_autofree gchar *v = g_shell_quote(eq+1);

		g_string_append_printf(text, "%s=%s\n", k, v);
	}

	/* remove final \n */
	if (text->len > 1)
		g_string_truncate(text, text->len - 1);

	return g_string_free(g_steal_pointer(&text), FALSE);
}

gchar **r_environ_setenv_ptr_array(gchar **envp, const GPtrArray *ptrarray, gboolean overwrite)
{
	g_return_val_if_fail(envp != NULL, NULL);
	g_return_val_if_fail(ptrarray != NULL, NULL);

	for (guint i = 0; i < ptrarray->len; i++) {
		const gchar *element = g_ptr_array_index(ptrarray, i);
		gchar *eq = strchr(element, '=');

		if (!eq) {
			g_error("missing '=' in '%s'", element);
			return NULL;
		}

		g_autofree gchar *k = g_strndup(element, eq-element);

		envp = g_environ_setenv(envp, k, eq+1, overwrite);
	}

	return envp;
}

void r_subprocess_launcher_setenv_ptr_array(GSubprocessLauncher *launcher, const GPtrArray *ptrarray, gboolean overwrite)
{
	g_return_if_fail(launcher != NULL);
	g_return_if_fail(ptrarray != NULL);

	for (guint i = 0; i < ptrarray->len; i++) {
		const gchar *element = g_ptr_array_index(ptrarray, i);
		gchar *eq = strchr(element, '=');

		if (!eq) {
			g_error("missing '=' in '%s'", element);
			return;
		}

		g_autofree gchar *k = g_strndup(element, eq-element);

		g_subprocess_launcher_setenv(launcher, k, eq+1, overwrite);
	}
}

GBytes *read_file(const gchar *filename, GError **error)
{
	gchar *contents = NULL;
	gsize length = 0;

	if (!g_file_get_contents(filename, &contents, &length, error))
		return NULL;

	return g_bytes_new_take(contents, length);
}

gchar *read_file_str(const gchar *filename, GError **error)
{
	gchar *contents = NULL;
	gsize length = 0;

	if (!g_file_get_contents(filename, &contents, &length, error))
		return NULL;

	gchar *res = g_strndup(contents, length);
	g_free(contents);

	return res;
}

gboolean write_file(const gchar *filename, GBytes *bytes, GError **error)
{
	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(bytes != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	gsize length;
	const gchar *contents = g_bytes_get_data(bytes, &length);

	return g_file_set_contents(filename, contents, length, error);
}

gboolean copy_file(const gchar *srcprefix, const gchar *srcfile,
		const gchar *dstprefix, const gchar *dstfile, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *srcpath = g_build_filename(srcprefix, srcfile, NULL);
	g_autofree gchar *dstpath = g_build_filename(dstprefix, dstfile, NULL);
	g_autoptr(GFile) src = g_file_new_for_path(srcpath);
	g_autoptr(GFile) dst = g_file_new_for_path(dstpath);

	gboolean res = g_file_copy(src, dst, G_FILE_COPY_NONE, NULL, NULL, NULL,
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
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(strlen(path) > 1, FALSE);
	g_return_val_if_fail(path[0] == '/', FALSE);

	int flags = FTW_DEPTH | FTW_MOUNT | FTW_PHYS;
	if (nftw(path, &rm_tree_cb, 20, flags)) {
		g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "failed to remove tree at %s: %s", path, g_strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static GPrivate tree_check_open_error = G_PRIVATE_INIT((GDestroyNotify)g_error_free);

static int tree_check_open_cb(const char *fpath, const struct stat *sb,
		int typeflag, struct FTW *ftwbuf)
{
	g_auto(filedesc) fd = -1;

	switch (typeflag) {
		case FTW_F:
			/* check for other open file descriptors via leases (see fcntl(2)) */
			fd = g_open(fpath, O_RDONLY);
			if (fd == -1) {
				int err = errno;
				g_private_set(&tree_check_open_error,
						g_error_new(
								G_FILE_ERROR,
								g_file_error_from_errno(err),
								"Failed to open %s: %s", fpath, g_strerror(err)
								)
						);
				return -1;
			}
			if (fcntl(fd, F_SETLEASE, F_WRLCK)) {
				int err = errno;
				if (err == EAGAIN) {
					g_private_set(&tree_check_open_error,
							g_error_new(
									R_UTILS_ERROR,
									R_UTILS_ERROR_OPEN_FILE,
									"File %s is currently open", fpath
									)
							);
					return 1;
				}
				const gchar *message = NULL;
				if (err == EACCES) {
					message = "EACCES: missing capability CAP_LEASE?";
				} else {
					message = g_strerror(err);
				}
				g_private_set(&tree_check_open_error,
						g_error_new(
								G_FILE_ERROR,
								g_file_error_from_errno(err),
								"Failed to check if %s is open: %s", fpath, message
								)
						);
				return -1;
			}
			return 0;
		case FTW_SL:
		case FTW_DP:
			return 0; /* continue walk */
		default:
			return -1;
	}
}

gboolean r_tree_check_open(const gchar *path, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(strlen(path) > 1, FALSE);
	g_return_val_if_fail(path[0] == '/', FALSE);
	g_return_val_if_fail(g_private_get(&tree_check_open_error) == NULL, FALSE);

	int flags = FTW_DEPTH | FTW_MOUNT | FTW_PHYS;
	int ret = nftw(path, &tree_check_open_cb, 20, flags);
	if (ret) {
		g_autofree GError *ierror = g_private_get(&tree_check_open_error);
		g_private_set(&tree_check_open_error, NULL);
		if (ret < 0 && ierror) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to check tree at %s for open files: ",
					path
					);
			ierror = NULL;
		} else if (ret < 0) {
			g_set_error(error,
					G_FILE_ERROR, G_FILE_ERROR_FAILED,
					"Failed to check tree at %s for open files: %s",
					path, g_strerror(errno)
					);
		} else if (ret == 1) {
			g_propagate_error(error, ierror);
			ierror = NULL;
		}
		return FALSE;
	}

	return TRUE;
}

gchar *resolve_path(const gchar *basefile, const gchar *path)
{
	if (path == NULL)
		return NULL;

	if (g_str_has_prefix(path, "pkcs11:"))
		return g_strdup(path);

	if (g_path_is_absolute(path))
		return g_strdup(path);

	g_autofree gchar *cwd = g_get_current_dir();

	if (!basefile)
		return g_build_filename(cwd, path, NULL);

	g_autofree gchar *dir = g_path_get_dirname(basefile);
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
	g_auto(GStrv) rem_groups = g_key_file_get_groups(key_file, &rem_num_groups);
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
	g_auto(GStrv) rem_keys = g_key_file_get_keys(key_file, groupname, &rem_num_keys, NULL);
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
	GError *ierror = NULL;

	gchar *result = g_key_file_get_string(key_file, group_name, key, &ierror);
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

gboolean value_check_tab_whitespace(const gchar *str, GError **error)
{
	g_return_val_if_fail(str != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (strchr(str, '\t') || strchr(str, ' ')) {
		g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
				"The value '%s' can not contain tab or whitespace characters",
				str
				);
		return FALSE;
	}

	return TRUE;
}

gint key_file_consume_integer(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
{
	GError *ierror = NULL;

	gint result = g_key_file_get_integer(key_file, group_name, key, &ierror);
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
	GError *ierror = NULL;

	g_autofree gchar *string = key_file_consume_string(key_file, group_name, key, &ierror);
	if (!string) {
		g_propagate_error(error, ierror);
		return 0;
	}

	gchar *scale;
	guint64 result = g_ascii_strtoull(string, &scale, 10);
	if (result == 0)
		return result;

	guint scale_shift = 0;
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
	gchar *rpath = realpath(path, buf);

	return g_strdup(rpath);
}

gboolean r_whitespace_removed(gchar *str)
{
	if (str == NULL)
		return FALSE;

	gsize len = strlen(str);

	if (len == 0)
		return FALSE;

	g_strstrip(str);

	return strlen(str) != len;
}

guint8 *r_hex_decode(const gchar *hex, size_t len)
{
	g_assert(hex != NULL);

	size_t input_len = strlen(hex);
	if (input_len != (len * 2))
		return NULL;

	g_autofree guint8 *raw = g_malloc0(len);
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
	g_assert(raw != NULL);
	g_assert(len > 0);

	const char hex_chars[] = "0123456789abcdef";
	len *= 2;
	gchar *hex = g_malloc0(len+1);
	for (size_t i = 0; i < len; i += 2) {
		hex[i] = hex_chars[(raw[i/2] >> 4)];
		hex[i+1] = hex_chars[(raw[i/2] & 0xf)];
	}

	return hex;
}

gboolean r_read_exact(const int fd, guint8 *data, size_t size, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	size_t pos = 0;
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
			g_set_error(error,
					G_FILE_ERROR,
					G_FILE_ERROR_FAILED,
					"Unexpected end of file");
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
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	size_t pos = 0;
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
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	size_t pos = 0;
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
			g_set_error(error,
					G_FILE_ERROR,
					G_FILE_ERROR_FAILED,
					"Unexpected end of file");
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
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	size_t pos = 0;
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
	guint sector_size = 512;

	if (ioctl(fd, BLKSSZGET, &sector_size) != 0)
		return 512;

	return sector_size;
}

goffset get_device_size(gint fd, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, 0);

	guint64 size = 0;
	if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
		int err = errno;
		if (err == ENOTTY) {
			g_set_error(error,
					R_UTILS_ERROR,
					R_UTILS_ERROR_INAPPROPRIATE_IOCTL,
					"Failed to get device size: Not a block device");
		} else {
			g_set_error(error,
					G_FILE_ERROR,
					g_file_error_from_errno(err),
					"Failed to get device size: %s", g_strerror(err));
		}
		return 0;
	}

	g_assert(size <= G_MAXOFFSET);

	return size;
}

void r_replace_strdup(gchar **dst, const gchar *src)
{
	g_free(*dst);
	*dst = g_strdup(src);
}

gchar *r_prepare_env_key(const gchar *key, GError **error)
{
	g_return_val_if_fail(key != NULL, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, 0);

	size_t len = strlen(key);
	g_autofree gchar *result = g_ascii_strup(key, len);

	for (size_t i = 0; i < len; i++) {
		if (g_ascii_isalnum(result[i]))
			continue;
		if (result[i] == '_')
			continue;
		if (result[i] == '-') {
			result[i] = '_';
			continue;
		}
		g_set_error(error,
				R_UTILS_ERROR,
				R_UTILS_ERROR_INVALID_ENV_KEY,
				"Character '%c' is unsuitable for environment variables",
				key[i]);
		return NULL;
	}

	return g_steal_pointer(&result);
}

gboolean r_update_symlink(const gchar *target, const gchar *name, GError **error)
{
	GError *ierror = NULL;

	g_autofree gchar *old_target = g_file_read_link(name, &ierror);
	if (old_target == NULL) {
		if (!g_error_matches(ierror, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		g_clear_error(&ierror);
	} else if (g_strcmp0(old_target, target) == 0) {
		return TRUE;
	}

	g_autofree gchar *tmp_name = g_strdup_printf("%s.tmp-link", name);
	if (symlink(target, tmp_name) == -1) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to create symlink: %s", g_strerror(err));
		return FALSE;
	}

	if (rename(tmp_name, name) == -1) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to replace symlink: %s", g_strerror(err));
		/* try to remove the temporary symlink */
		unlink(tmp_name);

		return FALSE;
	}

	return TRUE;
}

gboolean r_syncfs(const gchar *path, GError **error)
{
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_auto(filedesc) fd = g_open(path, O_RDONLY);
	if (fd == -1) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to open %s for syncfs: %s", path, g_strerror(err));
		return FALSE;
	}

	if (syncfs(fd) == -1) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to sync filesystem for %s: %s", path, g_strerror(err));
		return FALSE;
	}

	return TRUE;
}

gchar* r_fakeroot_init(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-fakeroot-XXXXXX", &ierror);
	if (tmpdir == NULL) {
		g_propagate_prefixed_error(error, ierror, "Failed to create tmp dir: ");
		return NULL;
	}

	g_autofree gchar *tmpfile = g_build_filename(tmpdir, "environment", NULL);
	g_auto(filedesc) fd = g_open(tmpfile, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		int err = errno;
		g_set_error(error,
				G_FILE_ERROR,
				g_file_error_from_errno(err),
				"Failed to create %s: %s", tmpfile, g_strerror(err));
		return FALSE;
	}

	return g_steal_pointer(&tmpfile);
}

void r_fakeroot_add_args(GPtrArray *args, const gchar *envpath)
{
	g_return_if_fail(args != NULL);

	if (!envpath)
		return;

	g_assert(g_path_is_absolute(envpath));
	g_assert(g_str_has_suffix(envpath, "/environment"));

	g_ptr_array_add(args, g_strdup("fakeroot"));
	g_ptr_array_add(args, g_strdup("-s"));
	g_ptr_array_add(args, g_strdup(envpath));
	g_ptr_array_add(args, g_strdup("-i"));
	g_ptr_array_add(args, g_strdup(envpath));
	g_ptr_array_add(args, g_strdup("--"));
}

gboolean r_fakeroot_cleanup(const gchar *envpath, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!envpath)
		return TRUE;

	g_assert(g_path_is_absolute(envpath));
	g_assert(g_str_has_suffix(envpath, "/environment"));

	g_autofree gchar *tmpdir = g_path_get_dirname(envpath);

	return rm_tree(tmpdir, error);
}

void r_tempfile_cleanup(gchar *filename)
{
	if (!filename)
		return;

	if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
		if (g_unlink(filename) != 0)
			g_warning("failed to remove %s", filename);
	}

	g_free(filename);
}

gchar *r_bytes_unref_to_string(GBytes **bytes)
{
	g_return_val_if_fail(bytes != NULL && *bytes != NULL, NULL);

	gsize size = 0;
	g_autofree gchar *data = g_bytes_unref_to_data(*bytes, &size);
	*bytes = NULL;
	if (size == 0)
		return g_strdup("");

	return g_strndup(data, size);
}

gboolean r_semver_parse(const gchar *version_string, guint64 version_core[3], gchar **pre_release, gchar **build, GError **error)
{
	g_autofree gchar *version_copy = g_strdup(version_string);
	gchar *build_pos = NULL;
	gchar *pre_release_pos = NULL;
	g_auto(GStrv) version_parts = NULL;
	GError *ierror = NULL;
	int i = 0;

	g_return_val_if_fail(version_string, FALSE);
	g_return_val_if_fail(version_core, FALSE);
	g_return_val_if_fail(pre_release == NULL || *pre_release == NULL, FALSE);
	g_return_val_if_fail(build == NULL || *build == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* semantic versions BNF:
	 * <valid semver> ::= <version core>
	 * | <version core> "-" <pre-release>
	 * | <version core> "+" <build>
	 * | <version core> "-" <pre-release> "+" <build>
	 *
	 * detect first the '+build', separate it out by null terminating the
	 * version_copy at it's start position; repeat for the '-pre-release'; and
	 * then parse the remaining 'version core'
	 */

	build_pos = g_strrstr(version_copy, "+");
	if (build_pos != NULL) {
		if (build != NULL) {
			*build = g_strdup(build_pos + 1);
			if (*build == NULL) {
				g_set_error(error,
						R_UTILS_ERROR,
						R_UTILS_ERROR_SEMVER_PARSE,
						"Failed to parse semantic version '%s', '+build' turned out to be empty.",
						version_string);
				goto out;
			}
		}
		*build_pos = '\0';
	}

	pre_release_pos = g_strrstr(version_copy, "-");
	if (pre_release_pos != NULL) {
		if (pre_release != NULL) {
			*pre_release = g_strdup(pre_release_pos + 1);
			if (*pre_release == NULL) {
				g_set_error(error,
						R_UTILS_ERROR,
						R_UTILS_ERROR_SEMVER_PARSE,
						"Failed to parse semantic version '%s', '-pre_release' turned out to be empty.",
						version_string);
				goto out;
			}
		}
		*pre_release_pos = '\0';
	}

	version_parts = g_strsplit(version_copy, ".", 3);
	/* Note that g_strsplit returns an empty array when splitting: "" */
	if (version_parts == NULL) {
		g_set_error(error,
				R_UTILS_ERROR,
				R_UTILS_ERROR_SEMVER_PARSE,
				"Failed to parse semantic version '%s', 'version core' turned out to be empty.",
				version_string);
		goto out;
	}
	/* and NULL terminates arrays it creates */
	if (version_parts[0] == NULL) {
		g_set_error(error,
				R_UTILS_ERROR,
				R_UTILS_ERROR_SEMVER_PARSE,
				"Failed to parse semantic version '%s', 'version core' has no components.",
				version_string);
		goto out;
	}

	for (i = 0; i < 3; i++)
		version_core[i] = 0;
	i = 0;
	while (version_parts[i]) {
		if (!g_ascii_string_to_unsigned(version_parts[i], 10, 0, G_MAXUINT64, &version_core[i], &ierror)) {
			g_propagate_prefixed_error(error, ierror,
					"Failed to parse core version component '%s' as uint: ", version_parts[i]);
			goto out;
		}
		i++;
	}

	return TRUE;

out:
	if (pre_release)
		g_clear_pointer(pre_release, g_free);
	if (build)
		g_clear_pointer(build, g_free);
	return FALSE;
}

gboolean r_semver_less_equal(const gchar *version_string_a, const gchar *version_string_b, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(version_string_a, FALSE);
	g_return_val_if_fail(version_string_b, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	guint64 version_core_a[3] = {0};
	g_autofree gchar *pre_release_a = NULL;
	if (!r_semver_parse(version_string_a, version_core_a, &pre_release_a, NULL, &ierror)) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to parse semantic version A for comparison: ");
		return FALSE;
	}
	guint64 version_core_b[3] = {0};
	g_autofree gchar *pre_release_b = NULL;
	if (!r_semver_parse(version_string_b, version_core_b, &pre_release_b, NULL, &ierror)) {
		g_propagate_prefixed_error(error, ierror,
				"Failed to parse semantic version B for comparison: ");
		return FALSE;
	}

	/* compare version cores: major, minor, patch */
	int i;
	for (i = 0; i < 3; i++) {
		if (version_core_a[i] < version_core_b[i]) {
			return TRUE;
		} else if (version_core_a[i] > version_core_b[i]) {
			return FALSE;
		}
	}

	/* version cores are equal, compare pre-release identifiers */
	if (pre_release_a == NULL && pre_release_b == NULL) {
		return TRUE;
	} else if (pre_release_a == NULL) {
		return FALSE; /* version_a > version_b-pre_release */
	} else if (pre_release_b == NULL) {
		return TRUE; /* version_a-pre_release < version_b */
	}

	/* compare dot-separated fields of pre-release identifiers */
	g_auto(GStrv) pre_fields_a = g_strsplit(pre_release_a, ".", 0);
	g_auto(GStrv) pre_fields_b = g_strsplit(pre_release_b, ".", 0);

	i = 0;
	while (pre_fields_a[i] != NULL && pre_fields_b[i] != NULL) {
		guint64 num_a = 0;
		gboolean is_num_a = g_ascii_string_to_unsigned(pre_fields_a[i], 10, 0, G_MAXUINT64, &num_a, NULL);
		guint64 num_b = 0;
		gboolean is_num_b = g_ascii_string_to_unsigned(pre_fields_b[i], 10, 0, G_MAXUINT64, &num_b, NULL);

		if (is_num_a && is_num_b) {
			/* compare numerically */
			if (num_a < num_b) {
				return TRUE; /* version_a < version_b */
			} else if (num_a > num_b) {
				return FALSE; /* version_a > version_b */
			}

			/* Numeric identifiers always have lower precedence than non-numeric identifiers. */
		} else if (is_num_a && !is_num_b) {
			return TRUE;
		} else if (!is_num_a && is_num_b) {
			return FALSE;
		} else {
			/* compare lexically */
			gint cmp = g_strcmp0(pre_fields_a[i], pre_fields_b[i]);
			if (cmp < 0) {
				return TRUE; /* version_a < version_b */
			} else if (cmp > 0) {
				return FALSE; /* version_a > version_b */
			}
		}
		i++;
	}

	if (pre_fields_a[i] == NULL && pre_fields_b[i] == NULL)
		return TRUE;
	else
		return (pre_fields_a[i] == NULL) && (pre_fields_b[i] != NULL);
}

gchar *r_format_duration(gint64 total_seconds)
{
	gint64 seconds = total_seconds % 60;
	gint64 minutes = (total_seconds / 60) % 60;
	gint64 hours = (total_seconds / 3600) % 24;
	gint64 days = total_seconds / (3600 * 24);

	GString *result = g_string_new(NULL);

	if (days)
		g_string_append_printf(result, "%"G_GINT64_FORMAT "d ", days);
	if (hours)
		g_string_append_printf(result, "%"G_GINT64_FORMAT "h ", hours);
	if (minutes)
		g_string_append_printf(result, "%"G_GINT64_FORMAT "m ", minutes);
	if (seconds || !total_seconds)
		g_string_append_printf(result, "%"G_GINT64_FORMAT "s", seconds);

	return g_strchomp(g_string_free(result, FALSE));
}

gchar *r_regex_match_simple(const gchar *pattern, const gchar *string)
{
	g_return_val_if_fail(pattern, NULL);
	g_return_val_if_fail(string, NULL);

	g_autoptr(GRegex) regex = g_regex_new(pattern, 0, 0, NULL);
	g_autoptr(GMatchInfo) match = NULL;
	if (g_regex_match(regex, string, 0, &match))
		return g_match_info_fetch(match, 1);

	return NULL;
}

gint64 r_get_boottime(void)
{
	struct timespec ts = {0};

	if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
		g_error("RAUC needs CLOCK_BOOTTIME (failed with %s)", g_strerror(errno));

	return (((gint64) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}
