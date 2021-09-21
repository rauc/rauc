#include <ctype.h>
#include <errno.h>
#include <ftw.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

#define R_SYSFS_UBI_BASE_PATH	"/sys/class/ubi"

/**
 * Resolve UBI volume sysfs path to device path.
 *
 * This is done through major:minor device number.
 *
 * @param path sysfs path like "/sys/class/ubi/ubiX/ubiX_Y"
 *
 * @return device path like "/dev/ubi0_2" (newly-allocated string) or NULL.
 */
static gchar *r_ubi_sysfs_to_dev_path(const gchar *path);

/**
 * Search sysfs for UBI volume name.
 *
 * UBI volume names can be read from sysfs path
 * '/sys/class/ubi/ubiX/ubiX_Y/name', so to get the volume id Y by
 * name, step through all volumes of dev X, and compare name until
 * match.
 *
 * @param dev UBI device number, e.g. 0 for ubi0.
 * @param name UBI volume name, e.g. the NAME part of a 'ubiX:NAME'
 *
 * @return sysfs path like "/sys/class/ubi/ubiX/ubiX_Y" (newly-allocated string) or NULL.
 */
static gchar *r_ubi_volname_to_sysfs_path(unsigned int dev, const gchar *name);

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

gchar *r_resolve_device(const gchar *dev)
{
	gchar *idev = NULL;

	if (!dev)
		return NULL;

	if (strncmp(dev, "PARTLABEL=", 10) == 0) {
		idev = g_build_filename("/dev/disk/by-partlabel/",
				&dev[10], NULL);
	} else if (strncmp(dev, "PARTUUID=", 9) == 0) {
		idev = g_build_filename("/dev/disk/by-partuuid/",
				&dev[9], NULL);
	} else if (strncmp(dev, "UUID=", 5) == 0) {
		idev = g_build_filename("/dev/disk/by-uuid/",
				&dev[5], NULL);
	}

	return idev;
}

gchar *r_ubi_name_to_sysfs_path(const gchar *name)
{
	unsigned long int dev;
	char *endptr;

	if (!name)
		return NULL;

	if (strlen(name) < 4)
		return NULL;

	/* see kernel function 'open_ubi()' in file 'fs/ubifs/super.c'
	 * for reference. */

	if (name[0] != 'u' || name[1] != 'b' || name[2] != 'i')
		return NULL;

	/* ubi:NAME method */
	if ((name[3] == ':' || name[3] == '!') && name[4] != '\0')
		return r_ubi_volname_to_sysfs_path(0, name + 4);

	/* every other method proceeds with a digit */
	if (!isdigit(name[3]))
		return NULL;

	dev = strtoul(name + 3, &endptr, 0);

	/* ubiY method */
	if (*endptr == '\0')
		return g_strdup_printf("%s/ubi0/ubi0_%lu",
				R_SYSFS_UBI_BASE_PATH, dev);

	/* ubiX_Y method */
	if (*endptr == '_' && isdigit(endptr[1])) {
		unsigned long int vol;

		vol = strtoul(endptr + 1, &endptr, 0);
		if (*endptr != '\0')
			return NULL;
		return g_strdup_printf("%s/ubi%lu/ubi%lu_%lu",
				R_SYSFS_UBI_BASE_PATH, dev, dev, vol);
	}

	/* ubiX:NAME method */
	if ((*endptr == ':' || *endptr == '!') && endptr[1] != '\0')
		return r_ubi_volname_to_sysfs_path(dev, ++endptr);

	/* no match */
	return NULL;
}

gchar *r_ubi_sysfs_to_dev_path(const gchar *path)
{
	g_autoptr(GFileInputStream) finstream = NULL;
	g_autoptr(GDataInputStream) dinstream = NULL;
	g_autoptr(GFile) infile = NULL;
	gchar *dev = NULL, *devnum, *spath;
	char *line;

	/* open path/dev, store major:minor */
	spath = g_build_filename(path, "dev", NULL);
	devnum = read_file_str(spath, NULL);
	g_free(spath);
	if (!devnum)
		return NULL;
	g_strchomp(devnum);

	/* open /sys/dev/char/major:minor/uevent */
	spath = g_build_filename("/sys/dev/char", devnum, "uevent", NULL);

	/* find and parse DEVNAME */
	infile = g_file_new_for_path(spath);
	g_free(spath);

	finstream = g_file_read(infile, NULL, NULL);
	if (!finstream)
		return NULL;

	dinstream = g_data_input_stream_new( G_INPUT_STREAM(finstream) );

	while ( (line = g_data_input_stream_read_line( dinstream, NULL, NULL, NULL )) )
	{
		g_auto(GStrv) split = g_strsplit(line, "=", 2);
		free(line);

		if (g_strv_length(split) != 2)
			continue;

		if (g_strcmp0(split[0], "DEVNAME") == 0) {
			dev = g_build_filename("/dev", split[1], NULL);
			break;
		}
	}

	return dev;
}

gchar *r_ubi_volname_to_sysfs_path(unsigned int dev, const gchar *name)
{
	g_autoptr(GRegex) regex = NULL;
	g_autoptr(GDir) dir = NULL;
	gchar *spath = NULL, *upath;
	const gchar *dir_entry;

	if (!name)
		return NULL;

	regex = g_regex_new("^ubi\\d+_\\d+$", 0, 0, NULL);
	if (!regex)
		return NULL;

	/* files to be looked at: /sys/class/ubi/ubiX/ubiX_Y/name with X
	 * the same as parameter 'dev' */
	upath = g_strdup_printf("%s/ubi%u", R_SYSFS_UBI_BASE_PATH, dev);

	dir = g_dir_open(upath, 0, NULL);
	if (!dir) {
		g_free(upath);
		return NULL;
	}

	while ((dir_entry = g_dir_read_name(dir))) {
		/* match entry to ubiX_Y, skip everything else */
		if (g_regex_match(regex, dir_entry, 0, NULL)) {
			gchar *npath, *sname;
			int cmpres;

			npath = g_build_filename(upath, dir_entry, "name", NULL);
			sname = g_strchomp(read_file_str(npath, NULL));
			g_free(npath);

			cmpres = g_strcmp0(name, sname);
			g_free(sname);

			if (cmpres == 0) {
				spath = g_build_filename(upath, dir_entry, NULL);
				break;
			}
		}
	}

	g_free(upath);

	return spath;
}
