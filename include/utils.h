#pragma once

#include <gio/gio.h>
#include <glib.h>

/* Use
 *
 *   g_auto(filedesc) fd = -1
 *
 * to declare a file descriptor that will be automatically closed when
 * fd goes out of scope. The desctructor is guaranteed to preserve
 * errno.
 */
typedef int filedesc;
void close_preserve_errno(filedesc fd);
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(filedesc, close_preserve_errno, -1)

#define R_LOG_DOMAIN_SUBPROCESS "rauc-subprocess"

static inline GSubprocess* r_subprocess_newv(GPtrArray *args, GSubprocessFlags flags, GError **error)
{
	gchar *call = g_strjoinv(" ", (gchar**) args->pdata);
	g_log(R_LOG_DOMAIN_SUBPROCESS, G_LOG_LEVEL_DEBUG, "launching subprocess: %s", call);
	g_free(call);

	return g_subprocess_newv((const gchar * const *) args->pdata, flags, error);
}

static inline GSubprocess * r_subprocess_launcher_spawnv(GSubprocessLauncher *launcher, GPtrArray *args, GError **error)
{
	gchar *call = g_strjoinv(" ", (gchar**) args->pdata);
	g_log(R_LOG_DOMAIN_SUBPROCESS, G_LOG_LEVEL_DEBUG, "launching subprocess: %s", call);
	g_free(call);

	return g_subprocess_launcher_spawnv(launcher,
			(const gchar * const *)args->pdata, error);
}

GSubprocess *r_subprocess_new(GSubprocessFlags flags, GError **error, const gchar *argv0, ...);

#define R_LOG_LEVEL_TRACE 1 << G_LOG_LEVEL_USER_SHIFT
#define r_trace(...)   g_log(G_LOG_DOMAIN,         \
		R_LOG_LEVEL_TRACE,    \
		__VA_ARGS__)

/**
 * Read file content into a GBytes.
 *
 * @param filename Filename to read from
 * @param error return location for a GError, or NULL
 *
 * @return A newly allocated GBytes on success, NULL if an error occurred
 */
GBytes *read_file(const gchar *filename, GError **error);

/**
 * Read file content into a gchar.
 *
 * @param filename Filename to read from
 * @param error return location for a GError, or NULL
 *
 * @return A newly allocated gchar on success, NULL if an error occurred
 */
gchar *read_file_str(const gchar *filename, GError **error);

/**
 * Write content of a GBytes to file.
 *
 * @param filename
 * @param bytes
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean write_file(const gchar *filename, GBytes *bytes, GError **error);

/**
 * Copy a file.
 *
 * @param srcprefix Prefix path to append to filename given in srcfile
 * @param srcfile filename or path of file to copy from
 * @param dtsprefix Prefix path to append to filename given in dstfile
 * @param dstfile filename or path of file to copy to
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean copy_file(const gchar *srcprefix, const gchar *srcfile,
		const gchar *dstprefix, const gchar *dstfile, GError **error);

/**
 * Recursively delete directory contents.
 *
 * @param path path of directory to delete
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean rm_tree(const gchar *path, GError **error);

/**
 * Resolve path based on directory of `basefile` argument or current working dir.
 *
 * This is useful for parsing paths from config files where the path locations
 * may depend on the config files location. In this case `path` would be the
 * pathname set in the config file, and `basefile` would be the path to the
 * config file itself.
 *
 * If given path itself is absolute, this will be returned.
 * If `basefile` is given and absolute, its location (whith the pathname
 * stripped) will be used as the prefix path for `path`.
 * If `basefile` is not an absolute path, the current workding dir will be used
 * as the prefix path for `path` instead.
 *
 * @param basefile Reference path to resolve `path` to
 * @param path The path to resolve an absolute path for
 *
 * @return An absolute path name, determined as described above, NULL if undeterminable
 *         [transfer full]
 */
gchar *resolve_path(const gchar *basefile, gchar *path);


gboolean check_remaining_groups(GKeyFile *key_file, GError **error);
gboolean check_remaining_keys(GKeyFile *key_file, const gchar *groupname, GError **error);

gchar * key_file_consume_string(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error);

guint64 key_file_consume_binary_suffixed_string(GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error);
