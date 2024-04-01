#pragma once

#include <gio/gio.h>
#include <glib.h>

#define R_UTILS_ERROR r_utils_error_quark()

GQuark r_utils_error_quark(void);

typedef enum {
	R_UTILS_ERROR_FAILED,
	R_UTILS_ERROR_INAPPROPRIATE_IOCTL,
	R_UTILS_ERROR_INVALID_ENV_KEY,
} RUtilsError;

#define BIT(nr) (1UL << (nr))

/* Evaluate EXPRESSION, and repeat as long as it returns -1 with `errno'
 * set to EINTR. Needed for builds against musl, taken from glibc's unistd.h.
 */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
	(__extension__ \
		 ({ long int __result; \
		    do {__result = (long int) (expression);} \
		    while (__result == -1L && errno == EINTR); \
		    __result; }))
#endif

/* Use
 *
 *   g_auto(filedesc) fd = -1
 *
 * to declare a file descriptor that will be automatically closed when
 * fd goes out of scope. The destructor is guaranteed to preserve
 * errno.
 */
typedef int filedesc;
void close_preserve_errno(filedesc fd);
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(filedesc, close_preserve_errno, -1)

#define R_LOG_DOMAIN_SUBPROCESS "rauc-subprocess"

static inline GSubprocess* r_subprocess_newv(GPtrArray *args, GSubprocessFlags flags, GError **error)
{
	g_autofree gchar *call = g_strjoinv(" ", (gchar**) args->pdata);
	g_log(R_LOG_DOMAIN_SUBPROCESS, G_LOG_LEVEL_DEBUG, "launching subprocess: %s", call);

	return g_subprocess_newv((const gchar * const *) args->pdata, flags, error);
}

static inline GSubprocess * r_subprocess_launcher_spawnv(GSubprocessLauncher *launcher, GPtrArray *args, GError **error)
{
	g_autofree gchar *call = g_strjoinv(" ", (gchar**) args->pdata);
	g_log(R_LOG_DOMAIN_SUBPROCESS, G_LOG_LEVEL_DEBUG, "launching subprocess: %s", call);

	return g_subprocess_launcher_spawnv(launcher,
			(const gchar * const *)args->pdata, error);
}

GSubprocess *r_subprocess_new(GSubprocessFlags flags, GError **error, const gchar *argv0, ...)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Starts a subprocess and waits for it to finish.
 *
 * @param args subprocess arguments
 * @param flags subprocess flags
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean r_subprocess_runv(GPtrArray *args, GSubprocessFlags flags, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

#define R_LOG_LEVEL_TRACE 1 << G_LOG_LEVEL_USER_SHIFT
#define r_trace(...)   g_log(G_LOG_DOMAIN,         \
		R_LOG_LEVEL_TRACE,    \
		__VA_ARGS__)

/**
 * Adds elements of a zero-terminated GStrv/gchar** to an existing GPtrArray
 *
 * @param ptrarray GPtrArray to add to
 * @param argvp arguments to add (may be NULL)
 * @param copy whether to just add the pointer (FALSE) or copy the underlying data (TRUE)
 */
static inline void r_ptr_array_addv(GPtrArray *ptrarray, gchar **argvp, gboolean copy)
{
	if (argvp == NULL)
		return;

	for (gchar **addarg = argvp; *addarg != NULL; addarg++) {
		g_ptr_array_add(ptrarray, copy ? g_strdup(*addarg) : *addarg);
	}
}

/**
 * Read file content into a GBytes.
 *
 * @param filename Filename to read from
 * @param error return location for a GError, or NULL
 *
 * @return A newly allocated GBytes on success, NULL if an error occurred
 */
GBytes *read_file(const gchar *filename, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Read file content into a gchar.
 *
 * @param filename Filename to read from
 * @param error return location for a GError, or NULL
 *
 * @return A newly allocated gchar on success, NULL if an error occurred
 */
gchar *read_file_str(const gchar *filename, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Write content of a GBytes to file.
 *
 * @param filename
 * @param bytes
 * @param error return location for a GError, or NULL
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean write_file(const gchar *filename, GBytes *bytes, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
		const gchar *dstprefix, const gchar *dstfile, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

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
 * If `basefile` is given and absolute, its location (with the pathname
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
gchar *resolve_path(const gchar *basefile, const gchar *path)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Resolve path based on directory of `basefile` argument or current working dir
 * and free path.
 *
 * This is a wrapper around resolve_path(), for use when the path argument is
 * not needed after the call.
 *
 * @param basefile Reference path to resolve `path` to
 * @param path The path to resolve an absolute path for (freed)
 *
 * @return An absolute path name, determined as described above, NULL if undeterminable
 *         [transfer full]
 */
gchar *resolve_path_take(const gchar *basefile, gchar *path)
G_GNUC_WARN_UNUSED_RESULT;

gboolean check_remaining_groups(GKeyFile *key_file, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
gboolean check_remaining_keys(GKeyFile *key_file, const gchar *groupname, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get string argument from key and remove key from key_file.
 *
 * @return A newly allocated string or NULL on error.
 */
gchar * key_file_consume_string(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Ensure that the input string contains neither whitespace nor tab.
 *
 * @param str string to check.
 *
 * @return TRUE if str contains neither whitespace nor tab, FALSE otherwise
 */
gboolean value_check_tab_whitespace(const gchar *str, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Get integer argument from key and remove key from key_file.
 */
gint key_file_consume_integer(
		GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
G_GNUC_WARN_UNUSED_RESULT;

guint64 key_file_consume_binary_suffixed_string(GKeyFile *key_file,
		const gchar *group_name,
		const gchar *key,
		GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gchar * r_realpath(const gchar *path)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Remove surrounding whitespace and signal changes.
 *
 * @param str string to modify
 *
 * @return TRUE if whitespace was removed, FALSE otherwise
 */
gboolean r_whitespace_removed(gchar *str)
G_GNUC_WARN_UNUSED_RESULT;

guint8 *r_hex_decode(const gchar *hex, size_t len)
G_GNUC_WARN_UNUSED_RESULT;
gchar *r_hex_encode(const guint8 *raw, size_t len)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_read_exact(const int fd, guint8 *data, size_t size, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
gboolean r_write_exact(const int fd, const guint8 *data, size_t size, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_pread_exact(const int fd, guint8 *data, size_t size, off_t offset, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_pwrite_exact(const int fd, const guint8 *data, size_t size, off_t offset, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_pwrite_lazy(const int fd, const guint8 *data, size_t size, off_t offset, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

guint get_sectorsize(gint fd)
G_GNUC_WARN_UNUSED_RESULT;

goffset get_device_size(gint fd, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Converts a key for use in an environment variable name.
 *
 * Only alphanumeric characters and '_' are allowed. '-' is converted to '_'.
 *
 * @param key string to convert
 * @param error return location for a GError, or NULL
 *
 * @return the newly alloacted and converted string
 */
gchar *r_prepare_env_key(const gchar *key, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Atomically updates a symlink (if needed).
 *
 * @param target new target for the symlink
 * @param name filename of the symlink to update
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if the symlink now points to the given target, FALSE otherwise
 */
gboolean r_update_symlink(const gchar *target, const gchar *name, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Calls syncfs on a given filesystem.
 *
 * @param path path on the filesystem to sync
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if the filesystem was synced, FALSE otherwise
 */
gboolean r_syncfs(const gchar *path, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Create a temporary directory for the fakeroot environment file.
 *
 * @param error return location for a GError, or NULL
 *
 * @return path to the env file, NULL on error
 */
gchar* r_fakeroot_init(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

/**
 * Add fakeroot startup arguments to the array.
 *
 * The env file needs to be created with r_fakeroot_init first.
 * Does nothing if the path is NULL.
 *
 * @param args the GPtrArray to modify
 * @param envpath path to the env file
 */
void r_fakeroot_add_args(GPtrArray *args, const gchar *envpath);

/**
 * Removes the temporary directory containing the fakeroot environment file.
 *
 * Does nothing if the path is NULL.
 *
 * @param envpath path to the env file
 * @param error return location for a GError, or NULL
 *
 * @return TRUE if the cleanup was successful, FALSE otherwise
 */
gboolean r_fakeroot_cleanup(const gchar *envpath, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
