#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

static void whitespace_removed_test(void)
{
	gchar *str;

	str = g_strdup("foo");
	g_assert_false(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup(" foo ");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);

	str = g_strdup("\r\n\t  foo  \t\r\n");
	g_assert_true(r_whitespace_removed(str));
	g_assert_cmpstr(str, ==, "foo");
	g_free(str);
}

static void get_sectorsize_test(void)
{
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	guint size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_sectorsize(fd);
	g_assert_cmpint(size, ==, 512);

	if (fd >= 0)
		g_close(fd, NULL);
}

static void get_device_size_test(void)
{
	GError *error = NULL;
	const gchar *device = g_getenv("RAUC_TEST_BLOCK_LOOP");
	int fd = -1;
	goffset size = 0;

	if (!device) {
		g_test_message("no block device for testing found (define RAUC_TEST_BLOCK_LOOP)");
		g_test_skip("RAUC_TEST_BLOCK_LOOP undefined");
		return;
	}

	fd = g_open(device, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmphex(fd, >=, 0);

	size = get_device_size(fd, &error);
	g_assert_no_error(error);
	g_assert_cmpint(size, ==, 64<<20); /* 64MiB */

	if (fd >= 0)
		g_close(fd, NULL);
}

static void update_symlink_test(void)
{
	g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_autoptr(GError) error = NULL;
	g_autofree gchar *name_bad = g_build_filename(tmpdir, "missing/s0", NULL);
	g_autofree gchar *name_s1 = g_build_filename(tmpdir, "s1", NULL);
	g_autofree gchar *name_s1_tmp = g_build_filename(tmpdir, "s1.tmp-link", NULL);
	g_autofree gchar *target = NULL;
	struct stat stat_orig = {}, stat_new = {};
	gboolean res = FALSE;

	/* test invalid name */
	res = r_update_symlink("target", name_bad, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_clear_error(&error);

	/* test with directory blocking the symlink name */
	g_assert_cmpint(mkdir(name_s1, 0), ==, 0);

	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_INVAL);
	g_clear_error(&error);

	g_assert_true(g_file_test(name_s1, G_FILE_TEST_IS_DIR));

	g_assert_cmpint(rmdir(name_s1), ==, 0);

	/* test nonexistent symlink */
	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_0");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_orig), ==, 0);

	/* test update with same target */
	res = r_update_symlink("target_0", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_0");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_new), ==, 0);
	g_assert_cmpuint(stat_orig.st_ino, ==, stat_new.st_ino);

	/* test update with different target */
	res = r_update_symlink("target_1", name_s1, &error);
	g_assert_true(res);
	g_assert_no_error(error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_1");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);

	g_assert_cmpint(lstat(name_s1, &stat_new), ==, 0);
	g_assert_cmpuint(stat_orig.st_ino, !=, stat_new.st_ino);

	/* test with a directory blocking the tmp name */
	g_assert_cmpint(mkdir(name_s1_tmp, 0), ==, 0);

	res = r_update_symlink("target_2", name_s1, &error);
	g_assert_false(res);
	g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST);
	g_assert_cmpstr(error->message, ==, "Failed to create symlink: File exists");
	g_clear_error(&error);

	target = g_file_read_link(name_s1, &error);
	g_assert_cmpstr(target, ==, "target_1");
	g_assert_no_error(error);
	g_clear_pointer(&target, g_free);
}

static void fakeroot_test(void)
{
	g_autofree GError *ierror = NULL;
	g_autofree gchar *envpath = NULL;
	g_autoptr(GPtrArray) chown_args = g_ptr_array_new_with_free_func(g_free);
	g_autoptr(GPtrArray) test_args = g_ptr_array_new_with_free_func(g_free);
	g_autoptr(GSubprocess) sproc = NULL;
	g_autofree gchar *stdout = NULL;
	gboolean res = FALSE;

	if (g_strcmp0(g_get_host_name(), "qemu-test") != 0) {
		g_test_message("fakeroot test is only supported under qemu-test");
		g_test_skip("not running under qemu-test");
		return;
	}

	envpath = r_fakeroot_init(&ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(envpath);

	/* fakeroot has not been used yet, but the env should be created by _init */
	g_assert_true(g_file_test(envpath, G_FILE_TEST_EXISTS));

	/* check that /etc/hostname is owned by root */
	r_fakeroot_add_args(test_args, envpath);
	g_assert_cmpuint(test_args->len, ==, 6);

	g_ptr_array_add(test_args, g_strdup("stat"));
	g_ptr_array_add(test_args, g_strdup("-c"));
	g_ptr_array_add(test_args, g_strdup("%u"));
	g_ptr_array_add(test_args, g_strdup("/etc/hostname"));
	g_ptr_array_add(test_args, NULL);

	sproc = r_subprocess_newv(test_args, G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(sproc);

	res = g_subprocess_communicate_utf8(sproc, NULL, NULL, &stdout, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_cmpstr(g_strchomp(stdout), ==, "0");

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_clear_pointer(&stdout, g_free);
	g_clear_pointer(&sproc, g_object_unref);

	/* chown /etc/hostname to user 1*/
	r_fakeroot_add_args(chown_args, envpath);

	g_ptr_array_add(chown_args, g_strdup("chown"));
	g_ptr_array_add(chown_args, g_strdup("1"));
	g_ptr_array_add(chown_args, g_strdup("/etc/hostname"));
	g_ptr_array_add(chown_args, NULL);

	sproc = r_subprocess_newv(chown_args, G_SUBPROCESS_FLAGS_NONE, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(sproc);

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_clear_pointer(&sproc, g_object_unref);

	/* fakeroot has been used yet, the env should exist */
	g_assert_true(g_file_test(envpath, G_FILE_TEST_EXISTS));

	/* check that /etc/hostname is not owned by root */
	sproc = r_subprocess_newv(test_args, G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror);
	g_assert_no_error(ierror);
	g_assert_nonnull(sproc);

	res = g_subprocess_communicate_utf8(sproc, NULL, NULL, &stdout, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
	g_assert_cmpstr(g_strchomp(stdout), ==, "1");

	res = g_subprocess_wait_check(sproc, NULL, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);

	g_clear_pointer(&sproc, g_object_unref);

	res = r_fakeroot_cleanup(envpath, &ierror);
	g_assert_no_error(ierror);
	g_assert_true(res);
}

static void test_bytes_unref_to_string(void)
{
	g_autoptr(GBytes) bytes = NULL;
	g_autofree gchar *str = NULL;

	bytes = g_bytes_new("", 0);
	str = r_bytes_unref_to_string(&bytes);
	g_assert_null(bytes);
	g_assert_nonnull(str);
	g_assert_cmpuint(strlen(str), ==, 0);
	g_assert_cmpstr(str, ==, "");
	g_clear_pointer(&str, g_free);

	bytes = g_bytes_new("", 1);
	str = r_bytes_unref_to_string(&bytes);
	g_assert_null(bytes);
	g_assert_nonnull(str);
	g_assert_cmpuint(strlen(str), ==, 0);
	g_assert_cmpstr(str, ==, "");
	g_clear_pointer(&str, g_free);

	bytes = g_bytes_new("test", 4);
	str = r_bytes_unref_to_string(&bytes);
	g_assert_null(bytes);
	g_assert_nonnull(str);
	g_assert_cmpuint(strlen(str), ==, 4);
	g_assert_cmpstr(str, ==, "test");
	g_clear_pointer(&str, g_free);
}

static void environ_test(void)
{
	g_autoptr(GPtrArray) env_array = g_ptr_array_new_full(2, g_free);
	g_autofree gchar *shell_str = NULL;
	g_auto(GStrv) env = NULL;

	r_ptr_array_add_printf(env_array, "FOO_%d=%s", 12, "bar$");
	r_ptr_array_add_printf(env_array, "BAZ=%s", "baz");

	g_assert_cmpuint(env_array->len, ==, 2);
	g_assert_cmpstr(env_array->pdata[0], ==, "FOO_12=bar$");
	g_assert_cmpstr(env_array->pdata[1], ==, "BAZ=baz");

	shell_str = r_ptr_array_env_to_shell(env_array);
	g_assert_cmpstr(shell_str, ==, "FOO_12='bar$'\nBAZ='baz'");

	env = g_environ_setenv(env, "OTHER", "other-value", FALSE);
	env = g_environ_setenv(env, "BAZ", "old-value", FALSE);
	env = r_environ_setenv_ptr_array(env, env_array, FALSE);
	g_assert_cmpstr(g_environ_getenv(env, "OTHER"), ==, "other-value");
	g_assert_cmpstr(g_environ_getenv(env, "BAZ"), ==, "old-value");
	g_assert_cmpstr(g_environ_getenv(env, "FOO_12"), ==, "bar$");

	env = r_environ_setenv_ptr_array(env, env_array, TRUE);
	g_assert_cmpstr(g_environ_getenv(env, "OTHER"), ==, "other-value");
	g_assert_cmpstr(g_environ_getenv(env, "BAZ"), ==, "baz");
	g_assert_cmpstr(g_environ_getenv(env, "FOO_12"), ==, "bar$");
}

static void semver_parse_test(void)
{
	g_autofree gchar *version_string = NULL;
	g_autofree guint64 version[3] = {0};
	g_autofree gchar *pre_release = NULL;
	g_autofree gchar *build = NULL;
	g_autofree GError *error = NULL;

	version_string = g_strdup("1.2.3");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1);
	g_assert_cmpint(version[1], ==, 2);
	g_assert_cmpint(version[2], ==, 3);
	g_assert_null(pre_release);
	g_assert_null(build);

	r_replace_strdup(&version_string, "1.2.3-foo+baa");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1);
	g_assert_cmpint(version[1], ==, 2);
	g_assert_cmpint(version[2], ==, 3);
	g_assert_cmpstr(pre_release, ==, "foo");
	g_assert_cmpstr(build, ==, "baa");
	g_clear_pointer(&pre_release, g_free);
	g_clear_pointer(&build, g_free);

	r_replace_strdup(&version_string, "1.2.3-foo");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1);
	g_assert_cmpint(version[1], ==, 2);
	g_assert_cmpint(version[2], ==, 3);
	g_assert_cmpstr(pre_release, ==, "foo");
	g_assert_null(build);
	g_clear_pointer(&pre_release, g_free);

	r_replace_strdup(&version_string, "1.2.3+baa");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1);
	g_assert_cmpint(version[1], ==, 2);
	g_assert_cmpint(version[2], ==, 3);
	g_assert_null(pre_release);
	g_assert_cmpstr(build, ==, "baa");
	g_clear_pointer(&build, g_free);

	r_replace_strdup(&version_string, "1.2.3-a.2.d");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1);
	g_assert_cmpint(version[1], ==, 2);
	g_assert_cmpint(version[2], ==, 3);
	g_assert_cmpstr(pre_release, ==, "a.2.d");
	g_assert_null(build);
	g_clear_pointer(&pre_release, g_free);

	/* test error cases */
	r_replace_strdup(&version_string, "v1.2.3");
	g_assert_false(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_error(error, G_NUMBER_PARSER_ERROR, G_NUMBER_PARSER_ERROR_INVALID);
	g_clear_error(&error);

	r_replace_strdup(&version_string, "1.foo.3");
	g_assert_false(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_error(error, G_NUMBER_PARSER_ERROR, G_NUMBER_PARSER_ERROR_INVALID);
	g_clear_error(&error);

	r_replace_strdup(&version_string, "1..3");
	g_assert_false(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_error(error, G_NUMBER_PARSER_ERROR, G_NUMBER_PARSER_ERROR_INVALID);
	g_clear_error(&error);

	r_replace_strdup(&version_string, "..");
	g_assert_false(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_error(error, G_NUMBER_PARSER_ERROR, G_NUMBER_PARSER_ERROR_INVALID);
	g_clear_error(&error);

	r_replace_strdup(&version_string, "");
	g_assert_false(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_error(error, R_UTILS_ERROR, R_UTILS_ERROR_SEMVER_PARSE);
	g_clear_error(&error);

	/* test "relaxed" semantic versions */
	r_replace_strdup(&version_string, "1012.11-a.2.d");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1012);
	g_assert_cmpint(version[1], ==, 11);
	g_assert_cmpint(version[2], ==, 0);
	g_assert_cmpstr(pre_release, ==, "a.2.d");
	g_assert_null(build);
	g_clear_pointer(&pre_release, g_free);

	r_replace_strdup(&version_string, "1012-abc");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1012);
	g_assert_cmpint(version[1], ==, 0);
	g_assert_cmpint(version[2], ==, 0);
	g_assert_cmpstr(pre_release, ==, "abc");
	g_assert_null(build);
	g_clear_pointer(&pre_release, g_free);

	r_replace_strdup(&version_string, "1012");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 1012);
	g_assert_cmpint(version[1], ==, 0);
	g_assert_cmpint(version[2], ==, 0);
	g_assert_null(pre_release);
	g_assert_null(build);

	r_replace_strdup(&version_string, "0");
	g_assert_true(r_semver_parse(version_string, version, &pre_release, &build, &error));
	g_assert_no_error(error);
	g_assert_cmpint(version[0], ==, 0);
	g_assert_cmpint(version[1], ==, 0);
	g_assert_cmpint(version[2], ==, 0);
	g_assert_null(pre_release);
	g_assert_null(build);
}

static void semver_less_equal_test(void)
{
	g_autofree GError *error = NULL;

	/* test "relaxed" semantic versions */
	g_assert_true(r_semver_less_equal("0", "3.2.1", &error));
	g_assert_true(r_semver_less_equal("3", "3.2.1", &error));
	g_assert_true(r_semver_less_equal("3.2", "3.2.1", &error));
	g_assert_false(r_semver_less_equal("4", "3.2.1", &error));

	/* core version comparisons */
	g_assert_true(r_semver_less_equal("3.2.1", "3.2.1", &error));
	g_assert_false(r_semver_less_equal("3.2.2", "3.2.1", &error));
	g_assert_true(r_semver_less_equal("3.2.2", "3.3.1", &error));
	g_assert_false(r_semver_less_equal("4.2.2", "3.3.1", &error));

	/* lexicographic pre_releases */
	g_assert_true(r_semver_less_equal("3.2.1-foo", "3.2.1-foo", &error));
	g_assert_true(r_semver_less_equal("3.2.1-foo", "3.2.1", &error));
	g_assert_true(r_semver_less_equal("3.2.1-foo", "3.2.1-goo", &error));
	g_assert_false(r_semver_less_equal("3.2.1-foop", "3.2.1-foo", &error));

	/* numerical/dot-separated pre_releases */
	g_assert_true(r_semver_less_equal("3.2.1-1.2.3", "3.2.1-1.2.3", &error));
	g_assert_true(r_semver_less_equal("3.2.1-123", "3.2.1-123", &error));
	g_assert_false(r_semver_less_equal("3.2.1-124", "3.2.1-123", &error));
	g_assert_true(r_semver_less_equal("3.2.1-23", "3.2.1-123", &error));
	g_assert_true(r_semver_less_equal("3.2.1-23.0.1", "3.2.1-123.0.12", &error));
	g_assert_true(r_semver_less_equal("3.2.1-23.0.111111", "3.2.1-123.0.12", &error));

	/* mixed */
	g_assert_true(r_semver_less_equal("3.2.1-1.abc", "3.2.1-1.abc", &error));
	g_assert_false(r_semver_less_equal("3.2.1-1.abz", "3.2.1-1.abc", &error));
	g_assert_true(r_semver_less_equal("3.2.1-1.abc.1", "3.2.1-1.abc.2", &error));
	g_assert_false(r_semver_less_equal("3.2.1-1.abc.3", "3.2.1-1.abc.2", &error));
	g_assert_false(r_semver_less_equal("3.2.1-1abc.3", "3.2.1-1000.3", &error));
	g_assert_true(r_semver_less_equal("3.2.1-1999.3", "3.2.1-1abc.3", &error));

	/* none of the tests should have raised an error */
	g_assert_no_error(error);
}

static void format_duration_test(void)
{
	gchar *tmp = NULL;

	tmp = r_format_duration(0);
	g_assert_cmpstr(tmp, ==, "0s");
	g_free(tmp);

	tmp = r_format_duration(1);
	g_assert_cmpstr(tmp, ==, "1s");
	g_free(tmp);

	tmp = r_format_duration(61);
	g_assert_cmpstr(tmp, ==, "1m 1s");
	g_free(tmp);

	tmp = r_format_duration(3601);
	g_assert_cmpstr(tmp, ==, "1h 1s");
	g_free(tmp);

	tmp = r_format_duration(86400);
	g_assert_cmpstr(tmp, ==, "1d");
	g_free(tmp);
}

static void regex_match_test(void)
{
	gchar *tmp = NULL;

	tmp = r_regex_match_simple("rauc\\.slot=(\\S+)", "root=foo quiet rauc.slot=system0 dummy");
	g_assert_cmpstr(tmp, ==, "system0");
	g_free(tmp);

	tmp = r_regex_match_simple("rauc\\.slot=(\\S+)", " root=/dev/null ");
	g_assert_null(tmp);
}

static void tempfile_cleanup_test(void)
{
	g_autofree gchar *tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);

	g_auto(RTempFile) filename = g_build_filename(tmpdir, "file", NULL);
	g_assert_false(g_file_test(filename, G_FILE_TEST_EXISTS));

	/* test missing file */
	{
		g_auto(RTempFile) temp_filename = g_strdup(filename);
		(void)temp_filename;
	}
	g_assert_false(g_file_test(filename, G_FILE_TEST_EXISTS));

	/* test normal file */
	{
		g_auto(RTempFile) temp_filename = g_strdup(filename);
		g_auto(filedesc) temp_fd = g_open(temp_filename, O_RDWR|O_CLOEXEC|O_CREAT, 0);
		(void)temp_fd;
		g_assert_true(g_file_test(temp_filename, G_FILE_TEST_EXISTS));
	}
	g_assert_false(g_file_test(filename, G_FILE_TEST_EXISTS));

	/* test directory instead of file (should warn) */
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "failed to remove */file");
	{
		g_auto(RTempFile) temp_filename = g_strdup(filename);
		g_assert_cmpint(g_mkdir(temp_filename, 0777), ==, 0);
		g_assert_true(g_file_test(temp_filename, G_FILE_TEST_EXISTS));
	}
	g_assert_cmpint(g_rmdir(filename), ==, 0);
	g_test_assert_expected_messages();
}

static void boottime_test(void)
{
	gint64 a = r_get_boottime();
	g_usleep(100000);
	gint64 b = r_get_boottime();

	g_assert_cmpint(b, >, a);
	gint64 diff = b - a;

	g_assert_cmpint(diff, >=, 100000);
	g_assert_cmpint(diff, <=, 110000);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_assert(g_setenv("GIO_USE_VFS", "local", TRUE));

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/utils/whitespace_removed", whitespace_removed_test);
	g_test_add_func("/utils/get_sectorsize", get_sectorsize_test);
	g_test_add_func("/utils/get_device_size", get_device_size_test);
	g_test_add_func("/utils/update_symlink", update_symlink_test);
	g_test_add_func("/utils/fakeroot", fakeroot_test);
	g_test_add_func("/utils/bytes_unref_to_string", test_bytes_unref_to_string);
	g_test_add_func("/utils/environ", environ_test);
	g_test_add_func("/utils/semver_parse_test", semver_parse_test);
	g_test_add_func("/utils/semver_less_equal_test", semver_less_equal_test);
	g_test_add_func("/utils/format_duration", format_duration_test);
	g_test_add_func("/utils/regex_match", regex_match_test);
	g_test_add_func("/utils/tempfile_cleanup", tempfile_cleanup_test);
	g_test_add_func("/utils/boottime", boottime_test);

	return g_test_run();
}
