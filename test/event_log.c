#include <locale.h>
#include <glib.h>

#include <event_log.h>
#include <context.h>

typedef struct {
	gchar *tmpdir;
} EventLogFixture;

typedef struct {
	goffset maxsize;
	gint rotates_at;
} RotationTestConfig;

static void event_log_fixture_set_up(EventLogFixture *fixture,
		gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-event_log-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();
}

static void config_file_fixture_tear_down(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
	r_context_clean();
}

/* Test setting up a logger */
static void event_log_test_setup_logger(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);

	r_event_log_setup_logger(logger);

	g_assert_true(logger->configured);
	g_assert_cmpint(logger->filesize, ==, 0);
}

/* Test setting up a readable (default) logger and writing a simple log message to the logfile */
static void event_log_test_log_write_simple(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"SLOT_NAME", "rootfs.0", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
		{"SLOT_BOOTNAME", "A", -1},
	};
	g_autofree gchar *contents = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);

	r_event_log_setup_logger(logger);

	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	g_assert_true(g_file_get_contents(logger->filename, &contents, NULL, NULL));

	g_assert_nonnull(strstr(contents, "This is a test (mark) log message"));
	g_assert_nonnull(strstr(contents, "bundle hash: b970468f-89e4-4793-9904-06c922902b25"));
}

/* Test setting up a logger with an unwritable file */
static void event_log_test_log_write_broken(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"SLOT_NAME", "rootfs.0", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
		{"SLOT_BOOTNAME", "A", -1},
	};

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_strdup("/this/path/does/not/exist/testfile.log");

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Setting up logger testlogger for *");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Failed to open log file for appending: *");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Deactivating broken logger *");

	r_event_log_setup_logger(logger);

	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	g_assert_true(logger->broken);
	g_assert_false(g_file_test(logger->filename, G_FILE_TEST_EXISTS));
}

/* Test setting up a logger with no space left on device */
static void event_log_test_log_no_space_left(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
	};

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_strdup("/dev/full");

	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Setting up logger testlogger for *");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Failed to write log file *: Error writing to file: No space left on device");
	g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Deactivating broken logger *");

	r_event_log_setup_logger(logger);

	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	g_assert_true(logger->broken);
}

/* Test setting up a json format logger and writing a log message to the logfile */
static void event_log_test_log_write_json(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
	};
	g_autofree gchar *contents = NULL;

	if (!ENABLE_JSON) {
		g_test_skip("Test requires RAUC being configured with \"-Djson=enabled\".");
		return;
	}

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->format = R_EVENT_LOGFMT_JSON;
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);

	r_event_log_setup_logger(logger);

	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	g_assert_true(g_file_get_contents(logger->filename, &contents, NULL, NULL));

	g_assert_nonnull(strstr(contents, "\"MESSAGE\":\"This is a test (mark) log message\""));
	g_assert_nonnull(strstr(contents, "\"MESSAGE_ID\":\"1d1b7a5aa9084c3a9004650c9d2ce850\""));
}

/* Test setting a maxsize and logging until exceeding it */
static void event_log_test_max_size(EventLogFixture *fixture,
		gconstpointer user_data)
{
	const RotationTestConfig *rot_test = user_data;
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
	};
	g_autofree gchar *rotatefile = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);
	logger->maxsize = rot_test->maxsize;
	logger->maxfiles = 1;

	rotatefile = g_build_filename(fixture->tmpdir, "testfile.log.1", NULL);

	r_event_log_setup_logger(logger);

	/* Message size is 128 bytes, thus the 4th write should exceed the
	 * configured 500 bytes maxsize and create the rotation file. */
	for (gint i = 0; i < rot_test->rotates_at; i++) {
		logger->writer(logger, fields, G_N_ELEMENTS(fields));
		if (i == rot_test->rotates_at - 1)
			g_assert_true(g_file_test(rotatefile, G_FILE_TEST_EXISTS));
		else
			g_assert_false(g_file_test(rotatefile, G_FILE_TEST_EXISTS));
	}
}

/* Test setting a maxsize and logging until exceeding it */
static void event_log_test_max_files_rotation(EventLogFixture *fixture,
		gconstpointer user_data)
{
	g_autoptr(REventLogger) logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1 },
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1 },
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
	};
	g_autofree gchar *rotatefile = NULL;
	const gchar *rotate_content = "This string will walk through the files";
	g_autofree gchar *compare_content = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);
	logger->maxsize = 256;
	logger->maxfiles = 3;

	/* create file with content to rotate */
	rotatefile = g_build_filename(fixture->tmpdir, "testfile.log.1", NULL);
	g_assert_true(g_file_set_contents(rotatefile, rotate_content, -1, NULL));

	r_event_log_setup_logger(logger);

	/* Pre-fill logfile with 128 bytes */
	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	/* search string must be in .1 file */
	g_assert_true(g_file_get_contents(rotatefile, &compare_content, NULL, NULL));
	g_assert_cmpstr(rotate_content, ==, compare_content);
	g_clear_pointer(&compare_content, g_free);

	/* file size was 0, message size is 128 bytes, will rotate on 3rd message */
	logger->writer(logger, fields, G_N_ELEMENTS(fields));
	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	/* search string must be in .2 file (but not in .1) */
	g_assert_true(g_file_get_contents(rotatefile, &compare_content, NULL, NULL));
	g_assert_cmpstr(rotate_content, !=, compare_content);
	g_clear_pointer(&compare_content, g_free);
	g_free(rotatefile);
	rotatefile = g_build_filename(fixture->tmpdir, "testfile.log.2", NULL);
	g_assert_true(g_file_get_contents(rotatefile, &compare_content, NULL, NULL));
	g_assert_cmpstr(rotate_content, ==, compare_content);
	g_clear_pointer(&compare_content, g_free);

	/* file size was 128, message size is 128 bytes, will rotate on 2nd message */
	logger->writer(logger, fields, G_N_ELEMENTS(fields));
	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	/* file size was 128, message size is 128 bytes, will rotate on 2nd message */
	logger->writer(logger, fields, G_N_ELEMENTS(fields));
	logger->writer(logger, fields, G_N_ELEMENTS(fields));

	/* .3 file must not be created and search string must not be in .2 */
	g_assert_true(g_file_get_contents(rotatefile, &compare_content, NULL, NULL));
	g_assert_cmpstr(rotate_content, !=, compare_content);
	g_clear_pointer(&compare_content, g_free);
	g_free(rotatefile);
	rotatefile = g_build_filename(fixture->tmpdir, "testfile.log.3", NULL);
	g_assert_false(g_file_get_contents(rotatefile, &compare_content, NULL, NULL));
}

/* Test setting up a logger, for structured logging and log with g_log_structured */
static void event_log_test_structured_logging(EventLogFixture *fixture,
		gconstpointer user_data)
{
	REventLogger *logger = NULL;
	GLogField fields[] = {
		{"MESSAGE", "This is a test (mark) log message", -1},
		{"PRIORITY", r_event_log_level_to_priority(G_LOG_LEVEL_INFO), -1},
		{"MESSAGE_ID", "1d1b7a5aa9084c3a9004650c9d2ce850", -1},
		{"GLIB_DOMAIN", R_EVENT_LOG_DOMAIN, -1},
		{"RAUC_EVENT_TYPE", "mark", -1},
		{"BUNDLE_HASH", "b970468f-89e4-4793-9904-06c922902b25", -1},
	};
	g_autofree gchar *contents = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);
	logger->events = g_malloc(2 * sizeof(gchar *));
	logger->events[0] = g_strdup("all");
	logger->events[1] = NULL;

	r_event_log_setup_logger(logger);
	/* must be configured */
	r_context()->config->loggers = g_list_append(r_context()->config->loggers, logger);

	/* Write test message */
	g_log_structured_array(G_LOG_LEVEL_INFO, fields, G_N_ELEMENTS(fields));

	g_assert_true(g_file_get_contents(logger->filename, &contents, NULL, NULL));
	g_assert_nonnull(strstr(contents, "This is a test (mark) log message"));
}

/* Test setting up a logger for structured logging and log with r_event_log_message */
static void event_log_test_log_utility(EventLogFixture *fixture,
		gconstpointer user_data)
{
	REventLogger *logger = NULL;
	g_autofree gchar *contents = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);
	logger->events = g_malloc(2 * sizeof(gchar *));
	logger->events[0] = g_strdup("all");
	logger->events[1] = NULL;

	r_event_log_setup_logger(logger);
	/* must be configured */
	r_context()->config->loggers = g_list_append(r_context()->config->loggers, logger);

	/* Write test message */
	r_event_log_message("mark", "Example message: %s", "with arguments");

	g_assert_true(g_file_get_contents(logger->filename, &contents, NULL, NULL));
	g_assert_nonnull(strstr(contents, "Example message: with arguments"));
}

/* Test setting up a logger structured logging for events 'mark' and 'install' and test message filtering */
static void event_log_test_log_filtering(EventLogFixture *fixture,
		gconstpointer user_data)
{
	REventLogger *logger = NULL;
	g_autofree gchar *contents = NULL;

	logger = g_new0(REventLogger, 1);
	logger->name = g_strdup("testlogger");
	logger->filename = g_build_filename(fixture->tmpdir, "testfile.log", NULL);
	logger->events = g_malloc(3 * sizeof(gchar *));
	logger->events[0] = g_strdup("mark");
	logger->events[1] = g_strdup("install");
	logger->events[2] = NULL;

	r_event_log_setup_logger(logger);
	/* must be configured */
	r_context()->config->loggers = g_list_append(r_context()->config->loggers, logger);

	/* Write test messages for different events */
	r_event_log_message("mark", "Example mark message");
	r_event_log_message("boot", "Example boot message");
	r_event_log_message("install", "Example install message");
	r_event_log_message("mark", "Example second mark message");

	g_assert_true(g_file_get_contents(logger->filename, &contents, NULL, NULL));
	g_assert_nonnull(strstr(contents, "Example mark message"));
	g_assert_null(strstr(contents, "Example boot message"));
	g_assert_nonnull(strstr(contents, "Example install message"));
	g_assert_nonnull(strstr(contents, "Example second mark message"));
}

int main(int argc, char *argv[])
{
	RotationTestConfig *rot_test_conf;

	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/event-log/setup-logger", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_setup_logger,
			config_file_fixture_tear_down);
	g_test_add("/event-log/log-writer/simple", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_write_simple,
			config_file_fixture_tear_down);
	g_test_add("/event-log/log-writer/broken", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_write_broken,
			config_file_fixture_tear_down);
	g_test_add("/event-log/log-writer/no-space-left", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_no_space_left,
			config_file_fixture_tear_down);
	g_test_add("/event-log/log-writer/json", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_write_json,
			config_file_fixture_tear_down);

	rot_test_conf = &(RotationTestConfig) {
		.maxsize = 128,
		.rotates_at = 2,
	};
	g_test_add("/event-log/logger-max-size/128", EventLogFixture, rot_test_conf,
			event_log_fixture_set_up, event_log_test_max_size,
			config_file_fixture_tear_down);

	rot_test_conf = &(RotationTestConfig) {
		.maxsize = 129,
		.rotates_at = 2,
	};
	g_test_add("/event-log/logger-max-size/129", EventLogFixture, rot_test_conf,
			event_log_fixture_set_up, event_log_test_max_size,
			config_file_fixture_tear_down);

	rot_test_conf = &(RotationTestConfig) {
		.maxsize = 255,
		.rotates_at = 2,
	};
	g_test_add("/event-log/logger-max-size/255", EventLogFixture, rot_test_conf,
			event_log_fixture_set_up, event_log_test_max_size,
			config_file_fixture_tear_down);
	g_test_add("/event-log/logger-max-files", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_max_files_rotation,
			config_file_fixture_tear_down);

	/* Test writing through structured logging (instead of calling writer directly) */
	/* Logger registration must be called only once, thus call it here */
	g_log_set_writer_func(r_event_log_writer, NULL, NULL);
	g_test_add("/event-log/structured/logging", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_structured_logging,
			config_file_fixture_tear_down);
	g_test_add("/event-log/structured/utility", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_utility,
			config_file_fixture_tear_down);
	g_test_add("/event-log/structured/filtering", EventLogFixture, NULL,
			event_log_fixture_set_up, event_log_test_log_filtering,
			config_file_fixture_tear_down);

	return g_test_run();
}
