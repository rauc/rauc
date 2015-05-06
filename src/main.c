#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <config.h>
#include <config_file.h>
#include <context.h>
#include <install.h>

static gboolean install_cleanup(gpointer data);

static gboolean install_notify(gpointer data) {
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "foo!\n");

	return FALSE;

}

static gpointer install_thread(gpointer data) {
	GApplicationCommandLine *cmdline = data;

	g_usleep(2*G_USEC_PER_SEC);
	g_application_command_line_print(cmdline, "foo?\n");
	g_main_context_invoke(NULL, install_notify, data);
	g_usleep(20*G_USEC_PER_SEC);
	g_main_context_invoke(NULL, install_cleanup, data);

	return NULL;
}

static gboolean install_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	GThread *thread;
	r_context_set_busy(TRUE);
	g_application_command_line_print(cmdline, "install started\n");

	thread = g_thread_new("installer", install_thread, cmdline);
	g_thread_unref(thread);

	g_print("Active slot bootname: %s\n", get_cmdline_bootname());


	return G_SOURCE_REMOVE;
}

static gboolean install_cleanup(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "install done\n");
	g_application_command_line_set_exit_status(cmdline, 0);

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	r_context_set_busy(FALSE);
	return G_SOURCE_REMOVE;
}

static gboolean bundle_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	g_application_command_line_print(cmdline, "bundle start\n");

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

static gboolean checksum_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	gboolean sign = FALSE;
	int exit_status = 0;

	g_application_command_line_print(cmdline, "checksum start\n");

	if (r_context()->certpath != NULL &&
	    r_context()->keypath != NULL) {
		sign = TRUE;
	} else if (r_context()->certpath != NULL ||
	    r_context()->keypath != NULL) {
		g_error("either both or none of cert and key files must be provided");
		goto out;
	}

	if (argc != 3) {
		g_error("a directory name must be provided");
	}

	g_print("updating checksums for: %s\n", argv[2]);

	if (!update_manifest(argv[2], sign)) {
		exit_status = 1;
	}

out:
	g_application_command_line_set_exit_status(cmdline, exit_status);

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

static gboolean info_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	g_application_command_line_print(cmdline, "info start\n");

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

static gboolean status_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	g_application_command_line_print(cmdline, "status start\n");

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

static gboolean unknown_start(GApplicationCommandLine *cmdline, int argc, char **argv)
{
	g_application_command_line_print(cmdline, "unknown start\n");

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

typedef enum  {
	INSTALL = 0,
	BUNDLE,
	CHECKSUM,
	STATUS,
	INFO,
	UNKNOWN
} RaucCommandType;

typedef struct {
	const RaucCommandType type;
	const gchar* name;
	const gchar* usage;
	gboolean (*cmd_handler) (GApplicationCommandLine *cmdline, int argc, char **argv);
	gboolean while_busy;
} RaucCommand;

static gboolean cmdline_handler(gpointer data)
{
	GApplicationCommandLine *cmdline = data;
	gchar **args = NULL, **argv = NULL;
	gint argc;
	gboolean help = FALSE, version = FALSE;
	gchar *confpath = NULL, *certpath = NULL, *keypath = NULL, *mount = NULL;
	GOptionContext *context = NULL;
	GOptionEntry entries[] = {
		{"conf", 'c', 0, G_OPTION_ARG_FILENAME, &confpath, "config file", "FILENAME"},
		{"cert", '\0', 0, G_OPTION_ARG_FILENAME, &certpath, "cert file", "PEMFILE"},
		{"key", '\0', 0, G_OPTION_ARG_FILENAME, &keypath, "key file", "PEMFILE"},
		{"mount", '\0', 0, G_OPTION_ARG_FILENAME, &mount, "mount prefix", "PATH"},
		{"version", '\0', 0, G_OPTION_ARG_NONE, &version, "display version", NULL},
		{"help", 'h', 0, G_OPTION_ARG_NONE, &help, NULL, NULL},
		{NULL}
	};
	GError *error = NULL;

	RaucCommand rcommands[] = {
		{INSTALL, "install", "install <BUNDLE>", install_start, FALSE},
		{BUNDLE, "bundle", "bundle <FILE>", bundle_start, FALSE},
		{CHECKSUM, "checksum", "checksum <DIRECTORY>", checksum_start, FALSE},
		{INFO, "info", "info <FILE>", info_start, FALSE},
		{STATUS, "status", "status", status_start, TRUE},
		{UNKNOWN, NULL, "<COMMAND>", unknown_start, TRUE}
	};
	RaucCommand *rcommand = &rcommands[UNKNOWN];

	g_print("handling command line %p\n", cmdline);

	args = g_application_command_line_get_arguments(cmdline, &argc);

	/* GOptionContext will modify argv, keep the original so we can free
	 * the strings */
	argv = g_new(gchar *, argc + 1);
	for (gint i = 0; i <= argc; i++) {
		argv[i] = args[i];
	}

	/* show command-specific usage output */
	context = g_option_context_new(rcommand->usage);

	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_set_ignore_unknown_options(context, TRUE);
	g_option_context_add_main_entries(context, entries, NULL);

	if (rcommand->type == UNKNOWN) {
		g_option_context_set_description(context, 
				"List of rauc commands:\n" \
				"  bundle\tCreate a bundle\n" \
				"  checksum\tUpdate a manifest with checksums (and optionally sign it)\n" \
				"  resign\tResign a bundle\n" \
				"  install\tInstall a bundle\n" \
				"  info\t\tShow file information\n" \
				"  status\tShow status");
	}

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_application_command_line_printerr(cmdline, "%s\n",
						    error->message);
		g_error_free(error);
		g_application_command_line_set_exit_status(cmdline, 1);
		goto done;
	}

	/* search for command (first option not starting with '-') */
	for (gint i = 1; i <= argc; i++) {
		RaucCommand *rc = rcommands;

		if (!argv[i] || g_str_has_prefix (argv[i], "-")) {
			continue;
		}

		/* test if known command */
		while (rc->name) {
			if (g_strcmp0(rc->name, argv[i]) == 0) {
				rcommand = rc;
				break;
			}
			rc++;
		}
		break;
	}

	if (version) {
		g_application_command_line_print(cmdline, PACKAGE_STRING "\n");
		goto done;
	} else if (help || rcommand->type == UNKNOWN) {
		gchar *text;
		text = g_option_context_get_help(context, FALSE, NULL);
		g_application_command_line_print(cmdline, "%s", text);
		g_free(text);
		goto done;
	}

	/* configuration updates are handled here */
	if (!r_context_get_busy()) {
		r_context_conf()->configpath = confpath;
		r_context_conf()->certpath = certpath;
		r_context_conf()->keypath = keypath;
		r_context_conf()->mountprefix = mount;
	} else {
		if (confpath != NULL ||
		    certpath != NULL ||
		    keypath != NULL) {
			g_application_command_line_printerr(cmdline,
							    "rauc busy, cannot reconfigure");
			g_application_command_line_set_exit_status(cmdline, 1);
			goto done;
		}
	}

	if (r_context_get_busy() && !rcommand->while_busy) {
		g_application_command_line_printerr(cmdline,
						    "rauc busy: cannot run %s",
						    rcommand->name);
		g_application_command_line_set_exit_status(cmdline, 1);
		goto done;
	}

	/* real commands are handled here */
	if (rcommand->cmd_handler) {
		rcommand->cmd_handler(cmdline, argc, argv);
		goto delegated;
	}

done:
	/* we are done handling this commandline */
	g_object_unref(cmdline);
delegated:
	g_clear_pointer(&argv, g_free);
	g_clear_pointer(&args, g_strfreev);
	g_clear_pointer(&context, g_option_context_free);;
	return G_SOURCE_REMOVE;
}

static int command_line(GApplication *application, GApplicationCommandLine *cmdline)
{
	/* keep the application running until we are done with this commandline */
	g_application_hold(application);

	g_object_set_data_full(G_OBJECT(cmdline),
			       "application", application,
			       (GDestroyNotify) g_application_release);

	g_object_ref(cmdline);
	g_idle_add(cmdline_handler, cmdline);

	return 0;
}

/* Prevents from handling arguments locally as currently all arguments
 * are processed by the remote instance */
static gboolean
handle_local_cmdline (GApplication   *application,
                    gchar        ***arguments,
                    gint           *exit_status)
{
#if 0
	gint i;
#endif
	gchar **argv;

	argv = *arguments;


	/* If first option does not start wiht '-' it is assumed to be
	 * a remote command line call */
	if (argv[1] && !g_str_has_prefix (argv[1], "-")) {
		//g_print("This is a REMOTE command\n");
		return FALSE;
	}

	/* Do local handling here */

#if 0
	/* Dummy eater */
	i = 1;
	while (argv[i]) {
		g_free (argv[i]);
		i++;
	}
#endif

	*exit_status = 0;

	return FALSE;
}

typedef GApplication TestApplication;
typedef GApplicationClass TestApplicationClass;

static GType test_application_get_type (void);
G_DEFINE_TYPE (TestApplication, test_application, G_TYPE_APPLICATION)

static void
test_application_finalize (GObject *object) {
	G_OBJECT_CLASS (test_application_parent_class)->finalize (object);
}

static void
test_application_init (TestApplication *app) {
}

static void
test_application_class_init (TestApplicationClass *class) {
	G_OBJECT_CLASS (class)->finalize = test_application_finalize;
	G_APPLICATION_CLASS (class)->local_command_line = handle_local_cmdline;
}

static GApplication *
test_application_new (const gchar       *application_id,
                      GApplicationFlags  flags) {
	g_return_val_if_fail (g_application_id_is_valid (application_id), NULL);

	return g_object_new (test_application_get_type (),
			"application-id", application_id,
			"flags", flags,
			NULL);
}

int
main (int argc, char **argv) {
	GApplication *app;
	int status;

	app = test_application_new ("de.pengutronix.rauc", G_APPLICATION_HANDLES_COMMAND_LINE);
	//g_application_set_inactivity_timeout (app, 10000);
	g_signal_connect (app, "command-line", G_CALLBACK (command_line), NULL);

	status = g_application_run (app, argc, argv);

	g_object_unref (app);

	return status;
}
