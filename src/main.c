#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <config.h>
#include <config_file.h>
#include <install.h>

static gboolean install_start(gpointer data);
static gboolean install_cleanup(gpointer data);

static gboolean install_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "install started\n");
	g_timeout_add(2000, install_cleanup, data);


	g_print("Active slot bootname: %s\n", get_active_slot_bootname());

	return G_SOURCE_REMOVE;
}

static gboolean install_cleanup(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "install done\n");
	g_application_command_line_set_exit_status(cmdline, 0);

	/* we are done handling this commandline */
	g_object_unref(cmdline);

	return G_SOURCE_REMOVE;
}

static gboolean bundle_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "bundle start\n");
	return G_SOURCE_REMOVE;
}

static gboolean info_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "info start\n");
	return G_SOURCE_REMOVE;
}

static gboolean status_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "status start\n");
	return G_SOURCE_REMOVE;
}

static gboolean unknown_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "unknown start\n");
	return G_SOURCE_REMOVE;
}

typedef enum  {
	INSTALL,
	BUNDLE,
	STATUS,
	INFO,
	UNKNOWN
} RaucCommandType;

typedef struct {
	const RaucCommandType type;
	const gchar* name;
	const gchar* usage;
	gboolean (*cmd_handler) (gpointer user_data);
} RaucCommand;

static gboolean cmdline_handler(gpointer data)
{
	GApplicationCommandLine *cmdline = data;
	gchar **args, **argv;
	gint argc;
	gint arg1 = 0;
	gboolean arg2 = FALSE;
	gboolean help = FALSE, version = FALSE;
	GOptionContext *context;
	GOptionEntry entries[] = {
		{"arg1", 0, 0, G_OPTION_ARG_INT, &arg1, NULL, NULL},
		{"arg2", 0, 0, G_OPTION_ARG_NONE, &arg2, NULL, NULL},
		{"version", '\0', 0, G_OPTION_ARG_NONE, &version, "display version", NULL},
		{"help", '?', 0, G_OPTION_ARG_NONE, &help, NULL, NULL},
		{NULL}
	};
	GError *error;

	RaucCommand rcommands[] = {
		{INSTALL, "install", "install <bundle>", install_start},
		{BUNDLE, "bundle", "bundle <file>", bundle_start},
		{INFO, "info", "info <file>", info_start},
		{STATUS, "status", "status", status_start},
		{UNKNOWN, NULL, "<command>", unknown_start}
	};
	RaucCommand *rcommand = &rcommands[4];

	g_print("handling command line %p\n", cmdline);

	args = g_application_command_line_get_arguments(cmdline, &argc);

	/* GOptionContext will modify argv, keep the original so we can free
	 * the strings */
	argv = g_new(gchar *, argc + 1);
	for (gint i = 0; i <= argc; i++) {
		argv[i] = args[i];
	}


	/* Search for command (first option not starting with '-') */
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

	/* show command-specific usage output */
	context = g_option_context_new(rcommand->usage);

	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_add_main_entries(context, entries, NULL);

	if (rcommand->type == UNKNOWN) {
		g_option_context_set_description(context, 
				"List of rauc commands:\n" \
				"  bundle\tCreate a bundle\n" \
				"  resign\tResign a bundle\n" \
				"  install\tInstall a bundle\n" \
				"  info\t\tShow file information\n" \
				"  status\tShow status");
	}

	error = NULL;
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_application_command_line_printerr(cmdline, "%s\n",
						    error->message);
		g_error_free(error);
		g_application_command_line_set_exit_status(cmdline, 1);
	} else if (help) {
		gchar *text;
		text = g_option_context_get_help(context, FALSE, NULL);
		g_application_command_line_print(cmdline, "%s", text);
		g_free(text);
	} else if (version) {
		g_application_command_line_print(cmdline, PACKAGE_STRING "\n");
	} else {
		if (rcommand->cmd_handler)
			g_idle_add(rcommand->cmd_handler, data);
		goto pending;
	}

	g_free(argv);
	g_strfreev(args);

	g_option_context_free(context);

	/* we are done handling this commandline */
	g_object_unref(cmdline);
pending:
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
	gchar **argv;

	argv = *arguments;


	/* If first option does not start wiht '-' it is assumed to be
	 * a remote command line call */
	if (argv[1] && !g_str_has_prefix (argv[1], "-")) {
		return FALSE;
	}

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

	app = test_application_new ("de.pengutronix.rauc", 0);
	//g_application_set_inactivity_timeout (app, 10000);
	g_signal_connect (app, "command-line", G_CALLBACK (command_line), NULL);

	status = g_application_run (app, argc, argv);

	g_object_unref (app);

	return status;
}
