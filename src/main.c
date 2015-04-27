#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <config.h>
#include <config_file.h>

static gboolean install_start(gpointer data);
static gboolean install_cleanup(gpointer data);

static gboolean install_start(gpointer data)
{
	GApplicationCommandLine *cmdline = data;

	g_application_command_line_print(cmdline, "install started\n");
	g_timeout_add(2000, install_cleanup, data);

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
	gint i;

	g_print("handling command line %p\n", cmdline);

	args = g_application_command_line_get_arguments(cmdline, &argc);

	/* GOptionContext will modify argv, keep the original so we can free
	 * the strings */
	argv = g_new(gchar *, argc + 1);
	for (i = 0; i <= argc; i++)
		argv[i] = args[i];

	context = g_option_context_new(NULL);
	g_option_context_set_help_enabled(context, FALSE);
	g_option_context_add_main_entries(context, entries, NULL);

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
		g_idle_add(install_start, data);
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

int main(int argc, char **argv)
{
	GApplication *app;
	RaucConfig *config = NULL;
	int status;

	/* FIXME load only in the non-remote case */
	load_config("/etc/rauc/system.conf", &config);

	app = g_application_new("de.pengutronix.rauc",
				G_APPLICATION_HANDLES_COMMAND_LINE);
	g_signal_connect(app, "command-line", G_CALLBACK(command_line), NULL);

	status = g_application_run(app, argc, argv);

	g_object_unref(app);

	return status;
}
