#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <bundle.h>
#include <config_file.h>
#include <context.h>
#include <install.h>

GMainLoop *r_loop = NULL;
int r_exit_status = 0;

static gboolean r_quit(gpointer data) {
	if (r_loop)
		g_main_loop_quit(r_loop);
	return G_SOURCE_REMOVE;
}

static gboolean install_notify(gpointer data) {
	RaucInstallArgs *args = data;

	g_message("foo! %s=%d\n", args->name, args->result);

	return G_SOURCE_REMOVE;
}

static gboolean install_cleanup(gpointer data)
{
	RaucInstallArgs *args = data;

	r_exit_status = args->result;

	g_idle_add(r_quit, NULL);

	return G_SOURCE_REMOVE;
}

static gboolean install_start(int argc, char **argv)
{
	RaucInstallArgs *args = g_new0(RaucInstallArgs, 1);

	g_message("install started\n");

	if (argc < 3) {
		g_error("a bundle filename name must be provided");
		goto out;
	}

	g_print("input bundle: %s\n", argv[2]);

	args->name = g_strdup(argv[2]);
	args->notify = install_notify;
	args->cleanup = install_cleanup;

	r_loop = g_main_loop_new(NULL, FALSE);
	install_run(args);
	g_main_loop_run(r_loop);
	g_main_loop_unref(r_loop);


out:
	return TRUE;
}

static gboolean bundle_start(int argc, char **argv)
{
	g_message("bundle start\n");

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_error("cert and key files must be provided");
		goto out;
	}

	if (argc < 3) {
		g_error("an input directory name must be provided");
		goto out;
	}

	if (argc != 4) {
		g_error("an output bundle name must be provided");
		goto out;
	}

	g_print("input directory: %s\n", argv[2]);
	g_print("output bundle: %s\n", argv[3]);

	if (!update_manifest(argv[2], FALSE)) {
		g_print("failed to update manifest\n");
		r_exit_status = 1;
		goto out;
	}

	if (!create_bundle(argv[3], argv[2])) {
		g_print("failed to create bundle\n");
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

static gboolean checksum_start(int argc, char **argv)
{
	gboolean sign = FALSE;

	g_message("checksum start\n");

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
		goto out;
	}

	g_print("updating checksums for: %s\n", argv[2]);

	if (!update_manifest(argv[2], sign)) {
		g_print("failed to update manifest\n");
		r_exit_status = 1;
	}

out:
	return TRUE;
}

static gboolean info_start(int argc, char **argv)
{
	gsize size;

	g_message("info start\n");

	if (argc != 3) {
		g_error("a file name must be provided");
	}

	g_print("checking manifest for: %s\n", argv[2]);

	if (!check_bundle(argv[2], &size)) {
		g_print("signature invalid (squashfs size: %"G_GSIZE_FORMAT")\n", size);
		r_exit_status = 1;
		goto out;
	}

	g_print("signature correct (squashfs size: %"G_GSIZE_FORMAT")\n", size);

out:
	return TRUE;
}

static gboolean status_start(int argc, char **argv)
{
	g_message("status start\n");

	return TRUE;
}

static gboolean unknown_start(int argc, char **argv)
{
	g_message("unknown start\n");

	return TRUE;
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
	gboolean (*cmd_handler) (int argc, char **argv);
	gboolean while_busy;
} RaucCommand;

static void cmdline_handler(int argc, char **argv)
{
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
		g_error("%s\n", error->message);
		g_error_free(error);
		r_exit_status = 1;
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
		g_print(PACKAGE_STRING"\n");
		goto done;
	} else if (help || rcommand->type == UNKNOWN) {
		gchar *text;
		text = g_option_context_get_help(context, FALSE, NULL);
		g_print("%s", text);
		g_free(text);
		goto done;
	}

	/* configuration updates are handled here */
	if (!r_context_get_busy()) {
		r_context_conf();
		if (confpath)
			r_context_conf()->configpath = confpath;
		if (certpath)
			r_context_conf()->certpath = certpath;
		if (keypath)
			r_context_conf()->keypath = keypath;
		if (mount)
			r_context_conf()->mountprefix = mount;
	} else {
		if (confpath != NULL ||
		    certpath != NULL ||
		    keypath != NULL) {
			g_error("rauc busy, cannot reconfigure");
			r_exit_status = 1;
			goto done;
		}
	}

	if (r_context_get_busy() && !rcommand->while_busy) {
		g_error("rauc busy: cannot run %s", rcommand->name);
		r_exit_status = 1;
		goto done;
	}

	/* real commands are handled here */
	if (rcommand->cmd_handler) {
		rcommand->cmd_handler(argc, argv);
		goto done;
	}

done:
	g_clear_pointer(&context, g_option_context_free);;
}

int main(int argc, char **argv) {
	cmdline_handler(argc, argv);

	return r_exit_status;
}
