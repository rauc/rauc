#include <config.h>

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include <bootchooser.h>
#include <bundle.h>
#include <config_file.h>
#include <context.h>
#include <install.h>
#include <service.h>

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

	r_exit_status = args->result ? 0 : 1;

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
	g_debug("bundle start");

	if (r_context()->certpath == NULL ||
	    r_context()->keypath == NULL) {
		g_warning("cert and key files must be provided");
		goto out;
	}

	if (argc < 3) {
		g_warning("an input directory name must be provided");
		goto out;
	}

	if (argc != 4) {
		g_warning("an output bundle name must be provided");
		goto out;
	}

	g_print("input directory: %s\n", argv[2]);
	g_print("output bundle: %s\n", argv[3]);

	if (!update_manifest(argv[2], FALSE, NULL)) {
		g_warning("failed to update manifest");
		r_exit_status = 1;
		goto out;
	}

	if (!create_bundle(argv[3], argv[2])) {
		g_warning("failed to create bundle");
		r_exit_status = 1;
		goto out;
	}

out:
	return TRUE;
}

static gboolean checksum_start(int argc, char **argv)
{
	GError *error = NULL;
	gboolean sign = FALSE;

	g_message("checksum start");

	if (r_context()->certpath != NULL &&
	    r_context()->keypath != NULL) {
		sign = TRUE;
	} else if (r_context()->certpath != NULL ||
	    r_context()->keypath != NULL) {
		g_warning("Either both or none of cert and key files must be provided");
		goto out;
	}

	if (argc != 3) {
		g_warning("A directory name must be provided");
		goto out;
	}

	g_message("updating checksums for: %s", argv[2]);

	if (!update_manifest(argv[2], sign, &error)) {
		g_warning("Failed to update manifest: %s", error->message);
		g_clear_error(&error);
		r_exit_status = 1;
	}

out:
	return TRUE;
}

static gboolean info_start(int argc, char **argv)
{
	gsize size;

	g_message("info start");

	if (argc != 3) {
		g_warning("a file name must be provided");
	}

	g_message("checking manifest for: %s", argv[2]);

	if (!check_bundle(argv[2], &size)) {
		g_warning("signature invalid (squashfs size: %"G_GSIZE_FORMAT")", size);
		r_exit_status = 1;
		goto out;
	}

	g_message("signature correct (squashfs size: %"G_GSIZE_FORMAT")", size);

out:
	return TRUE;
}

static gboolean status_start(int argc, char **argv)
{
	GHashTableIter iter;
	gpointer key, value;
	gboolean res = FALSE;
	RaucSlot *booted = NULL;

	g_message("status start\n");

	g_print("booted from: %s\n", get_bootname());

	res = determine_slot_states();
	if (!res) {
		g_warning("Failed to determine slot states");
		goto out;
	}

	g_print("slot states:\n");
	g_hash_table_iter_init(&iter, r_context()->config->slots);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		gchar *name = key;
		RaucSlot *slot = value;
		const gchar *state = NULL;
		switch (slot->state) {
		case ST_ACTIVE:
			state = "active";
			break;
		case ST_INACTIVE:
			state = "inactive";
			break;
		case ST_BOOTED:
			state = "booted";
			booted = slot;
			break;
		case ST_UNKNOWN:
		default:
			g_error("invalid slot status");
			break;
		}
		g_print("  %s: class=%s, device=%s, type=%s, bootname=%s, state=%s\n",
			name, slot->sclass, slot->device, slot->type,
			slot->bootname, state);
	}

	if (argc < 3) {
		goto out;
	}

	if (g_strcmp0(argv[2], "mark-good") == 0) {
		g_print("marking slot %s as good\n", booted->name);
		r_boot_set_state(booted, TRUE);
	} else if (g_strcmp0(argv[2], "mark-bad") == 0) {
		g_print("marking slot %s as bad\n", booted->name);
		r_boot_set_state(booted, FALSE);
	} else {
		g_message("unknown subcommand %s", argv[2]);
	}

out:
	return TRUE;
}

static gboolean service_start(int argc, char **argv)
{
	g_message("service start");

	return r_service_run();
}

static gboolean unknown_start(int argc, char **argv)
{
	g_message("unknown start");

	return TRUE;
}

typedef enum  {
	INSTALL = 0,
	BUNDLE,
	CHECKSUM,
	STATUS,
	INFO,
	SERVICE,
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
	gchar *confpath = NULL, *certpath = NULL, *keypath = NULL, *mount = NULL,
	      *handlerextra = NULL;
	GOptionContext *context = NULL;
	GOptionEntry entries[] = {
		{"conf", 'c', 0, G_OPTION_ARG_FILENAME, &confpath, "config file", "FILENAME"},
		{"cert", '\0', 0, G_OPTION_ARG_FILENAME, &certpath, "cert file", "PEMFILE"},
		{"key", '\0', 0, G_OPTION_ARG_FILENAME, &keypath, "key file", "PEMFILE"},
		{"mount", '\0', 0, G_OPTION_ARG_FILENAME, &mount, "mount prefix", "PATH"},
		{"handler-args", '\0', 0, G_OPTION_ARG_STRING, &handlerextra, "extra handler arguments", "ARGS"},
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
		{SERVICE, "service", "service", service_start, TRUE},
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
		if (handlerextra)
			r_context_conf()->handlerextra = handlerextra;
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
