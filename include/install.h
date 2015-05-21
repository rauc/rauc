#pragma once

#include <glib.h>

#include "manifest.h"

void set_bootname_provider(const gchar* (*provider)(void));
const gchar* get_bootname(void);

gboolean determine_slot_states(void);

GList* get_slot_class_members(const gchar* slotclass);
GHashTable* determine_target_install_group(RaucManifest *manifest);

gboolean do_install_bundle(const gchar* bundlelocation);
gboolean do_install_network(const gchar *url);

typedef struct {
	gchar *name;
	GSourceFunc notify;
	GSourceFunc cleanup;
	GMutex status_mutex;
	GQueue status_messages;
	gint status_result;
} RaucInstallArgs;

RaucInstallArgs *install_args_new(void);
void install_args_free(RaucInstallArgs *args);

gboolean install_run(RaucInstallArgs *args);
