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
	const gchar *name;
	GSourceFunc notify;
	GSourceFunc cleanup;
	gboolean result;
} RaucInstallArgs;

gboolean install_run(RaucInstallArgs *args);
