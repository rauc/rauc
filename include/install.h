#pragma once

#include <glib.h>

#include "manifest.h"

const gchar* get_cmdline_bootname(void);

gboolean determine_slot_states(void);

GList* get_slot_class_members(const gchar* slotclass);
GHashTable* determine_target_install_group(RaucManifest *manifest);

void set_bootname_provider(const gchar* (*provider)(void));

gboolean do_install_bundle(const gchar* bundlelocation);
