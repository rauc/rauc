#pragma once

#include <glib.h>

#include "manifest.h"

const gchar* get_cmdline_bootname(void);

gboolean determine_slot_states(const gchar* (*bootname_provider)(void));

GList* get_slot_class_members(const gchar* slotclass);
GHashTable* determine_target_install_group(RaucManifest *manifest);

gboolean do_install(const gchar* bundlelocation);
