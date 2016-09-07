#pragma once

#include <glib.h>

#include "manifest.h"

#define R_INSTALL_ERROR r_install_error_quark ()
GQuark r_install_error_quark (void);

typedef enum {
	R_INSTALL_ERROR_FAILED,
	R_INSTALL_ERROR_NOSRC,
	R_INSTALL_ERROR_NODST,
	R_INSTALL_ERROR_COMPAT_MISMATCH,
	R_INSTALL_ERROR_REJECTED,
	R_INSTALL_ERROR_MARK_BOOTABLE,
	R_INSTALL_ERROR_MARK_NONBOOTABLE,
	R_INSTALL_ERROR_TARGET_GROUP,
	R_INSTALL_ERROR_DOWNLOAD_MF,
	R_INSTALL_ERROR_HANDLER,
	R_INSTALL_ERROR_NO_SUPPORTED
} RInstallError;

typedef struct {
	gchar *name;
	GSourceFunc notify;
	GSourceFunc cleanup;
	GMutex status_mutex;
	GQueue status_messages;
	gint status_result;
} RaucInstallArgs;

void set_bootname_provider(const gchar* (*provider)(void));
const gchar* get_bootname(void);

gboolean determine_slot_states(GError **error);

GList* get_slot_class_members(const gchar* slotclass);
GHashTable* determine_target_install_group(RaucManifest *manifest);

gboolean do_install_bundle(RaucInstallArgs *args, GError **error);
gboolean do_install_network(const gchar *url, GError **error);


RaucInstallArgs *install_args_new(void);
void install_args_free(RaucInstallArgs *args);

gboolean install_run(RaucInstallArgs *args);
