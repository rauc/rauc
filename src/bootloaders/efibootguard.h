#pragma once

#include <glib.h>

#include <slot.h>

typedef enum {
	R_EFIBOOTGUARD_USTATE_OK = 0,
	R_EFIBOOTGUARD_USTATE_INSTALLED = 1,
	R_EFIBOOTGUARD_USTATE_TESTING = 2,
	R_EFIBOOTGUARD_USTATE_FAILED = 3,
	/* The unknown state is used internally in efibootguard and is not user-facing */
	R_EFIBOOTGUARD_USTATE_UNKNOWN = 4,
} RaucEfibootguardUstate;

gboolean r_efibootguard_set_state(RaucSlot *slot, gboolean good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_efibootguard_set_primary(RaucSlot *slot, GError **error)
G_GNUC_WARN_UNUSED_RESULT;

RaucSlot *r_efibootguard_get_primary(GError **error)
G_GNUC_WARN_UNUSED_RESULT;

gboolean r_efibootguard_get_state(RaucSlot *slot, gboolean *good, GError **error)
G_GNUC_WARN_UNUSED_RESULT;
