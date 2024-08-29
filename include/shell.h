#pragma once

#include <glib.h>

#include "manifest.h"

/**
 * Add the meta-data contents from a manifest as newly allocated strings to a
 * GPtrArray, formatted for use as shell variables.
 *
 * This is useful for the 'rauc info' command and hooks/handlers.
 *
 * @param ptrarray GPtrArray to add to
 * @param manifest RaucManifest to use as input
 */
void r_shell_from_manifest_meta(GPtrArray *shell_vars, const RaucManifest *manifest);
