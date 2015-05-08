#pragma once

#include <glib.h>

typedef struct {
        GChecksumType type;
        gchar *digest;
        gsize size;
} RaucChecksum;

gboolean update_checksum(RaucChecksum *checksum, const gchar *filename);
gboolean verify_checksum(RaucChecksum *checksum, const gchar *filename);
