#pragma once

#include <glib.h>
#include <openssl/cms.h>

GByteArray *cms_sign(GByteArray *content, const gchar *certfile, const gchar *keyfile);
gboolean cms_verify(GByteArray *content, GByteArray *sig);
