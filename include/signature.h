#pragma once

#include <glib.h>
#include <openssl/cms.h>

GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile);
gboolean cms_verify(GBytes *content, GBytes *sig);
