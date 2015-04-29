#pragma once

#include <glib.h>
#include <openssl/cms.h>

void signature_init(void);

GBytes *cms_sign(GBytes *content, const gchar *certfile, const gchar *keyfile);
gboolean cms_verify(GBytes *content, GBytes *sig);

GBytes *cms_sign_file(const gchar *filename, const gchar *certfile, const gchar *keyfile);
gboolean cms_verify_file(const gchar *filename, GBytes *sig, gsize limit);
