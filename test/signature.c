#include <stdio.h>
#include <locale.h>
#include <glib.h>


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "signature.h"

static GByteArray *read_file(const gchar *filename) {
  gchar *contents;
  gsize length;
  if (!g_file_get_contents(filename, &contents, &length, NULL))
    return NULL;
  return g_byte_array_new_take((guint8 *)contents, length);
}

static void signature_sign(void)
{
  GByteArray *content = read_file("test/openssl-ca/manifest");
  g_assert_nonnull(content);
  g_assert_nonnull(cms_sign(content,
			    "test/openssl-ca/rel/release-1.cert.pem",
                            "test/openssl-ca/rel/private/release-1.pem"));
  g_byte_array_unref(content);
}

static void signature_verify(void)
{
  GByteArray *content = read_file("test/openssl-ca/manifest");
  GByteArray *sig = read_file("test/openssl-ca/manifest-r1.sig");
  g_assert_nonnull(content);
  g_assert_nonnull(sig);
  g_assert_true(cms_verify(content, sig));
  g_byte_array_unref(content);
  g_byte_array_unref(sig);
}

int main(int argc, char *argv[])
{
  setlocale(LC_ALL, "");

  OPENSSL_no_config();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/signature/sign", signature_sign);
  g_test_add_func("/signature/verify", signature_verify);

  return g_test_run ();
}
