#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include "config_file.h"

typedef struct {
  RaucConfig *config;
} ConfigFileFixture;

static void config_file_fixture_set_up(ConfigFileFixture *fixture,
                                       gconstpointer user_data)
{
}

static void config_file_fixture_tear_down(ConfigFileFixture *fixture,
                                          gconstpointer user_data)
{
  g_free(fixture->config);
}

static void config_file_test1(ConfigFileFixture *fixture,
                              gconstpointer user_data)
{
  load_config("test/system.conf", &fixture->config);
  g_assert_nonnull(fixture->config);
  g_assert_cmpstr(fixture->config->system_compatible, ==, "FooCorp Super BarBazzer");
  g_assert_cmpstr(fixture->config->system_bootloader, ==, "barebox");
}

static void config_file_test2(ConfigFileFixture *fixture,
                              gconstpointer user_data)
{
  RaucSlotStatus *ss;
  g_assert_true(load_slot_status("test/rootfs.raucs", &ss));
  g_assert_nonnull(ss);
  g_assert_cmpstr(ss->status, ==, "ok");
  g_assert_cmpint(ss->checksum.type, ==, G_CHECKSUM_SHA256);
  g_assert_cmpstr(ss->checksum.digest, ==,
                  "e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27");
}

int main(int argc, char *argv[])
{
  setlocale(LC_ALL, "");

  g_test_init(&argc, &argv, NULL);

  g_test_add("/config-file/test1", ConfigFileFixture, NULL,
             config_file_fixture_set_up, config_file_test1,
             config_file_fixture_tear_down);

  g_test_add("/config-file/test2", ConfigFileFixture, NULL,
             config_file_fixture_set_up, config_file_test2,
             config_file_fixture_tear_down);

  return g_test_run ();
}
