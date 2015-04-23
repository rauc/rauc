#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include "config_file.h"

typedef struct {
  GKeyFile *key_file;
} ConfigFileFixture;

static void config_file_fixture_set_up(ConfigFileFixture *fixture,
                                       gconstpointer user_data)
{
  fixture->key_file = g_key_file_new();
}

static void config_file_fixture_tear_down(ConfigFileFixture *fixture,
                                          gconstpointer user_data)
{
  g_key_file_free(fixture->key_file);
}

static void config_file_test1(ConfigFileFixture *fixture,
                              gconstpointer user_data)
{
  load_config(NULL);
  g_assert_null(user_data);
}

static void config_file_test2(ConfigFileFixture *fixture,
                              gconstpointer user_data)
{
  load_config(NULL);
  g_assert_null(user_data);
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
