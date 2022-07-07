#include <locale.h>
#include <glib.h>

#include "stats.h"

static void test_basic(void)
{
	g_autoptr(RaucStats) stats = NULL;

	stats = r_stats_new("test");
	g_assert_nonnull(stats);
	g_assert_cmpstr(stats->label, ==, "test");

	r_stats_add(stats, 1.0);
	r_stats_add(stats, 2.0);

	g_assert_cmpuint(stats->count, ==, 2);
	g_assert_cmpfloat(r_stats_get_avg(stats), ==, 1.5);
	g_assert_cmpfloat(r_stats_get_recent_avg(stats), ==, 1.5);

	for (guint i = 0; i < 128; i++) {
		r_stats_add(stats, i);
	}

	g_assert_cmpuint(stats->count, ==, 130);
	g_assert_cmpfloat(r_stats_get_avg(stats), ==, 62.54615384615385);
	g_assert_cmpfloat(r_stats_get_recent_avg(stats), ==, 95.5);
	g_assert_cmpfloat(stats->sum, ==, 8131.0);
	g_assert_cmpfloat(stats->min, ==, 0.0);
	g_assert_cmpfloat(stats->max, ==, 127.0);
}

static void test_queue(void)
{
	g_autoptr(RaucStats) stats = NULL;

	r_test_stats_start();
	test_basic();
	stats = r_stats_new("test 2");
	g_clear_pointer(&stats, r_stats_free);
	r_test_stats_stop();

	stats = r_test_stats_next();
	g_assert_nonnull(stats);
	g_assert_cmpstr(stats->label, ==, "test");
	g_clear_pointer(&stats, r_stats_free);

	stats = r_test_stats_next();
	g_assert_nonnull(stats);
	g_assert_cmpstr(stats->label, ==, "test 2");
	g_clear_pointer(&stats, r_stats_free);

	r_test_stats_start();
	r_test_stats_stop();
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/stats/basic", test_basic);
	g_test_add_func("/stats/queue", test_queue);

	return g_test_run();
}
