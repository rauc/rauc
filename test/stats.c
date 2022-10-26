#include <locale.h>
#include <glib.h>

#include "stats.h"

/* APPROX_VALUE exists in glib >= 2.58 */
#ifndef G_APPROX_VALUE
#define G_APPROX_VALUE(a, b, epsilon) \
	(((a) > (b) ? (a) - (b) : (b) - (a)) < (epsilon))
#endif

/* g_assert_cmpfloat_with_epsilon exists in glib >= 2.58 */
#ifndef g_assert_cmpfloat_with_epsilon
#define g_assert_cmpfloat_with_epsilon(n1, n2, epsilon) \
	G_STMT_START { \
		double __n1 = (n1), __n2 = (n2), __epsilon = (epsilon); \
		if (G_APPROX_VALUE(__n1,  __n2, __epsilon)); else \
		g_assertion_message_cmpnum(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		#n1 " == " #n2 " (+/- " #epsilon ")", __n1, "==", __n2, 'f'); \
	} G_STMT_END
#endif

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

	/*
	 * Don't use an exact compare on non-trivial floating-point
	 * calculations.
	 */
	g_assert_cmpfloat_with_epsilon(r_stats_get_avg(stats), 62.54615384615385, 1e-10);
	g_assert_cmpfloat_with_epsilon(r_stats_get_recent_avg(stats), 95.5, 1e-10);
	g_assert_cmpfloat_with_epsilon(stats->sum, 8131.0, 1e-10);
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
