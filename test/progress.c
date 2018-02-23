#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <locale.h>
#include <context.h>

gint callback_counter;
gint last_percentage;

static void test_progress_callback(gint percentage,
		const gchar *message,
		gint nesting_depth)
{

	/* percentage sanity checks */
	g_assert_cmpint(percentage, >=, 0);
	g_assert_cmpint(percentage, <=, 100);

	g_assert_nonnull(message);
	g_assert_cmpint(percentage, >=, last_percentage);

	callback_counter++;
	last_percentage = percentage;
}

static void progress_test_nesting(void)
{
	RaucProgressStep *step;

	/* reset global state */
	callback_counter = 0;
	last_percentage = 0;

	g_assert_nonnull(r_context()->progress_callback);

	/* test several nested steps */
	r_context_begin_step("test_1", "testing step 1", 1);
	r_context_begin_step("test_1.1", "testing step 1.1", 1);
	r_context_begin_step("test_1.1.1", "testing step 1.1.1", 1);
	r_context_begin_step("test_1.1.1.1", "testing step 1.1.1.1", 2);
	r_context_begin_step("test_1.1.1.1.1", "testing step 1.1.1.1.1", 0);
	g_assert_cmpint(g_list_length(r_context()->progress), ==, 5);
	r_context_end_step("test_1.1.1.1.1", TRUE);

	r_context_begin_step("test_1.1.1.1.2", "testing step 1.1.1.1.2", 0);
	g_assert_cmpint(g_list_length(r_context()->progress), ==, 5);

	/* test RaucProgressStep items in list */
	for (guint i = 0; i < g_list_length(r_context()->progress); i++) {
		step = g_list_nth_data(r_context()->progress, i);

		g_assert_nonnull(step->description);
		g_assert_nonnull(step->name);

		g_assert_cmpint(step->substeps_total, >=, 0);
		g_assert_cmpint(step->substeps_done, >=, 0);
		g_assert_cmpint(step->substeps_done, <=, step->substeps_done);
	}

	r_context_end_step("test_1.1.1.1.2", TRUE);
	r_context_end_step("test_1.1.1.1", TRUE);
	r_context_end_step("test_1.1.1", TRUE);
	r_context_end_step("test_1.1", TRUE);
	r_context_end_step("test_1", TRUE);

	g_assert_cmpint(g_list_length(r_context()->progress), ==, 0);
	g_assert_cmpint(last_percentage, ==, 100);

	/* callback should have been called twice per step */
	g_assert_cmpint(callback_counter, ==, 12);
}

static void progress_test_unsuccessful_substep(void)
{
	/* reset global state */
	callback_counter = 0;
	last_percentage = 0;

	/* test unsuccessful substep */
	r_context_begin_step("test_1", "testing step 1", 1);
	r_context_begin_step("test_1.1", "testing step 1.1", 0);
	r_context_end_step("test_1.1", FALSE);
	r_context_end_step("test_1", TRUE);

	g_assert_cmpint(last_percentage, ==, 100);

	/* callback should have been called twice per step */
	g_assert_cmpint(callback_counter, ==, 4);
}

static void progress_test_explicit_percentage(void)
{
	/* reset global state */
	callback_counter = 0;
	last_percentage = 0;

	/* test setting explicit percentage */
	r_context_begin_step("test_1", "testing step 1", 2);
	r_context_begin_step("test_1.1", "testing step 1.1", 0);
	r_context_end_step("test_1.1", TRUE);
	g_assert_cmpint(last_percentage, ==, 50);

	r_context_begin_step("test_1.2", "testing step 1.2", 0);

	r_context_set_step_percentage("test_1.2", 25);
	g_assert_cmpint(last_percentage, ==, 62);

	r_context_set_step_percentage("test_1.2", 50);
	g_assert_cmpint(last_percentage, ==, 75);

	r_context_set_step_percentage("test_1.2", 75);
	g_assert_cmpint(last_percentage, ==, 87);

	r_context_end_step("test_1.2", TRUE);
	r_context_end_step("test_1", TRUE);
	g_assert_cmpint(last_percentage, ==, 100);

	/* callback gets called twice per step and once per explicit percentage
	 * set
	 */
	g_assert_cmpint(callback_counter, ==, 9);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	/* set up config/context */
	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();

	r_context_register_progress_callback(test_progress_callback);

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/progress/test_nesting", progress_test_nesting);
	g_test_add_func("/progress/test_unsuccessful_substep", progress_test_unsuccessful_substep);
	g_test_add_func("/progress/test_explicit_percentage", progress_test_explicit_percentage);

	return g_test_run();
}
