#include <locale.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "dm.h"
#include "mount.h"

static void dm_verity_simple_test(void)
{
	GError *error = NULL;
	gboolean res;
	g_autoptr(RaucDMVerity) dm_verity = NULL;
	int datafd = -1;
	int loopfd = -1;
	gchar *loopname = NULL;
	int fd = -1;
	guchar buf[4096];

	/* needs to run as root */
	if (!test_running_as_root())
		return;

	datafd = g_open("test/dummy.verity", O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(datafd, >, 0);

	res = r_setup_loop(datafd, &loopfd, &loopname, 4096*132, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_nonnull(loopname);
	g_close(datafd, NULL);

	dm_verity = new_dm_verity();
	dm_verity->lower_dev = g_strdup(loopname);
	dm_verity->data_size = 4096*129;
	dm_verity->root_digest = g_strdup("3049cbffaa49c6dc12e9cd1dd4604ef5a290e3d13b379c5a50d356e68423de23");
	dm_verity->salt = g_strdup("799ea94008bbdc6555d7895d1b647e2abfd213171f0e8b670e1da951406f4691");

	res = setup_dm_verity(dm_verity, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_close(loopfd, NULL);

	g_assert_nonnull(dm_verity->upper_dev);

	fd = g_open(dm_verity->upper_dev, O_RDONLY|O_CLOEXEC, 0);
	g_assert_cmpint(fd, >, 0);

	res = remove_dm_verity(dm_verity, TRUE, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	for (int i = 0; i<129; i++) {
		int r = read(fd, buf, sizeof(buf));
		g_assert_cmpint(r, ==, 4096);
		g_assert_cmpint(buf[0], ==, 0);
		g_assert_cmpint(buf[1], ==, 0);
		g_assert_cmpint(buf[2], ==, 0);
		g_assert_cmpint(buf[3], ==, i);
	}

	g_close(fd, NULL);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/dm/verity_simple", dm_verity_simple_test);

	return g_test_run();
}
