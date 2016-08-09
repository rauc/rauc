#include <locale.h>
#include <glib.h>

#include "update_handler.h"
#include "manifest.h"

typedef struct {
	gchar *tmpdir;
} UpdateHandlerFixture;

typedef struct {
	// slot type to test for (extension)
	const gchar *slottype;
	// image type to test for (extension)
	const gchar *imagetype;
	// whether test is expected to be successful
	gboolean success;
} UpdateHandlerTestPair;

/* Allows to test several source image / slot type combinations to either have
 * a valid handler or not */
static void test_get_update_handler(UpdateHandlerFixture *fixture, gconstpointer user_data)
{
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;
	UpdateHandlerTestPair *test_pair = (UpdateHandlerTestPair*) user_data;

	image = g_new0(RaucImage, 1);
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strconcat("rootfs.", test_pair->imagetype, NULL);

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_strdup("rootfs.0");
	targetslot->sclass = g_strdup("rootfs");
	targetslot->device = g_strdup("/dev/null");
	targetslot->type = g_strdup(test_pair->slottype);

	handler = get_update_handler(image, targetslot, NULL);
	if (test_pair->success)
		g_assert_nonnull(handler);
	else
		g_assert_null(handler);
}

static void test_get_custom_update_handler(UpdateHandlerFixture *fixture, gconstpointer user_data)
{
	RaucImage *image;
	RaucSlot *targetslot;
	img_to_slot_handler handler;

	image = g_new0(RaucImage, 1);
	image->slotclass = g_strdup("rootfs");
	image->filename = g_strdup("rootfs.custom");
	image->hooks.install = TRUE;

	targetslot = g_new0(RaucSlot, 1);
	targetslot->name = g_strdup("rootfs.0");
	targetslot->sclass = g_strdup("rootfs");
	targetslot->device = g_strdup("/dev/null");
	targetslot->type = g_strdup("nand");

	handler = get_update_handler(image, targetslot, NULL);
	g_assert_nonnull(handler);
}

int main(int argc, char *argv[])
{
	UpdateHandlerTestPair testpair_matrix[] = {
		{"ext4", "tar.bz2", TRUE},
		{"ext4", "ext4", TRUE},
		{"ubifs", "tar.bz2", TRUE},
		{"ubifs", "ext4", FALSE},
		{0}
	};
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add("/update_handler/get_handler/tar_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[0],
			NULL,
			test_get_update_handler,
			NULL);

	g_test_add("/update_handler/get_handler/ext4_to_ext4",
			UpdateHandlerFixture,
			&testpair_matrix[1],
			NULL,
			test_get_update_handler,
			NULL);

	g_test_add("/update_handler/get_handler/tar.bz2_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[2],
			NULL,
			test_get_update_handler,
			NULL);

	g_test_add("/update_handler/get_handler/fail/ext4_to_ubifs",
			UpdateHandlerFixture,
			&testpair_matrix[3],
			NULL,
			test_get_update_handler,
			NULL);

	g_test_add("/update_handler/get_custom_handler",
			UpdateHandlerFixture,
			NULL,
			NULL,
			test_get_custom_update_handler,
			NULL);

	return g_test_run();
}
