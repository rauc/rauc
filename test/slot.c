#include <glib.h>
#include <locale.h>

#include <slot.h>

static void test_slot_get_all_children(void)
{
	g_autoptr(GHashTable) slots = NULL;
	RaucSlot *rootfs_0 = NULL;
	RaucSlot *rootfs_1 = NULL;
	RaucSlot *appfs_1 = NULL;
	RaucSlot *datafs_2 = NULL;
	RaucSlot *somefs_0 = NULL;
	RaucSlot *somefs_1 = NULL;
	GList *child_slots = NULL;

	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);

	/* create a hierarchy of:
	 *   rootfs.0 <- appfs.1 <- datafs.2
	 *            <- somefs.0
	 *   rootfs.1 <- somefs.1
	 */
	rootfs_0 = g_new0(RaucSlot, 1);
	rootfs_0->name = g_intern_string("rootfs.0");
	g_hash_table_insert(slots, (gchar*)rootfs_0->name, rootfs_0);
	rootfs_1 = g_new0(RaucSlot, 1);
	rootfs_1->name = g_intern_string("rootfs.1");
	g_hash_table_insert(slots, (gchar*)rootfs_1->name, rootfs_1);
	appfs_1 = g_new0(RaucSlot, 1);
	appfs_1->name = g_intern_string("appfs.1");
	appfs_1->parent = rootfs_0;
	g_hash_table_insert(slots, (gchar*)appfs_1->name, appfs_1);
	datafs_2 = g_new0(RaucSlot, 1);
	datafs_2->name = g_intern_string("datafs.2");
	datafs_2->parent = appfs_1;
	g_hash_table_insert(slots, (gchar*)datafs_2->name, datafs_2);
	somefs_0 = g_new0(RaucSlot, 1);
	somefs_0->name = g_intern_string("somefs.0");
	somefs_0->parent = rootfs_0;
	g_hash_table_insert(slots, (gchar*)somefs_0->name, somefs_0);
	somefs_1 = g_new0(RaucSlot, 1);
	somefs_1->name = g_intern_string("somefs.1");
	somefs_1->parent = rootfs_1;
	g_hash_table_insert(slots, (gchar*)somefs_1->name, somefs_1);

	/* test if rootfs.0 has children appfs.1, datafs.2, somefs.0 */
	child_slots = r_slot_get_all_children(slots, rootfs_0);

	g_assert_nonnull(child_slots);
	g_assert_false(r_slot_list_contains(child_slots, rootfs_0));
	g_assert_false(r_slot_list_contains(child_slots, rootfs_1));
	g_assert_false(r_slot_list_contains(child_slots, somefs_1));
	g_assert_true(r_slot_list_contains(child_slots, appfs_1));
	g_assert_true(r_slot_list_contains(child_slots, datafs_2));
	g_assert_true(r_slot_list_contains(child_slots, somefs_0));
	g_assert_cmpint(g_list_length(child_slots), ==, 3);
}

static void test_slot_get_all_of_class(void)
{
	g_autoptr(GHashTable) slots = NULL;
	RaucSlot *rootfs_0 = NULL;
	RaucSlot *datafs_0 = NULL;
	RaucSlot *datafs_1 = NULL;
	GList *class_slots = NULL;

	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);

	/* create the slots 'rootfs.0', 'datafs.0', 'datafs.1' with their
	 * correct class information */
	rootfs_0 = g_new0(RaucSlot, 1);
	rootfs_0->name = g_intern_string("rootfs.0");
	rootfs_0->sclass = g_intern_string("rootfs");
	g_hash_table_insert(slots, (gchar*)rootfs_0->name, rootfs_0);
	datafs_0 = g_new0(RaucSlot, 1);
	datafs_0->name = g_intern_string("datafs.0");
	datafs_0->sclass = g_intern_string("datafs");
	g_hash_table_insert(slots, (gchar*)datafs_0->name, datafs_0);
	datafs_1 = g_new0(RaucSlot, 1);
	datafs_1->name = g_intern_string("datafs.1");
	datafs_1->sclass = g_intern_string("datafs");
	g_hash_table_insert(slots, (gchar*)datafs_1->name, datafs_1);

	class_slots = r_slot_get_all_of_class(slots, "datafs");

	g_assert_nonnull(class_slots);
	g_assert_false(r_slot_list_contains(class_slots, rootfs_0));
	g_assert_true(r_slot_list_contains(class_slots, datafs_0));
	g_assert_true(r_slot_list_contains(class_slots, datafs_1));
	g_assert_cmpint(g_list_length(class_slots), ==, 2);

}

static gboolean string_array_contains(gchar **array, const gchar *searchstring)
{
	for (gchar **current = array; *current != NULL; current++) {
		if (g_strcmp0(*current, searchstring) == 0)
			return TRUE;
	}

	return FALSE;
}

static void test_slot_get_root_classes(void)
{
	g_autoptr(GHashTable) slots = NULL;
	RaucSlot *rootfs_0 = NULL;
	RaucSlot *rootfs_1 = NULL;
	RaucSlot *appfs_1 = NULL;
	RaucSlot *datafs_2 = NULL;
	RaucSlot *somefs_0 = NULL;
	RaucSlot *somefs_1 = NULL;
	RaucSlot *boot_0 = NULL;
	gchar** root_classes = NULL;

	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);

	/* create a hierarchy of:
	 *   rootfs.0 <- appfs.1 <- datafs.2
	 *            <- somefs.0
	 *   rootfs.1 <- somefs.1
	 *   boot.0
	 */
	rootfs_0 = g_new0(RaucSlot, 1);
	rootfs_0->name = g_intern_string("rootfs.0");
	rootfs_0->sclass = g_intern_string("rootfs");
	g_hash_table_insert(slots, (gchar*)rootfs_0->name, rootfs_0);
	rootfs_1 = g_new0(RaucSlot, 1);
	rootfs_1->name = g_intern_string("rootfs.1");
	rootfs_1->sclass = g_intern_string("rootfs");
	g_hash_table_insert(slots, (gchar*)rootfs_1->name, rootfs_1);
	appfs_1 = g_new0(RaucSlot, 1);
	appfs_1->name = g_intern_string("appfs.1");
	appfs_1->sclass = g_intern_string("appfs");
	appfs_1->parent = rootfs_0;
	g_hash_table_insert(slots, (gchar*)appfs_1->name, appfs_1);
	datafs_2 = g_new0(RaucSlot, 1);
	datafs_2->name = g_intern_string("datafs.2");
	datafs_2->sclass = g_intern_string("datafs");
	datafs_2->parent = appfs_1;
	g_hash_table_insert(slots, (gchar*)datafs_2->name, datafs_2);
	somefs_0 = g_new0(RaucSlot, 1);
	somefs_0->name = g_intern_string("somefs.0");
	somefs_0->sclass = g_intern_string("somefs");
	somefs_0->parent = rootfs_0;
	g_hash_table_insert(slots, (gchar*)somefs_0->name, somefs_0);
	somefs_1 = g_new0(RaucSlot, 1);
	somefs_1->name = g_intern_string("somefs.1");
	somefs_1->sclass = g_intern_string("somefs");
	somefs_1->parent = rootfs_1;
	g_hash_table_insert(slots, (gchar*)somefs_1->name, somefs_1);
	boot_0 = g_new0(RaucSlot, 1);
	boot_0->name = g_intern_string("boot.0");
	boot_0->sclass = g_intern_string("boot");
	g_hash_table_insert(slots, (gchar*)boot_0->name, boot_0);

	root_classes = r_slot_get_root_classes(slots);

	g_assert_nonnull(root_classes);
	g_assert_true(string_array_contains(root_classes, "rootfs"));
	g_assert_true(string_array_contains(root_classes, "boot"));
	g_assert_false(string_array_contains(root_classes, "datafs"));
	g_assert_false(string_array_contains(root_classes, "somefs"));
	g_assert_false(string_array_contains(root_classes, "appfs"));
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/slot/get-all-children", test_slot_get_all_children);
	g_test_add_func("/slot/get-all-of-class", test_slot_get_all_of_class);
	g_test_add_func("/slot/get-root-classes", test_slot_get_root_classes);

	return g_test_run();
}
