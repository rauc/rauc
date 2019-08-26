#include "slot.h"

RaucSlot *find_slot_by_device(GHashTable *slots, const gchar *device)
{
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(device, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->device, device) == 0) {
			goto out;
		}
	}

	slot = NULL;

out:
	return slot;
}

RaucSlot *find_slot_by_bootname(GHashTable *slots, const gchar *bootname)
{
	GHashTableIter iter;
	RaucSlot *slot;

	g_return_val_if_fail(slots, NULL);
	g_return_val_if_fail(bootname, NULL);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->bootname, bootname) == 0) {
			goto out;
		}
	}

	slot = NULL;

out:
	return slot;
}
