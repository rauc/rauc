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

/* returns string representation of slot state */
gchar* slotstate_to_str(SlotState slotstate)
{
	gchar *state = NULL;

	switch (slotstate) {
		case ST_ACTIVE:
			state = g_strdup("active");
			break;
		case ST_INACTIVE:
			state = g_strdup("inactive");
			break;
		case ST_BOOTED:
			state = g_strdup("booted");
			break;
		case ST_UNKNOWN:
		default:
			g_error("invalid slot status %d", slotstate);
			break;
	}

	return state;
}

SlotState str_to_slotstate(gchar *str)
{
	if (g_strcmp0(str, "active") == 0) {
		return ST_ACTIVE;
	} else if (g_strcmp0(str, "inactive") == 0) {
		return ST_INACTIVE;
	} else if (g_strcmp0(str, "booted") == 0) {
		return ST_BOOTED;
	}

	return ST_UNKNOWN;
}
