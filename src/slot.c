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

typedef struct {
	const gchar *name;
	gboolean mountable;
} RaucSlotType;

RaucSlotType supported_slot_types[] = {
	{"raw", FALSE},
	{"ext4", TRUE},
	{"ubifs", TRUE},
	{"ubivol", FALSE},
	{"nand", FALSE},
	{"vfat", TRUE},
	{}
};

gboolean is_slot_mountable(RaucSlot *slot)
{
	for (RaucSlotType *slot_type = supported_slot_types; slot_type->name != NULL; slot_type++) {
		if (g_strcmp0(slot->type, slot_type->name) == 0) {
			return slot_type->mountable;
		}
	}

	return FALSE;
}

RaucSlot* get_parent_root_slot(RaucSlot *slot)
{
	RaucSlot *base = NULL;

	g_return_val_if_fail(slot, NULL);

	base = slot;
	while (base != NULL && base->parent != NULL)
		base = base->parent;

	return base;
}

gchar** get_root_system_slot_classes(GHashTable *slots)
{
	GPtrArray *slotclasses = NULL;
	GHashTableIter iter;
	RaucSlot *iterslot = NULL;

	g_return_val_if_fail(slots, NULL);

	slotclasses = g_ptr_array_new();

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &iterslot)) {
		const gchar *key = NULL;

		g_assert_nonnull(iterslot->sclass);

		if (iterslot->parent)
			continue;

		key = g_intern_string(iterslot->sclass);
		g_ptr_array_remove_fast(slotclasses, (gpointer)key); /* avoid duplicates */
		g_ptr_array_add(slotclasses, (gpointer)key);
	}
	g_ptr_array_add(slotclasses, NULL);

	return (gchar**) g_ptr_array_free(slotclasses, FALSE);
}
