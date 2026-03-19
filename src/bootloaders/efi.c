#include "efi.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define EFIBOOTMGR_NAME "efibootmgr"

typedef struct {
	gchar *num;
	gchar *name;
	gboolean active;
} efi_bootentry;

static void efi_bootentry_free(efi_bootentry *entry)
{
	if (!entry)
		return;

	g_free(entry->num);
	g_free(entry->name);
	g_free(entry);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(efi_bootentry, efi_bootentry_free);

static gboolean efi_bootentry_create(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot->bootname, FALSE);
	g_return_val_if_fail(slot->efi_loader, FALSE);
	g_return_val_if_fail(slot->efi_cmdline, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autofree gchar *realdev = r_realpath(slot->device);
	if (realdev == NULL) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Can't resolve device %s for EFI boot entry",
				slot->device);
		return FALSE;
	}

	g_autofree gchar *realdev_basename = g_path_get_basename(realdev);
	/* use /sys/class/block because it contains partition entries */
	g_autofree gchar *sysfs_part_path = g_build_filename("/sys/class/block", realdev_basename, "partition", NULL);
	g_autofree gchar *part_num = NULL;
	if (!g_file_get_contents(sysfs_part_path, &part_num, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* File contains newline, modify in-place */
	g_strchomp(part_num);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			EFIBOOTMGR_NAME,
			"--create-only",
			"--disk", realdev,
			"--part", part_num,
			"--label", slot->bootname,
			"--loader", slot->efi_loader,
			"--unicode", slot->efi_cmdline,
			NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	g_debug("Created missing EFI boot entry for %s", slot->bootname);

	return TRUE;
}

static gboolean efi_bootorder_set(gchar *order, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(order, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			EFIBOOTMGR_NAME,
			"--bootorder",
			order,
			NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

static gboolean efi_set_bootnext(gchar *bootnumber, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(bootnumber, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_NONE,
			&ierror,
			EFIBOOTMGR_NAME,
			"--bootnext",
			bootnumber,
			NULL);

	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

static efi_bootentry *get_efi_entry_by_bootnum(GList *entries, const gchar *bootnum)
{
	g_return_val_if_fail(entries, NULL);
	g_return_val_if_fail(bootnum, NULL);

	efi_bootentry *found_entry = NULL;
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *ptr = entry->data;
		if (g_strcmp0(bootnum, ptr->num) == 0) {
			found_entry = ptr;
			break;
		}
	}

	return found_entry;
}

/* Parses output of efibootmgr and returns information obtained.
 *
 * Note that this function can return two lists, pointing to the same elements.
 * The allocated efi_bootentry structs are owned by the all_entries list, so
 * that parameter is mandatory.
 *
 * @param bootorder_entries Return location for List (of efi_bootentry
 *        elements) of slots that are currently in EFI 'BootOrder'
 * @param all_entries Return location for List (of efi_bootentry element) of
 *        all EFI boot entries
 * @param bootnext Return location for EFI boot slot currently selected as
 *        'BootNext' (if any)
 * @param error Return location for a GError
 */
static gboolean efi_bootorder_get(GList **bootorder_entries, GList **all_entries, efi_bootentry **bootnext, efi_bootentry **bootcurrent, GError **error)
{
	GError *ierror = NULL;
	gint ret;

	g_return_val_if_fail(bootorder_entries == NULL || *bootorder_entries == NULL, FALSE);
	g_return_val_if_fail(all_entries != NULL && *all_entries == NULL, FALSE);
	g_return_val_if_fail(bootnext == NULL || *bootnext == NULL, FALSE);
	g_return_val_if_fail(bootcurrent == NULL || *bootcurrent == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GSubprocess) sub = r_subprocess_new(
			G_SUBPROCESS_FLAGS_STDOUT_PIPE,
			&ierror,
			EFIBOOTMGR_NAME,
			NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " EFIBOOTMGR_NAME ": ");
		return FALSE;
	}

	g_autoptr(GBytes) stdout_bytes = NULL;
	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				EFIBOOTMGR_NAME " communication failed: ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				EFIBOOTMGR_NAME " did not exit normally");
		return FALSE;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				EFIBOOTMGR_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	g_autofree gchar *stdout_str = r_bytes_unref_to_string(&stdout_bytes);

	/* Obtain mapping of efi boot numbers to bootnames */
	g_autoptr(GRegex) regex = g_regex_new("^Boot([0-9a-fA-F]{4})[\\* ] (.+)$", G_REGEX_MULTILINE, 0, NULL);
	g_autoptr(GMatchInfo) match = NULL;
	if (!g_regex_match(regex, stdout_str, 0, &match)) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Regex matching failed!");
		return FALSE;
	}

	g_autolist(efi_bootentry) entries = NULL;
	while (g_match_info_matches(match)) {
		gchar *tab_point = NULL;
		efi_bootentry *entry = g_new0(efi_bootentry, 1);
		entry->num = g_match_info_fetch(match, 1);
		entry->name = g_match_info_fetch(match, 2);

		/* Remove anything after a tab, as it is most likely path
		 * information which we don't need */
		tab_point = strchr(entry->name, '\t');
		if (tab_point)
			*tab_point = '\0';

		entries = g_list_append(entries, entry);
		g_match_info_next(match, NULL);
		g_debug("Detected EFI boot entry %s: %s", entry->num, entry->name);
	}

	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	/* Obtain bootnext */
	regex = g_regex_new("^BootNext: ([0-9a-fA-F]{4})$", G_REGEX_MULTILINE, 0, NULL);
	g_autofree gchar *matched = NULL;
	if (g_regex_match(regex, stdout_str, 0, &match)) {
		if (bootnext) {
			g_clear_pointer(&matched, g_free);
			matched = g_match_info_fetch(match, 1);
			*bootnext = get_efi_entry_by_bootnum(entries, matched);
		}
	}

	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	/* Obtain bootorder */
	regex = g_regex_new("^BootOrder: (\\S+)$", G_REGEX_MULTILINE, 0, NULL);
	if (!g_regex_match(regex, stdout_str, 0, &match)) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"unable to obtain boot order!");
		return FALSE;
	}

	g_clear_pointer(&matched, g_free);
	matched = g_match_info_fetch(match, 1);
	g_auto(GStrv) bootnumorder = g_strsplit(matched, ",", 0);

	/* Iterate over boot entries list in bootorder */
	g_autoptr(GList) returnorder = NULL;
	for (gchar **element = bootnumorder; *element; element++) {
		efi_bootentry *bentry = get_efi_entry_by_bootnum(entries, *element);
		if (bentry)
			returnorder = g_list_append(returnorder, bentry);
	}

	g_clear_pointer(&regex, g_regex_unref);
	g_clear_pointer(&match, g_match_info_free);

	/* Obtain boot current */
	regex = g_regex_new("^BootCurrent: ([0-9a-fA-F]{4})$", G_REGEX_MULTILINE, 0, NULL);
	if (g_regex_match(regex, stdout_str, 0, &match)) {
		if (bootcurrent) {
			g_clear_pointer(&matched, g_free);
			matched = g_match_info_fetch(match, 1);
			*bootcurrent = get_efi_entry_by_bootnum(entries, matched);
		}
	}

	if (bootorder_entries)
		*bootorder_entries = g_steal_pointer(&returnorder);
	*all_entries = g_steal_pointer(&entries);

	return TRUE;
}

/* Parses output of efibootmgr and returns information obtained, creating
 * missing EFI boot entry for slot.
 *
 * Wrapper around efi_bootorder_get() that creates a missing EFI boot entry for
 * the provided RAUC slot if efi-loader and efi-cmdline are configured.
 *
 * @param slot The RAUC slot to create a EFI boot entry for if it's missing
 * @param bootorder_entries See efi_bootorder_get()
 * @param all_entries See efi_bootorder_get()
 * @param error Return location for a GError
 */
static gboolean efi_bootorder_prepare(RaucSlot *slot, GList **bootorder_entries, GList **all_entries, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(bootorder_entries == NULL || *bootorder_entries == NULL, FALSE);
	g_return_val_if_fail(all_entries != NULL && *all_entries == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_bootorder_get(bootorder_entries, all_entries, NULL, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Lookup efi boot entry matching slot */
	for (GList *entry = *all_entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		if (g_strcmp0(efi->name, slot->bootname) == 0) {
			/* EFI boot entry exists, no further action needed */
			g_debug("EFI boot entry for bootname '%s' already exists", slot->bootname);
			return TRUE;
		}
	}

	/* Clear previously retrieved entries */
	if (*all_entries)
		g_list_free_full(g_steal_pointer(all_entries), (GDestroyNotify)efi_bootentry_free);
	if (bootorder_entries && *bootorder_entries)
		g_list_free(g_steal_pointer(bootorder_entries));

	/* No efi-loader/efi-cmdline given, bail out */
	if (!slot->efi_loader || !slot->efi_cmdline) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_FAILED,
				"Did not find efi entry for bootname '%s'!", slot->bootname);
		return FALSE;
	}


	/* Create missing EFI entry */
	if (!efi_bootentry_create(slot, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Retrieve EFI entries one more time */
	if (!efi_bootorder_get(bootorder_entries, all_entries, NULL, NULL, error)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

static gboolean efi_set_temp_primary(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autolist(efi_bootentry) entries = NULL;
	if (!efi_bootorder_prepare(slot, NULL, &entries, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Lookup efi boot entry matching slot */
	efi_bootentry *efi_slot_entry = NULL;
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		if (g_strcmp0(efi->name, slot->bootname) == 0) {
			efi_slot_entry = efi;
			break;
		}
	}

	/* efi_bootorder_prepare() above made sure a proper entry exists */
	g_assert_nonnull(efi_slot_entry);

	if (!efi_set_bootnext(efi_slot_entry->num, &ierror)) {
		g_propagate_prefixed_error(error, ierror, "Setting bootnext failed: ");
		return FALSE;
	}

	return TRUE;
}

/* Deletes given slot from efi bootorder list.
 * Prepends it to bootorder list if prepend argument is set to TRUE */
static gboolean efi_modify_persistent_bootorder(RaucSlot *slot, gboolean prepend, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GList) entries = NULL;
	g_autolist(efi_bootentry) all_entries = NULL;
	if (!efi_bootorder_prepare(slot, &entries, &all_entries, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Iterate over bootorder list until reaching boot entry to remove (if available) */
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		if (g_strcmp0(efi->name, slot->bootname) == 0) {
			entries = g_list_remove(entries, efi);
			break;
		}
	}

	if (prepend) {
		/* Iterate over full list to get entry to prepend to bootorder */
		efi_bootentry *efi_slot_entry = NULL;
		for (GList *entry = all_entries; entry != NULL; entry = entry->next) {
			efi_bootentry *efi = entry->data;
			if (g_strcmp0(efi->name, slot->bootname) == 0) {
				efi_slot_entry = efi;
				break;
			}
		}

		/* efi_bootorder_prepare() above made sure a proper entry exists */
		g_assert_nonnull(efi_slot_entry);

		entries = g_list_prepend(entries, efi_slot_entry);
	}

	/* Construct bootorder string out of boot entry list */
	g_autoptr(GPtrArray) bootorder = g_ptr_array_sized_new(g_list_length(entries));
	for (GList *entry = entries; entry != NULL; entry = entry->next) {
		efi_bootentry *efi = entry->data;
		g_ptr_array_add(bootorder, efi->num);
	}
	g_ptr_array_add(bootorder, NULL);

	g_autofree gchar *order = g_strjoinv(",", (gchar**)bootorder->pdata);

	if (!efi_bootorder_set(order, NULL)) {
		g_propagate_prefixed_error(error, ierror, "Modifying bootorder failed: ");
		return FALSE;
	}

	return TRUE;
}

gboolean r_efi_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!efi_modify_persistent_bootorder(slot, good, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

RaucSlot *r_efi_get_primary(GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GList) bootorder_entries = NULL;
	g_autolist(efi_bootentry) all_entries = NULL;
	efi_bootentry *bootnext = NULL;
	if (!efi_bootorder_get(&bootorder_entries, &all_entries, &bootnext, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* We prepend the content of BootNext if set */
	if (bootnext) {
		g_debug("Detected BootNext set to %s", bootnext->name);
		bootorder_entries = g_list_prepend(bootorder_entries, bootnext);
	}

	RaucSlot *primary = NULL;
	for (GList *entry = bootorder_entries; entry != NULL; entry = entry->next) {
		efi_bootentry *bootentry = entry->data;

		/* Find matching slot entry */
		GHashTableIter iter;
		g_hash_table_iter_init(&iter, r_context()->config->slots);
		RaucSlot *slot = NULL;
		while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
			if (g_strcmp0(bootentry->name, slot->bootname) == 0) {
				primary = slot;
				break;
			}
		}

		if (primary)
			break;
	}

	if (!primary) {
		g_set_error(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Did not find primary boot entry!");
		return NULL;
	}

	return primary;
}

gboolean r_efi_set_primary(RaucSlot *slot, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (r_context()->config->efi_use_bootnext) {
		if (!efi_set_temp_primary(slot, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		return TRUE;
	}

	if (!efi_modify_persistent_bootorder(slot, TRUE, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* We assume bootstate to be good if slot is listed in 'bootorder', otherwise
 * bad */
gboolean r_efi_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_autoptr(GList) bootorder_entries = NULL;
	g_autolist(efi_bootentry) all_entries = NULL;
	if (!efi_bootorder_get(&bootorder_entries, &all_entries, NULL, NULL, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Scan bootorder list for given slot */
	efi_bootentry *found_entry = NULL;
	for (GList *entry = bootorder_entries; entry != NULL; entry = entry->next) {
		efi_bootentry *ptr = entry->data;
		if (g_strcmp0(slot->bootname, ptr->name) == 0) {
			found_entry = ptr;
			break;
		}
	}

	*good = found_entry ? TRUE : FALSE;

	return TRUE;
}

gchar *r_efi_get_current_bootname(RaucConfig *config, GError **error)
{
	GError *ierror = NULL;

	g_autolist(efi_bootentry) all_entries = NULL;
	efi_bootentry *bootcurrent = NULL;
	if (!efi_bootorder_get(NULL, &all_entries, NULL, &bootcurrent, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, config->slots);
	RaucSlot *slot = NULL;
	while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
		if (g_strcmp0(slot->bootname, bootcurrent->name) == 0) {
			return slot->bootname;
		}
	}

	g_set_error(error,
			R_BOOTCHOOSER_ERROR,
			R_BOOTCHOOSER_ERROR_FAILED,
			"Current EFI bootentry not known to rauc!");

	return NULL;
}
