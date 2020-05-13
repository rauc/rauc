#include <glib/gstdio.h>
#include <unistd.h>

#include <libfdisk/libfdisk.h>

#include "gpt.h"
#include "update_handler.h"

/* partition entry in GPT partition table, the system boots from */
#define BOOT_PARTITION_ENTRY		0

static int ask_cb(struct fdisk_context *cxt, struct fdisk_ask *ask, void *data)
{
	switch (fdisk_ask_get_type(ask)) {
		case FDISK_ASKTYPE_INFO:
			g_info("libfdisk: %s", fdisk_ask_print_get_mesg(ask));
			break;
		case FDISK_ASKTYPE_WARNX:
			g_warning("libfdisk: %s", fdisk_ask_print_get_mesg(ask));
			break;
		case FDISK_ASKTYPE_WARN:
			g_warning("libfdisk: %s: %s", fdisk_ask_print_get_mesg(ask), strerror(fdisk_ask_print_get_errno(ask)));
			break;
		default:
			break;
	}
	return 0;
}

static struct fdisk_context *get_context(void)
{
	struct fdisk_context *cxt = NULL;

	fdisk_init_debug(0);

	cxt = fdisk_new_context();
	if (!cxt)
		g_error("%s: Failed to allocate libfdisk context\n", G_STRLOC);

	fdisk_disable_dialogs(cxt, 1);
	fdisk_set_ask(cxt, ask_cb, NULL);

	return cxt;
}

static gboolean check_gpt(struct fdisk_context *cxt,
		GError **error)
{
	gulong grain_size, sector_size;

	g_return_val_if_fail(cxt, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	grain_size = fdisk_get_grain_size(cxt);
	sector_size = fdisk_get_sector_size(cxt);

	if (grain_size < sector_size)
		g_error("%s: libfdisk reported grain size is less than sector size", G_STRLOC);

	if (fdisk_get_collision(cxt)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Partition table collision found: %s",
				fdisk_get_collision(cxt));
		return FALSE;
	}
	if (!fdisk_is_labeltype(cxt, FDISK_DISKLABEL_GPT)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"GPT not found");
		return FALSE;
	}
	if (fdisk_gpt_is_hybrid(cxt)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Hybrid GPT is not supported, use a protective MBR instead");
		return FALSE;
	}
	if (fdisk_get_alignment_offset(cxt) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Non-zero aligment offset (%ld) is not supported",
				fdisk_get_alignment_offset(cxt));
		return FALSE;
	}

	return TRUE;
}

static gboolean check_region(struct fdisk_context *cxt,
		guint64 region_start, guint64 region_size,
		GError **error)
{
	gboolean res = FALSE, found = FALSE;
	guint64 grain_size, sector_size;
	struct fdisk_table *tb = NULL;
	struct fdisk_iter *itr = NULL;
	struct fdisk_partition *pa = NULL;
	fdisk_sector_t number_of_sectors;
	fdisk_sector_t region_start_sector, region_end_sector;

	g_return_val_if_fail(cxt, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	grain_size = fdisk_get_grain_size(cxt);
	sector_size = fdisk_get_sector_size(cxt);
	number_of_sectors = fdisk_get_nsectors(cxt);

	if (region_start < 34*512 || region_size == 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region configuration is invalid");
		goto out;
	}

	if ((region_start % grain_size) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region start %"G_GINT64_MODIFIER "d is not aligned to grain-size %"G_GINT64_MODIFIER "d",
				region_start, grain_size);
		goto out;
	}

	if ((region_size % (2 * grain_size)) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region size %"G_GINT64_MODIFIER "d is not aligned to the double grain-size %"G_GINT64_MODIFIER "d",
				region_size, 2 * grain_size);
		goto out;
	}

	if (region_start / sector_size >= number_of_sectors) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region starts beyond end of block device");
		goto out;
	}

	if ((region_start + region_size) / sector_size >= number_of_sectors) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Region ends beyond end of block device");
		goto out;
	}

	region_start_sector = region_start / sector_size;
	region_end_sector = region_start_sector + region_size / sector_size - 1;

	if (fdisk_get_partitions(cxt, &tb)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to get partitions");
		goto out;
	}

	itr = fdisk_new_iter(FDISK_ITER_FORWARD);
	if (!itr)
		g_error("%s: Failed to allocate libfdisk iter\n", G_STRLOC);
	while (fdisk_table_next_partition(tb, itr, &pa) == 0) {
		fdisk_sector_t p_start_sector, p_end_sector;
		if (!fdisk_partition_has_start(pa) ||
		    !fdisk_partition_has_end(pa) ||
		    !fdisk_partition_has_partno(pa))
			g_error("%s: Invalid partition entry\n", G_STRLOC);

		/* skip boot partition entry */
		if (fdisk_partition_get_partno(pa) == BOOT_PARTITION_ENTRY) {
			found = TRUE;
			continue;
		}

		p_start_sector = fdisk_partition_get_start(pa);
		p_end_sector = fdisk_partition_get_end(pa);

		if (region_start_sector <= p_end_sector && p_start_sector <= region_end_sector) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
					"Region (sectors 0x%"G_GINT64_MODIFIER "x - 0x%"G_GINT64_MODIFIER "x) overlaps "
					"with partition %zd (sectors 0x%"G_GINT64_MODIFIER "x - 0x%"G_GINT64_MODIFIER "x)",
					region_start_sector, region_end_sector,
					fdisk_partition_get_partno(pa),
					p_start_sector, p_end_sector);
			goto out_table;
		}
	}

	if (!found) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"No boot partition found in entry %d",
				BOOT_PARTITION_ENTRY);
		goto out_table;
	}

	res = TRUE;

out_table:
	fdisk_free_iter(itr);
	fdisk_unref_table(tb);
out:

	return res;
}

gboolean r_gpt_switch_get_inactive_partition(const gchar *device,
		struct boot_switch_partition *partition,
		guint64 region_start, guint64 region_size,
		GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	gulong sector_size;
	struct fdisk_context *cxt = NULL;
	struct fdisk_partition *pa = NULL;

	g_return_val_if_fail(device, FALSE);
	g_return_val_if_fail(partition, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	cxt = get_context();

	if (fdisk_assign_device(cxt, device, 1)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to open %s with libfdisk", device);
		goto out_cxt;
	}

	if (!check_gpt(cxt, &ierror)) {
		g_propagate_error(error, ierror);
		goto out_deassign;
	}

	if (!check_region(cxt, region_start, region_size, &ierror)) {
		g_propagate_error(error, ierror);
		goto out_deassign;
	}

	if (fdisk_get_partition(cxt, BOOT_PARTITION_ENTRY, &pa) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"No boot partition found in entry %d",
				BOOT_PARTITION_ENTRY);
		goto out_deassign;
	}

	sector_size = fdisk_get_sector_size(cxt);
	if ((region_start / sector_size) ==
	    fdisk_partition_get_start(pa)) {
		partition->start = region_start + region_size / 2;
	} else if (((region_start + region_size / 2) / sector_size) ==
	           fdisk_partition_get_start(pa)) {
		partition->start = region_start;
	} else {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Boot partition's start address does not match "
				"region configuration");
		goto out_unref_part;
	}
	partition->size = region_size / 2;

	res = TRUE;

out_unref_part:
	fdisk_unref_partition(pa);
out_deassign:
	fdisk_deassign_device(cxt, 0);
out_cxt:
	fdisk_unref_context(cxt);

	return res;
}

gboolean r_gpt_switch_set_boot_partition(const gchar *device,
		const struct boot_switch_partition *partition,
		GError **error)
{
	gboolean res = FALSE;
	GError *ierror = NULL;
	gulong sector_size;
	struct fdisk_context *cxt = NULL;
	struct fdisk_label *lb = NULL;
	struct fdisk_partition *pa = NULL;

	g_return_val_if_fail(device, FALSE);
	g_return_val_if_fail(partition, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	cxt = get_context();

	if (fdisk_assign_device(cxt, device, 0)) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Failed to open %s with libfdisk", device);
		goto out_cxt;
	}

	if (!check_gpt(cxt, &ierror)) {
		g_propagate_error(error, ierror);
		goto out_deassign;
	}

	lb = fdisk_get_label(cxt, NULL);
	if (!lb)
		g_error("%s: Failed to get libfdisk label\n", G_STRLOC);

	/* Make sure both GPT copies are consistent so the actual update below
	 * is safe against crashes. */
	if (fdisk_label_is_changed(lb) == 1) {
		g_message("GPT is inconsistent, repairing...\n");
		if (fdisk_write_disklabel(cxt) != 0) {
			g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
					"Could not repair GPT");
			goto out_deassign;
		}
		g_message("GPT repaired\n");
	}
	if (fdisk_verify_disklabel(cxt) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Old GPT failed to verify");
		goto out_deassign;
	}

	if (fdisk_get_partition(cxt, BOOT_PARTITION_ENTRY, &pa) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"No boot partition found in entry %d",
				BOOT_PARTITION_ENTRY);
		goto out_deassign;
	}

	sector_size = fdisk_get_sector_size(cxt);
	fdisk_reset_partition(pa); /* only change the location */
	fdisk_partition_set_start(pa, partition->start / sector_size);
	fdisk_partition_set_size(pa, partition->size / sector_size);

	if (fdisk_set_partition(cxt, BOOT_PARTITION_ENTRY, pa) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Could not update boot partition");
		goto out_unref_part;
	}

	if (fdisk_verify_disklabel(cxt) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"New GPT failed to verify");
		goto out_unref_part;
	}
	/* As we made sure that we have two copies above, we are sure to always
	 * have at least one valid copy at any point during the update. */
	if (fdisk_write_disklabel(cxt) != 0) {
		g_set_error(error, R_UPDATE_ERROR, R_UPDATE_ERROR_FAILED,
				"Could not write new GPT");
		goto out_unref_part;
	}

	res = TRUE;

out_unref_part:
	fdisk_unref_partition(pa);
out_deassign:
	fdisk_deassign_device(cxt, 0);
out_cxt:
	fdisk_unref_context(cxt);

	return res;
}
