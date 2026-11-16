#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <mbr.h>
#include <update_handler.h>

#include "fuzz.h"

/* keep the device file small: region is bounded to the first 1 MiB */
#define FUZZ_MAX_DEVICE_SIZE (1024*1024)

/*
 * Fuzzes the MBR boot-switch logic in mbr.c.
 *
 * The MBR (and the partition table inside it) lives on storage that an
 * attacker with physical access can rewrite at will; rauc parses it to
 * find the inactive boot partition for bootloader switching. The harness
 * treats the fuzz input as the raw 512-byte sector on a file-backed
 * "device" (all ioctls in mbr.c have file fallbacks) and drives:
 *
 *   - r_mbr_switch_get_inactive_partition(): magic validation, region
 *     checks, partition-table overlap detection, boot-partition matching
 *   - r_mbr_switch_set_boot_partition(): write-back path including the
 *     CHS encoding of the updated entry
 *
 * Input layout: [0] op bits, [1..8] LE64 region start, [9..16] LE64
 * region size, [17..] device content (first 512 bytes = the MBR).
 */

static const guint8 mbr_magic[2] = {0x55, 0xaa};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *devname = NULL;
	int fd = -1;

	fuzz_set_logging_func();

	if (size < 17)
		return 0;

	uint8_t op = data[0];
	uint64_t region_start = 0;
	uint64_t region_size = 0;
	for (unsigned i = 0; i < 8; i++) {
		region_start |= (uint64_t)data[1 + i] << (8 * i);
		region_size |= (uint64_t)data[9 + i] << (8 * i);
	}

	/* sane region: inside the first MiB, double-sector aligned */
	region_start %= FUZZ_MAX_DEVICE_SIZE;
	region_start -= region_start % 512;
	if (region_start < 512)
		region_start = 512;
	region_size %= (FUZZ_MAX_DEVICE_SIZE - region_start);
	region_size -= region_size % 1024;

	gsize dev_size = (gsize)region_start + region_size;
	if (dev_size < 512)
		dev_size = 512;
	if (dev_size > FUZZ_MAX_DEVICE_SIZE)
		dev_size = FUZZ_MAX_DEVICE_SIZE;

	tmpdir = g_dir_make_tmp("rauc-fuzz-XXXXXX", NULL);
	if (!tmpdir)
		return 0;

	devname = g_build_filename(tmpdir, "device.img", NULL);
	if (!devname)
		goto out;

	{
		gchar *buf = g_malloc0(dev_size);
		/* the input past the header seeds the MBR sector directly so
		 * that partition-table entries land at their real offsets */
		gsize copysize = size - 17;
		if (copysize > dev_size)
			copysize = dev_size;
		memcpy(buf, data + 17, copysize);
		/* optionally seed the boot signature; otherwise the fuzz data
		 * in the magic field decides whether read_mbr accepts it */
		if (op & 0x04) {
			buf[510] = mbr_magic[0];
			buf[511] = mbr_magic[1];
		}
		gboolean written = g_file_set_contents(devname, buf, dev_size, NULL);
		g_free(buf);
		if (!written)
			goto out;
	}

	fd = g_open(devname, O_RDWR);
	if (fd < 0)
		goto out;

	if (op & 0x01) {
		struct boot_switch_partition partition = {};

		(void)r_mbr_switch_get_inactive_partition(devname,
				&partition, region_start, region_size, NULL);

		/* write-back path with whatever the parse produced */
		partition.start = region_start;
		partition.size = region_size / 2;
		(void)r_mbr_switch_set_boot_partition(devname,
				&partition, NULL);
	} else {
		struct boot_switch_partition partition = {};

		(void)r_mbr_switch_get_inactive_partition(devname,
				&partition, region_start, region_size, NULL);
	}

	close(fd);
	fd = -1;

out:
	if (fd >= 0)
		close(fd);
	if (devname)
		g_remove(devname);
	g_remove(tmpdir);

	return 0;
}
