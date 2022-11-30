Frequently Asked Questions
==========================

.. contents::
   :local:
   :depth: 1

Why doesn't the installed system use the whole partition?
---------------------------------------------------------

The filesystem image installed via RAUC was probably created for a size smaller
than the partition on the target device.

Especially in cases where the same bundle will be installed on devices which use
different partition sizes, tar archives are preferable to filesystem images.
When RAUC installs from a tar archive, it will first create a new filesystem on
the target partition, allowing use of the full size.

Is it possible to use RAUC without D-Bus (Client/Server mode)?
--------------------------------------------------------------

Yes. If you compile RAUC using the ``--disable-service`` configure option, you
will be able to compile RAUC without service mode and without D-Bus support::

  ./configure --disable-service

Then every call of the command line tool will be executed directly rather than
being forwarded to the RAUC service process running on your machine.

Why does RAUC not have an ext2 / ext3 file type?
------------------------------------------------

ext4 is the successor of ext3. There is no advantage in using ext3 over ext4.

Some people still tend to select ext2 when they want a file system without
journaling. This is not necessary, as one can turn off journaling in ext4,
either during creation::

  mkfs.ext4 -O ^has_journal

or later with::

  tune2fs -O ^has_journal

Note that even if there is only an ext4 slot type available, potentially each
file system mountable as ext4 should work (with the filename suffix adapted).

Is the RAUC bundle format forwards/backwards compatible?
--------------------------------------------------------

While RAUC now :ref:`supports <sec_ref_formats>` two bundle formats (verity and
crypt) in addition to the original format (plain), all are still installable by
default.
Support for the old format can be :ref:`disabled via the configuration
<sec_int_migration>`.
Going forward, any issue with installing bundles using old formats or features
would be considered a bug, except after an explicit deprecation period of
several years.

Newer RAUC versions have added features (such as casync), slot types
(eMMC/MBR/GPT bootloader partitions) and bundle formats (verity and crypt).
Only if you use those features by enabling them in the bundle manifest, older
versions of RAUC that cannot handle them will refuse to install the bundle.
As long as you don't enable new features, our intention is that bundles created
by newer versions will be installable by older versions and any such issues
would be considered a bug.

Some background is described in the :ref:`Forward and Backward Compatibility
section <sec-compatibility>`.

If there are ever reasons that require an incompatible change, you can use a
two step migration using an :ref:`intermediate version
<sec_migrate_updated_bundle_version>`.

Can I use RAUC with a dm-verity-protected partition?
----------------------------------------------------

Yes you can, as the offline-generated dm-verity hash tree is simply part of
the image that RAUC writes to the partition.
To ensure RAUC does not corrupt the partition by executing hooks or writing
slot status information, use ``type=raw`` in the respective slot config and
use a global (see :ref:`slot status file <statusfile>`) on a separate
non-redundant partition with setting ``statusfile=</path/to/global.status>``.

Can I use RAUC with a dm-crypt-protected partition?
---------------------------------------------------

Yes you can, by using the ``/dev/mapper/<devicename>`` as the device for the
slot (with the type of the filesystem of your choice).
This way, RAUC interacts only with the unencrypted device/content.

For example, with an encrypted root filesystem slot (perhaps unlocked by an
initramfs loaded from a different partition):

.. code-block:: cfg

  [slot.rootfs.0]
  device=/dev/mapper/crypt-rootfs0
  type=ext4
  bootname=system0

Remember to unlock the inactive slots as well so that RAUC can write to them.

What causes a payload size that is not a multiple of 4kiB?
----------------------------------------------------------

RAUC versions up to 1.4 had an issue in the casync bundle signature generation,
which caused two signatures to be appended.
While the squashfs payload size is a multiple of 4kiB, the end of the first
signature was not aligned.
As RAUC uses the second ("outer") signature during verification, this didn't
cause problems.
RAUC 1.5 fixed the casync bundle generation and added stricter checks, which
rejected the older bundles.
In RAUC 1.5.1, this was reduced to a notification message.

To avoid the message, you can recreate the bundle with RAUC 1.5 and newer.

.. _faq-udev-symlinks:

How can I refer to devices if the numbering is not fixed?
---------------------------------------------------------

There are many reasons why device numbering might change from one kernel
version to the next, across boots or even between hardware variants.
In the context of RAUC, this is mainly relevant for block, MTD and UBI devices.

In almost all cases, the proper way to configure this is to use `udev rules
<https://www.freedesktop.org/software/systemd/man/udev.html>`_.

For block devices, udev ships with rules which create symlinks in
``/dev/disk/by-path/``.
These are not affected by changes in the probe order or by other devices that
are not always connected.
For example, on an emulated ARM machine, this results in::

  root@qemuarm:~# ls -l /dev/disk/by-path
  lrwxrwxrwx    1 root     root             9 Nov 18 12:46 platform-a003c00.virtio_mmio -> ../../vda

By using ``/dev/disk/by-path/platform-a003c00.virtio_mmio`` in your
configuration, you ensure that you always refer to the same block device.

For UBI volumes, no equivalent rules are currently shipped by udev, so custom
rules can be used.
Depending on how the symlinks should be named, different rules could be used::

  # Use the volume name instead of the number
  SUBSYSTEM=="ubi", KERNEL=="ubi*_*", ATTRS{mtd_num}=="*", SYMLINK+="$parent_%s{name}"
  # Use the MTD device number instead of the UBI device number
  SUBSYSTEM=="ubi", KERNEL=="ubi*_*", ATTRS{mtd_num}=="*", SYMLINK+="ubi_mtd%s{mtd_num}_%s{name}"
  # Use the MTD device name instead of the UBI device number
  SUBSYSTEM=="ubi", KERNEL=="ubi*_*", ATTRS{mtd_num}=="*", IMPORT{program}="/bin/sh -ec 'echo MTD_NAME=$(cat /sys/class/mtd/mtd%s{mtd_num}/name)'" SYMLINK+="ubi_%E{MTD_NAME}_%s{name}"

When enabling all of these rules (which you should not do), you will get
something like::

  crw------- 1 root root 249,  0 Nov 18 13:46 /dev/ubi0
  crw------- 1 root root 249,  1 Nov 18 13:46 /dev/ubi0_0
  lrwxrwxrwx 1 root root       6 Nov 18 13:46 /dev/ubi0_rauc-test -> ubi0_0
  lrwxrwxrwx 1 root root       6 Nov 18 13:46 /dev/ubi_nandsim_rauc-test -> ubi0_0
  crw------- 1 root root  10, 59 Nov 18 13:46 /dev/ubi_ctrl
  lrwxrwxrwx 1 root root       6 Nov 18 13:46 /dev/ubi_mtd3_rauc-test -> ubi0_0

Custom udev rules can also be very useful when you want to refer to the active
data partition (in a scenario with redundant data partitions) with a fixed
name.
