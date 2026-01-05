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

Alternatively configure the option ``resize=true`` for all corresponding slots
to resize the installed filesystem to fully utilize the partitions' space.

Is it possible to use RAUC without D-Bus (Client/Server mode)?
--------------------------------------------------------------

Yes. If you compile RAUC using the ``-Dservice=false`` configure option, you
will be able to compile RAUC without service mode and without D-Bus support::

  meson setup -Dservice=false build

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

Yes you can, as long as the offline-generated dm-verity hash tree is simply part
of the images that RAUC writes to the slots.
To ensure RAUC does not corrupt the dm-verity-protected partition by executing
hooks or writing slot status information, use ``type=raw`` in the respective
slot config and use a :ref:`shared data directory <data-directory>` on a
separate non-redundant partition by setting
``data-directory=</path/to/data-directory>``.

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

Why does the installation fail with a ``resize2fs`` error?
----------------------------------------------------------

When installing an ext4 image with ``resize=true`` configured for that slot, it
may happen that the ext4 image has features enabled which are not supported by
the currently used version of ``resize2fs``.

For example, ``e2fsprogs`` 1.47 enabled the ``orphan_file`` feature by default
and is included in Yocto mickledore.
When an image generated by Yocto mickledore is installed on an older release
(perhaps built using kirkstone or older), that version of ``resize2fs`` will
refuse to modify the filesystem and the installation will be aborted::

  LastError: Installation error: Failed updating slot rootfs.1: Failed to run resize2fs: Child process exited with code 1

In the log output from RAUC, you'll find more details::

  …
  rauc[409]: opening slot device /dev/mmcblk0p2
  rauc[409]: writing data to device /dev/mmcblk0p2
  rauc[409]: Resizing /dev/mmcblk0p2
  …
  rauc[551]: resize2fs 1.46.5 (30-Dec-2021)
  rauc[551]: resize2fs: Filesystem has unsupported feature(s) (/dev/mmcblk0p2)
  rauc[409]: Installation error: Failed updating slot rootfs.1: Failed to run resize2fs: Child process exited with code 1
  …

A solution for this is to disable the unsupported filesystem features during the
image generation.
When using Yocto, in case of the ``orphan_file`` file feature, you could use::

  EXTRA_IMAGECMD:ext4:append = " -O ^orphan_file"

in the image recipe or an appropriate conf file to disable the feature until
all systems have been updated with versions of ``resize2fs`` which support this
feature.

Why does bundle creation fail with a "not supported as contents" error?
-----------------------------------------------------------------------

Previous versions of RAUC modified and added files in the input directory during
bundle creation.
While this wasn't much of a problem, we need to delete the original files when
converting tar archives to file trees in the context of artifact updates.
That would require the user to always re-create the bundle input directory after
running ``rauc bundle``, which would be unexpected and annoying.

Since version 1.12, RAUC hard-links all files from the input directory to a
``.rauc-workdir`` subdirectory.
This way, we don't actually need to copy any data and can perform any
preparation of the contents without affecting the input directory.

For simplicity, we abort on anything in the input directory which is not a
regular file, directory or a simple local symlink (containing no slashes).
If the input directory contains regular (non-hidden) subdirectories, the
subdirectory hierarchy will be mirrored into the bundle.
Hidden subdirectories (i.e., whose name starts with a '.') at the root of the
bundle are reserved for RAUC's internal use and we abort if any such directory
is found.
In that case, one of the following errors will be shown:

  * ``Failed to create bundle: absolute symlinks are not supported as bundle contents (a_symlink)``
  * ``Failed to create bundle: symlinks containing slashes are not supported as bundle contents (a_symlink)``
  * ``Failed to create bundle: hidden directories are not supported as top-level bundle contents (.a_hidden_directory)``
  * ``Failed to create bundle: only regular files are supported as bundle contents (a_fifo)``

If someone relies on the old undocumented behavior of including directories and
symlinks in the bundle, please contact us.

How can I access the manifest without using RAUC?
-------------------------------------------------

For bundles which use the :ref:`verity format <sec_ref_format_verity>`, you
only need to locate the CMS data and verify the signature.
The CMS data is located almost at the end of the bundle and is followed by
its size as an 8 byte big endian integer.

To see how this can be done, take a look at the `Python example script in
contrib/get-cms.py
<https://github.com/rauc/rauc/blob/master/contrib/get-cms.py>`_.
Used in the RAUC source directory, you would get::

  $ contrib/get-cms.py test/good-verity-bundle.raucb verity.cms
  CMS length is 1922 bytes.
  CMS written to 'cms.der'. You can now...

      print the CMS data structure:
      $ openssl cms -cmsout -in cms.der -inform DER -print

      skip the signature verification and print the manifest (verity format):
      $ openssl cms -verify -in cms.der -inform DER -noverify

      verify the signature and print the manifest (verity format):
      $ openssl cms -verify -in cms.der -inform DER -CAfile <your_ca.pem>

      decrypt, verify and print the manifest (crypt format):
      $ openssl cms -decrypt -in cms.der -inform DER -inkey <your_key.pem> |
        openssl cms -verify -inform DER -CAfile <your_ca.pem>

  $ openssl cms -verify -in verity.cms -inform DER -CAfile test/openssl-ca/dev-ca.pem
  [update]
  compatible=Test Config
  version=2011.03-2

  [bundle]
  format=verity
  verity-hash=931b44c2989432c0fcfcd215ec94384576b973d70530fdc75b6c4c67b0a60297
  verity-salt=ea12cb34c699ebbad0ebee8f6aca0049ee991f289011345d9cdb473ba4fdd285
  verity-size=4096

  [image.rootfs]
  sha256=101a4fc5c369a5c89a51a61bcbacedc9016e9510e59a4383f739ef55521f678d
  size=8192
  filename=rootfs.img

  [image.appfs]
  sha256=f95c0891937265df18ff962869b78e32148e7e97eab53fad7341536a24242450
  size=8192
  filename=appfs.img
  CMS Verification successful

For bundles which use the :ref:`crypt format <sec_ref_format_crypt>`, you need
to decrypt the CMS data before verifying it.
See the script output for an example command line.

For bundles which use the :ref:`plain format <sec_ref_format_plain>`, you would
need to split the payload and CMS data and then use `openssl cms -verify` with
the `-content` option.
As this is more involved, we recommend using either `rauc extract` or switching
to verity bundles.

How can I protect manufacturer data at the end of the boot partition when using ``boot-emmc``?
----------------------------------------------------------------------------------------------

When using RAUC's boot-emmc slot type for bootloader updates, the entire eMMC
boot partition is cleared before the new image is written.
If this partition contains manufacturer-specific data (e.g., calibration data
at the end), that data will be lost unless special precautions are taken.

The recommended solution is to migrate this data to a safe location during the
first boot of the device. This ensures future bootloader updates can proceed
safely.

If migration is not feasible (for example, on already deployed devices) RAUC
provides a ``size-limit`` :ref:`slot option <slot.slot-class.idx-section>` for
the ``boot-emmc`` slot.
This restricts the writable area to avoid overwriting critical data.

.. warning:: The ``size-limit`` option is intended only for backwards
   compatibility and should not be used in new designs!

How do I handle images with unrecognized file extensions?
---------------------------------------------------------

The classic file extension–based image type matching in RAUC often led to
confusion when using binary artifacts or images without one of the file
extensions RAUC expects (such as ``.img``, ``.ext4``, ``.tar.gz``, etc.).

Common examples include ``.bin`` for bootloader images, ``.ext4.verity`` for
ext4 images with verity information, or other variants emitted by build
systems.

Adding a new image type mapping to RAUC for every such variant is not
practical.

Since v1.15, RAUC supports setting an explicit :ref:`image type
<sec-ref-supported-image-types>` using the ``type`` manifest option.
With this set, you can freely choose the file extension, e.g.

.. code-block:: cfg

   [image.bootloader]
   filename=boot.bin
   type=raw

.. note:: Ensure all devices in the field run a RAUC version that supports
   this feature before making use of it.
