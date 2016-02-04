Terminology
===========

update controller
  This controls the update process and can be started on demand or run as a daemon.

update handler
  The handler performs the actual update installation.
  A default implementation is provided with the **update controller** and can
  be overridden in the **update manifest**.

update bundle
  The bundle is a single file containing an update. It consists of a squashfs
  with an appended cryptographic signature.
  It contains the **update manifest**, one or more images and optionally an
  **update handler**.

update manifest
  This contains information about update compatibility, image hashes and
  references the optional **handler**.
  It is either contained in a **bundle** or downloaded individually over the
  network.

slots
  Slots are possible targets for (parts of) updates. Usually they are
  partitions on a SD/eMMC, UBI volumes on NAND/NOR flash or raw block devices.
  For filesystem slots, the **controller** stores status information in a file
  in that filesystem.

slot class
  All slots with the same purpose (such as rootfs, appfs) belong to the same
  **slot class**.
  Only one slot per class can be active at runtime.

install group
  If a system consists of more than only the root file system, additional
  slots are bound to one of the root file system slots.
  They form an **install group**.
  An update can be applied only to members of the same group.

system configuration
  This configures the **controller** and contains compatibility information
  and slot definitions.
  For now, this file is shipped as part of the root filesystem.

boot chooser
  The bootloader component that determines which slot to boot from.

recovery system
  A non-updatable initial (fatory default) system, capable of running the
  update service to recover the system if all other slots are damaged.
