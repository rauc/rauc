Terminology
===========

.. glossary::

  Update Controller
    This controls the update process and can be started on demand or run as a daemon.

  Update Handler
    The handler performs the actual update installation.
    A default implementation is provided with the **update controller** and can
    be overridden in the **update manifest**.

  Update Bundle
    The bundle is a single file containing an update. It consists of a squashfs
    with an appended cryptographic signature.
    It contains the **update manifest**, one or more images and optionally an
    **update handler**.

  Update Manifest
    This contains information about update compatibility, image hashes and
    references the optional **handler**.
    It is either contained in a **bundle** or downloaded individually over the
    network.

  Slot
    Slots are possible targets for (parts of) updates. Usually they are
    partitions on a SD/eMMC, UBI volumes on NAND/NOR flash or raw block devices.
    For filesystem slots, the **controller** stores status information in a file
    in that filesystem.

  Slot Class
    All slots with the same purpose (such as rootfs, appfs) belong to the same
    **slot class**.
    Only one slot per class can be active at runtime.

  Install Group
    If a system consists of more than only the root file system, additional
    slots are bound to one of the root file system slots.
    They form an **install group**.
    An update can be applied only to members of the same group.

  .. FIXME find a better term for this

  System Configuration
    This configures the **controller** and contains compatibility information
    and slot definitions.
    For now, this file is shipped as part of the root filesystem.

  Boot Chooser
    The bootloader component that determines which slot to boot from.

  Recovery System
    A non-updatable initial (factory default) system, capable of running the
    update service to recover the system if all other slots are damaged.
