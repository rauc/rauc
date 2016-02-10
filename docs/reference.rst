Reference
=========

System Configuration File
-------------------------

A configuration file located in ``/etc/rauc/system.conf`` describes the
number and type of available slots.
It is used to validate storage locations for update images.
Each board type requires its special configuration.

Example configuration:

.. code-block:: cfg

  [system]
  compatible=FooCorp Super BarBazzer
  bootloader=barebox

  [keyring]
  path=/etc/rauc/keyring/

  [slot.rescue.0]
  device=/dev/mtd4
  type=raw
  bootname=factory0
  readonly=true

  [slot.rootfs.0]
  device=/dev/sda0
  type=ext4
  bootname=system0

  [slot.rootfs.1]
  device=/dev/sda1
  type=ext4
  bootname=system1

  [slot.appfs.0]
  device=/dev/sda2
  type=ext4
  parent=rootfs.0

  [slot.appfs.1]
  device=/dev/sda3
  type=ext4
  parent=rootfs.1


This file is (currently) part of the root file system.

The ``system``  section contains the ``compatible`` string which must describe
the board and its function as distinctly as it is required to assure that
only update bundles designed for this specific type can be installed.
The ``bootloader`` entry gives a hint which boot chooser implementation is
available.

The ``keyring`` section refers to the trusted keyring used for signature
verification.

Each slot is identified by a section starting with ``slot.`` followed by
the slot class name, and a slot number.
The *slot class* name is used in the *update manifest* to target the correct
set of slots.
``device`` points to the Linux device name for this slot.
`type`` provides a hint if and which file system the slot has.
``bootname`` is the name the bootloader uses for this slot.

A ``readonly`` slot cannot be a target slot.

The ``parent`` entry is used to bind additional slots to a bootable root
file system slot.
This is used together with the ``bootname`` to identify the currently active
slot, so that the inactive one can be selected as the update target.
The inactive root file system and all slots bound to it form the *install
group*.
An update is always applied only to slots of the *install group*.


Manifest
--------

.. code-block:: cfg

  [update]
  compatible=FooCorp Super BarBazzer
  version=2015.04-1
  
  [keyring]
  archive=release.tar

  [handler]
  filename=custom_handler.sh

  [image.rootfs]
  sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3
  filename=rootfs.ext4
  
  [image.appfs]
  sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca
  filename=appfs.ext4


The ``compatible`` string is used to determine whether the update image is
compatible with the target system.
An update is allowed only if the *update manifest* string and the system
information string match exactly.

If no handler section is present, the default handler is chosen.

If no keyring section is present, the keyring is copied from the currently
running system.

Slot name suffix of images must match the slot class name (slot.class.#).

The ``sha`` entry provides the slot images hash while the ``filename`` entry
provides the name of the slot's update image.
The filename suffix should either match the file system type (.ext4, .ubifs,
...) or be .tar.* for an archive to be extracted into an empty file system.

Slot Status File
----------------

File Formats
------------

(images "raucb", manifest signatures "raucm")

Command Line Tool
-----------------

.. code-block:: man

  Usage:
    rauc [OPTION...] <COMMAND>
  
  Application Options:
    -c, --conf=FILENAME     config file
    --cert=PEMFILE          cert file
    --key=PEMFILE           key file
    --mount=PATH            mount prefix
    --handler-args=ARGS     extra handler arguments
    --version               display version
    -h, --help              
  
  List of rauc commands:
    bundle        Create a bundle
    checksum      Update a manifest with checksums (and optionally sign it)
    resign        Resign a bundle
    install       Install a bundle
    info          Show file information
    status        Show status


Custom Handlers (Interface)
---------------------------

Interaction between rauc and custom handler shell scripts is done using shell
variables.

.. glossary::

  ``RAUC_SYSTEM_CONFIG``
    Path to the system configuration file (default path is ``/etc/rauc/system.conf``)

  ``RAUC_CURRENT_BOOTNAME``
    Bootname of the slot the system is currently booted from

  ``RAUC_UPDATE_SOURCE``
    Path to mounted update rauc bundle, e.g. ``/mnt/rauc/bundle``

  ``RAUC_MOUNT_PREFIX``
    Provides the path prefix that may be used for rauc mounting points

  ``RAUC_SLOTS``
    An iterator list to loop over all existing slots. Each item in the list is
    an integer referencing one of the slots. To get the slot parameters you have to
    resolve the per-slot variables (suffixed with <N> placeholder for the
    respective slot number).

  ``RAUC_TARGET_SLOTS``
    An iterator list similar to ``RAUC_SLOTS`` but only containing slots that
    were selected as target slots by the rauc target slot selection algorithm.
    You may use this list for safely installing images into these slots.

  ``RAUC_SLOT_NAME_<N>``
    The name of slot number <N>, e.g. ``rootfs.0``

  ``RAUC_SLOT_CLASS_<N>``
    The class of slot number <N>, e.g. ``rootfs``

  ``RAUC_SLOT_DEVICE_<N>``
    The device path of slot number <N>, e.g. ``/dev/sda1``

  ``RAUC_SLOT_BOOTNAME_<N>``
    The bootloader name of slot number <N>, e.g. ``system0``

  ``RAUC_SLOT_PARENT_<N>``
    The name of slot number <N>, empty if none, otherwise name of parent slot


.. code::

  for i in $RAUC_TARGET_SLOTS; do
          eval RAUC_SLOT_DEVICE=\$RAUC_SLOT_DEVICE_${i}
          eval RAUC_IMAGE_NAME=\$RAUC_IMAGE_NAME_${i}
          eval RAUC_IMAGE_DIGEST=\$RAUC_IMAGE_DIGEST_${i}
  done


Signatures
----------

D-Bus API
---------
