.. sectnum::

Robust Auto-Update Controller -- RAUC
#####################################

This document describes a generic update concept and toolchain for embedded Linux systems.

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

system configuration
  This configures the **controller** and contains compatibility information
  and slot definitions.
  For now, this file is shipped as part of the root filesystem.

boot chooser
  The bootloader component that determines which slot to boot from.

recovery system
  A non-updatable initial (fatory default) system, capable of running the
  update service to recover the system if all other slots are damaged.


Objectives
==========

- The update system is intended to be **flexible** and **generic**, while
  unnecessary complexity should be avoided.

- The update system *must* allow both to **update a running system** as well
  as **initializing a factory system**.

- If an update fails, a minimal (factory) **fallback system** *must* assure
  that the system can be recovered by installing an update.

- The update system *should* be able to **skip parts of an update** if the
  current version and the version contained in an update are identical.

- The update system *must* accept only **valid signed firmware**

- An update may consist of **multiple firmware bundles**.


Basic update procedure
======================

An *update controller* either running on the currently running system or on
a minimal fallback system handles incoming update requests.
An update request may be initiated manually from the command line or by a
script that checks for example for insertion of an USB stick containing a
*firmware bundle*.
A firmware bundle is a squashfs-packed set of config files, scripts, and disk
images with an appended signature that allows verifying the bundle's origin
and integrity.
For uploading a *bundle* to the system using a web interface, the required
web server is out of scope for the update server. The web server needs to
receive the bundle and trigger the *controller*.

Once the update controller receives an update request instruction containing
the file path of a firmware bundle it verifies its signature based on a public
key stored in the current rootfs.
If the signature is valid, the service loopback-mounts the bundle to access its
content and installs the update.

Installing the update means either calling an *update handler* included in the
bundle (if provided) or using a default updater script that performs the update
based on information about the available slots and versions.


Update Controller
=================

The update controller is written in C using glib. It runs in background on the
currently active system and can be controlled using a CLI or directly via D-Bus.
The CLI provides a simple text-based interface to initiate and monitor update
requests.
This eases both manual invocation as well as writing scripts.

::

  rauc install <file>

  rauc install /mnt/sdcard0/FooCorp_SuperBarBazzer_1.2.raucb

Update Procedure
----------------

1. Verify bundle integrity (using the signature)

2. Mount squashfs

3. Verify compatibility information

   - system compatibility is defined in the *system configuration*
   - update compatibility is defined in the *update manifest*
   - if the update is incompatible, reject the update (when running the
     *fallback system*, allow overriding the compatibility by the user)

4. Check for update handler, use default if not configured

5. Select target *slot*

6. Run the *update handler*

7. Reboot (depending on update success)


Status Feedback
---------------

A D-Bus interface provides status, errors, and progress information such as

- ``update failed``

- ``incompatible firmware``

- ``update started (0%)``

- ``rootfs updated (50%)``

- ``appfs skipped (80%)``
  
- ``update finished (100%)``

(produced by the *controller* and the *handler*, forwarded via D-Bus by controller)

A frontend (e.g. a wep page) may use this to give user information about the update status.


Update Handler
--------------

An update bundle may come with a custom update handler included which is
executed as root and has unlimited access to the system.
If none is included, a default update handler located in the currently
running system is executed.

This default update handler handles the most common cases for updating a system.

The *controller* provides the required information in environment variables:

SYSTEM_CONFIG
  filesystem path to the *system configuration* file
CURRENT_BOOTNAME
  *bootname* of the currently running system
TARGET_SLOT
  name of the *slot* to be updated
UPDATE_SOURCE
  filesystem path to the *bundle* contents (images)
MOUNT_PREFIX
  filesystem path to be used for mounting slots

To install an update, the *handler* usually performs the following steps:

1. Load meta-data from ``$UPDATE_SOURCE/manifest.raucm``

2. Mark target slot as non-bootable for the *boot chooser*

3. For each image listed in the *manifest*:

   1. Find, check and mount destination slot (possibly creating the filesystem)

   2. Compare slot status information

   3. Skip if identical, install update otherwise

   4. Update slot status file

4. Extract updated keyring (if supplied with the update)

5. After successful update, set target slot as bootable for the *boot chooser*

6. Return to the *controller* (with update success status)


Config file descriptions
========================

System Configuration File
-------------------------

A configuration file located in ``/etc/rauc/system.conf`` describes the
number and type of available slots.
It is used to validate storage locations for update images.
Each board type requires its special configuration.

Example configuration:

::

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

The ``keyring`` section refers to the trusted keyring used for signature
verification.

A ``readonly`` slot cannot be a target slot.

The ``parent`` entry is used to bind additional slots to a bootable root
filesystem slot.

Update Manifest
---------------

File located in each update as ``manifest.raucm``, describing update meta-data
and slots to update (e.g. for the *update handler*)

Example manifest:

::

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
An update is allowed only if the *update manifest* string and the system
information string match exactly.

If no handler section is present, the default handler is chosen.

If no keyring section is present, the keyring is copied from the currently
running system.

Slot name suffix of images must match the slot group name (slot.group.#).


Slot status file
----------------

A slot status file is placed in the root of every slot containing a file system.
It describes the current version of the content in this slot.
The updater compares the version to the one it provides and skips update if their
version is identical to save time.

Example:

::

  [slot]
  status=ok
  sha256=e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27


Booting
=======

To determine from which device / slot the system is booted, the barebox *boot chooser* is used.
This allows to maintain multiple potential systems with a *defined priority* and a *number of boot attempts*.
If booting from the highest-priority system (typically the current productive system) fails for e.g. 3 times,
the next lower priority boot source is chosen which could be the fallback system for example.

As updates are always installed in the currently inactive slot set, the boot order must be changed
after a successful update.


Signature and Verification
==========================

To sign and verify updates, a X.509 PKI is used. While RAUC only requires
images signed with a key which can be verified against the trusted keyring,
PKI setup similar to the following is recommended:

::

  * "FooCorp Firmware Update CA (root)" (kept offline)
    - "FooCorp Firmware Update (development)" (kept offline)
      + "FooCorp Auto-Builder (Super BarBazzer)" (on the build server for
        automatic signing)
    - "FooCorp Firmware Update (release)" (kept offline)
      + "FooCorp Release (Super BarBazzer)" (for manual resigning of development
        *bundles* for release)

By having separate intermediate CAs for development and release, it is possible
to safely perform automatic creation and signing of *update bundles* on the build
servers. Development systems and systems in the factory are configured to trust
both the "release" and the "development" CAs. Production systems instead only
trust the "release" CA.

This way development systems can be updated using the automatically generated
updates. Also, the factory image will accept "release" updates, which allows
them to be switched to the "release" keyring as described below.


Keyring Update
--------------

Each update can optionally contain a new trusted keyring. The *handler*
installs this keyring to the updated slot. If no new keyring is provided,
the current keyring for the running system will be used instead. They keyring
contains of one or more CA certificates and the corresponding CRLs, so that
certificates can be verified even without network access.


Image Resigning
---------------

To avoid having to rebuild a well-tested software version before releasing it
to production systems, RAUC supports resigning an existing *bundle* with a new
key. During resigning, the keyring contained in the bundle can be replaced with
a different one (for example replacing "development" with "release" trusted
keyring and signature).


Key Revocation
--------------

Using different keys for each purpose is recommended. If a key becomes
compromised, it can be revoked and the new CRL (certificate revocation list)
distributed using a update bundle.

The certificate lifetimes should be configured to avoid problems due to invalid
system time (broken/missing RTC).


Generating System and Firmware Images
=====================================

A build system is used to generate all the slot images required for an update
bundle, which is then created and signed using the ``rauc bundle`` command.

Generating the Fallback System
------------------------------

The fallback system is a minimal Linux system which contains a known-good
RAUC installation. It must be installed using conventional approaches such as
manually copying disk images.

Content of the system

- minimal kernel
  
- minimal rootfs (or appended InitRAMFS)

  - minimal Linux userspace

  - *update controller*
  
  - *system configuration file*
  
  - default *update handler*


Generating Updates
------------------

The build system generates separate filesystems images or tar archives for each
slot:

- rootfs

  - Linux kernel (in ``/boot``, optionally with InitRAMFS/DTB)

  - Linux userspace

  - *update controller*
  
  - *system configuration file*
  
  - default *updater handler*

  - trusted keyring

- appfs

  - application binaries

Then, ``rauc bundle`` can be used by the build system to create an update
bundle signed by a development key.

RAUC
====

RAUC CLI
--------

::

  rauc bundle --key=<keyfile> <input-dir> <output-file>

::

  rauc resign --key=<keyfile> <input-bundle> <output-bundle>

::

  rauc info <bundle>

::

  rauc install <file>

::

  rauc status


RAUC Command API
----------------

This can be used by the *handler* to reuse existing functionality in RAUC.

::

  rauc-cmd boot select <slot>

::

  rauc-cmd boot disable <slot>

::

  rauc-cmd mount <slot>

::

  rauc-cmd umount <slot>


System Setup
------------

By default an updatable platform should provide 3 slots from which one is the fallback system
and the other two are for productive systems.
If possible, the fallback system slot along with the bootloaders
should be placed in a different (read-only) storage than the productive system slots.


Future Improvements
===================

Fine-Grained Handler Hooks
--------------------------

*rauc-handler prepare <device> <slot-mountpoint>*
  check, mount, (format,)

*rauc-handler install <img> <slot-mountpoint>*
  install image to mounted slot

*rauc-handler finalize <slot-mountpoint>*
  unmount, select next boot source

Network Updates
---------------

RAUC should regularly contact an update server and download images if a new
version is available.

*staged updates*
  avoid updating all systems at once
