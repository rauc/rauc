.. sectnum::

Robust Auto-Update Controller -- RAUC
#####################################

This document describes a generic update concept and toolchain for embedded linux systems.

Terminology
===========

update controller
  Controls update process, maybe started on demand or run as a daemon

update handler
  Determines how the update should be installed
  Default implementation provided in update controller
  Overridable by the manifest
  
update bundle
  squashfs + signature appended
  contains images, update handler, manifest

update manifest
  contains information about update compatibility, image hashes, possible custom update handler(s)
  Either placed in a bundle or downloaded from a server

slots
  Possible targets for (parts of) updates
  Contains status file (hash)

system configuration
 contains compatibility information, slot definitions
  placed in each slot

boot chooser
  Bootloader component that dertermines which slot to boot from

recovery system
  non-updatable initial (fatory default) system, capable of running update service


Basic Requirements
====================

- The update system *should* be **flexible** and **generic**

- The update system *must* allow both to **update a productive system** as well as **initializing a factory system**.

- If an update fails, a minimal (factory) **fallback system** *must* assure that new firmware still can be uploaded

- The update system *should* be able to **skip parts of an update** if the current version and the version contained
  in an update are equal.

- The update system *must* accept only **valid signed firmware**

- An update may consist of **multiple firmware bundles**


Basic update procedure
======================

An *update controller* either running on the currently active productive system or on a minimal fallback system 
handles incoming update requests.
An update request may be initiated manually or by a script that checks for example for insertion of an usb stick containing a *firmware bundle*.
A firmware bundle is a squashfs-packed set of config files, scripts, and disk images with a signature appended that allows
verifying that bundles origin and integrity.

Once the update controller receives an update request instruction containing the source of a firmware bundle it
verifies its signature based on a public key stored in the current rootfs.
If the signature is valid, the service loopback-mounts the bundle to access its content and executes the update.

Executing the update means either calling a specific update handler included in the bundle, if available, or
a default updater script that performs the update based on information about the available slots and versions.


Update Controller
=================

The update controller is written in C and runs in background on the currently active system.
It provides a simple text-based interface to initiate update requests.
This eases both manual invocation as well as writing caller scripts.

::

  rauc install <url/file>

  rauc install /mnt/sdcard0/FoomaticSuperbarBazzer_1.2.raucb

  rauc install https://example.com/FoomaticSuperbarBazzer_1.2.raucm

Update procedure
----------------

0. opt. Copy firmware bundle

1. Verify integrity

2. Loopback mount squashfs

3. Verify board type

   - ->  where info about our system? (e.g. 'Foomatic super BarBazzer', Revision 1.1) -> info file !?

   - reject invalid
   - on fallback system, ask User

4. Check for update handler, use default if none provided

5. Mark update slot as non-bootable

6. Execute update

7. After successful update, update bootchooser

8. Reboot


Status Feedback
---------------


A D-Bus interface provides status, errors, and progress information such as

- ``update failed``

- ``incompatible firmware``

- ``update started (0%)``

- ``rootfs updated (50%)``

- ``appfs skipped (80%)``
  
- ``update finished (100%)``

(produced by handler, forwarded by controller)


A frontend (e.g. a wep page) may use this to give user information about the update status.


- TODO: required to RUN in background?

Update Handler
--------------

An update bundle may come with a custom update handler included which is executed as root and
potentially allows all kinds of modification to a system.
If none is included, a default update handler located in the currenly running system is executed.

This default update handler handles the most common cases for updating a system.


1. Load update list from info.ini

2. For each:

   1. Find and check destination slot

   2. Compare slot sha

   3. Skip if equal, write update if inequal

   4. Update slot info file


Config file descriptions
========================

System Configuration File
-------------------------

A config file located in TODO describess the number and type of available slots.
It is used to validate storage locations for update images.
Each board type requires its special configuration.

Example configuration:

::

  [system]
  compatible=Foomatic Super BarBazzer V1.0
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

  [slot.appfs.1]
  device=/dev/sda3
  type=ext4


This file is (currently) part of the root file system.


Update Manifest
---------------

File located in each update, describing update version and slots to update (e.g. for update handler)

Example manifest:

::

  [update]
  compatible=Foomatic Super BarBazzer V1.0

  [handler]
  filename=custom_handler

  [image.rootfs]
  SHA256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3
  filename=rootfs.ext4
 
  [image.appfs]
  SHA256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca
  filename=appfs.ext4


The board compatible string is used to determine wheter the update image fits to the target board.
An update is performed only if the update manifest string and the system information string match exactly.

If no handler section is present, the default handler is chosen.

Section name suffix of images must match the slot group name (slot.group.nr).


Slot info file
--------------

A  slot version file is placed in the root of every slot containing a file system.
It describes the current version of the content in this slot.
The updater compares the version to the one it provides and skips update if their version is identical.
This may save time.

Example:

::

  SHA256=e437ab217356ee47cd338be0ffe33a3cb6dc1ce679475ea59ff8a8f7f6242b27


Booting
=======

To determine from which device / slot the system should be booted barebox *bootchooser* is used.
This allows to maintain multiple potential systems with a *defined priority* and a *number of boot attempts*.
If booting from the highest-priority system (typically the current productive system) fails for e.g. 3 times,
the next lower priority boot source is chosen which could be the fallback system for example.

As updates are always installed in the currently inactive slot set, the boot order must be changed
after a successful update.

- prefer booting an outdated system or the fallback system in case of boot failure of active system?


Signature and Verification
==========================

- nss or x509 certificate verification

Key Update
----------

TODO


Key Revocation
--------------

TODO


Generate systems and fimware images
===================================

A build system is used to generat all the slot images required for an update bundle

Then the ``rauc bundle`` tool can be used to generate a signed RAUC update bundle.

::

  rauc bundle <input-dir> <output-bundle>

::

  rauc bundle --key=<keyfile> <input-dir> <output-file>

Generate Fallback System
------------------------

The fallback system is a minimal linux system which is generated with Yocto.
It must be installed using conventional approaches such as manually copying disk images.

::

  bitbake fallback-system

Content of the system

- minimal kernel
  
- miniml rootfs

  - update service
  
  - system info file (info.ini)
  
  - default updater script

- barebox bootloader
  - state, bootchoser framework


The fallback system does not provide slot info!?



Generate Update image
---------------------




Therfor Yocto-generated slot images must include:


- rootfs

  - typical content of rootfs

  - update service
  
  - system info file
  
  - default updater script

     - update handler (manually created or generated!?)

- appfs

  - typical content of aptfs


Yocto must generate:

- slot image hashes

- Update info (info.ini)
  
- optional: Update skript

::

  bitbake my-update-image


RAUC
====

RAUC CLI
--------


::

  rauc publish --key=<keyfile> <input-dir> <output-dir>

::

  rauc resign --key=<keyfile> <input-bundle> <output-bundle>

::

  rauc status

RAUC command API
----------------

Used by the handler to control RAUC

  rauc-cmd boot <slot>

  rauc-cmd mount <slot>

  rauc-cmd umount <slot>


RAUC handler 
------------

  - executable script
  
  - parameters passed as environment variables (e.g. active slot, target slot, mount path prefix, source directory)

  - format slot (if needed)

  - mount slot

  - copy image to slot

  - unmount slot

  - select next boot source

  - reboot?


**Signing**

To sign the image a separate tool is used as it might be required to do this step
on an extra signing server.

X. System Setup
---------------

By default an updatable platform should provide 3 slots from which one is the fallback system
and the other two are for productive systems.
If possible, the fallback system slot along with the bootloaders
should be placed in a different (read-only) storage than the productive system slots.


Future Tasks:
=============

RAUC handler CLI

::

  rauc-handler prepare <device> <slot-mountpoint>

- mount, (format,)

::

  rauc-handler install <img> <slot-mountpoint>

- install image to mounted slot

::

  rauc-handler finalize <slot-mountpoint>

- unmount, select next boot source
  (e.g. for 

NOTE: rauc mounts! mount-hook?
