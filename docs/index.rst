.. RAUC documentation master file, created by
   sphinx-quickstart on Fri Jan 22 16:00:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to the RAUC documentation!
==================================

Contents:

.. toctree::
   :glob:
   :numbered:
   :maxdepth: 1

   updating
   using
   examples
   scenarios
   checklist
   integration
   reference
   terminology
   design
   contributing

   changes

* :ref:`search`
* :ref:`genindex`

Overview
========

The Need for Updating
---------------------

Updating an embedded system is always a crucial step during the life cycle of
an embedded hardware product. Updates are important to either fix system bugs,
solve security problems or simply for adding new features to a platform.

As embedded hardware often is placed in locations that make it difficult or
costly to gain access to the board itself, an update must be performed unattended;
for example either by plugging in a special USB stick or by some network
roll-out strategy.

Updating an embedded system is risky; an update might be incompatible, a
procedure crashes, the underlying storage fails with a write error, or someone
accidentally switches the power off, etc. All this may occur but should not
lead to having an unbootable hardware at the end.

Another point besides safe upgrades are security considerations. You would like
to prevent that someone unauthorized is able to load modified firmware onto the
system.

What is RAUC?
-------------

RAUC is a lightweight update client that runs on your embedded device and
reliably controls the procedure of updating your device with a new firmware
revision. RAUC is also the tool on your host system that lets you create, inspect
and modify update artifacts for your device.

The decision to design was made after having worked on several custom update
solutions for different projects again and again while always facing different
issues and unexpected quirks and pitfalls that were not taken into
consideration before.

Thus, the aim of RAUC is to provide a well-proven, solid and generic base for
the different custom requirements and restrictions an update concept for a
specfic platform must deal with.

When designing the RAUC update tool, all of these requirements were taken into
consideration. In the following, we provide a short overview of basic concepts,
principles and solutions RAUC provides for updating an embedded system.

Key Features of RAUC
--------------------

* **Fail-Safe & Atomic**:

  * An update may be interrupted at any point without breaking the running
    system.
  * Update compatibility check

* **Cryptographic signing and verification** of updates using OpenSSL (signatures
  based on x.509 certificates)

* **Flexible and customizable** redundancy/storage setup

  * **Symmetric** setup (Root-FS A & B)
  * **Asymmetric** setup (recovery & normal)
  * Application partition, data partitions, ...
  * Allows **grouping** of multiple slots (rootfs, appfs) as update targets

* Supports common bootloaders

  * `grub <https://www.gnu.org/software/grub/>`_
  * `barebox <http://barebox.org/>`_

    * Well integrated with `bootchooser <http://barebox.de/doc/latest/user/bootchooser.html?highlight=bootchooser>`_ framework
  * `u-boot <http://www.denx.de/wiki/U-Boot>`_

* Storage support:

  * ext2/3/4 filesystem
  * UBI volumes
  * UBIFS
  * raw NAND (using nandwrite)
  * squashfs

* Independent from updates source

  * **USB Stick**
  * Software provisioning server (e.g. **Hawkbit**)

* Controllable via **D-Bus** interface

* Supports data migration

* Network protocol support using libcurl (https, http, ftp, ssh, ...)

* Several layers of update customization

  * Update-specific extensions (hooks)
  * System-specific extensions (handlers)
  * Fully custom update script

* Yocto support in `meta-rauc <https://github.com/rauc/meta-rauc>`_
