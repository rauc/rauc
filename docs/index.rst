.. RAUC documentation master file, created by
   sphinx-quickstart on Fri Jan 22 16:00:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to the RAUC documentation!
==================================

Contents:

.. toctree::
   :glob:
   :maxdepth: 1

   updating
   basic
   using
   examples
   scenarios
   integration
   advanced
   checklist
   faq
   reference
   man
   terminology
   contributing

   changes

* :ref:`search`
* :ref:`genindex`

The Need for Updating
---------------------

Updating an embedded system is always a critical step during the life cycle of
an embedded hardware product.
Updates are important to either fix system bugs, solve security problems or
simply for adding new features to a platform.

As embedded hardware often is placed in locations that make it difficult or
costly to gain access to the board itself, an update must be performed unattended;
for example either by connecting a special USB stick or via some network roll-out
strategy.

Updating an embedded system is risky; an update might be incompatible, a
procedure crashes, the underlying storage fails with a write error, or someone
accidentally switches the power off, etc.
All this may occur but should not lead to having an unbootable hardware at the
end.

Another point besides safe upgrades are security considerations.
You would like to prevent that someone unauthorized is able to load modified
firmware onto the system.

What is RAUC?
-------------

RAUC is a lightweight update client that runs on your embedded device and
reliably controls the procedure of updating your device with a new firmware
revision.
RAUC is also the tool on your host system that lets you create, inspect and
modify update files ("*bundles*") for your device.

The decision to design was made after having worked on custom update solutions
for different projects again and again while always facing different issues and
unexpected quirks and pitfalls that were not taken into consideration before.

Thus, the aim of RAUC is to provide a well-tested, solid and generic base for
the different custom requirements and restrictions an update concept for a
specific platform must deal with.

When designing the RAUC update tool, all of these requirements were taken into
consideration.
In the following, we provide a short overview of basic concepts, principles and
solutions RAUC provides for updating an embedded system.

And What Not?
-------------

RAUC is NOT a full-blown updating application or GUI.
It provides a CLI for testing but is mainly designed to allow seamless
integration into your individual Applications and Infrastructure by providing a
D-Bus interface.

RAUC can NOT replace your bootloader who is responsible for selecting the
appropriate target to boot, but it provides a well-defined interface to
incorporate with all common bootloaders.

RAUC does NOT intend to be a deployment server.
On your host side, it only creates the update bundles.
You may want to have a look at
`rauc-hawkbit-updater <https://github.com/rauc/rauc-hawkbit-updater>`_ for
interfacing with the hawkBit deployment server.

RAUC bundles are NOT a general purpose transport container.
This means that on your target side you should not use ``rauc extract``.
Instead use ``rauc install`` or the D-Bus API to trigger an installation.
Any necessary customization should be done using hooks and handlers.

And finally, factory bring up of your device, i.e. initial partitioning etc. is
also out of scope for an update tool like RAUC.
While you may use it for initially filling your slot contents during factory
bring up, the partitioning or volume creation must be made manually or by a
separate factory bring up tool (such as `systemd-repart
<https://www.freedesktop.org/software/systemd/man/systemd-repart.html>`_).

Key Features of RAUC
--------------------

* **Fail-Safe & Atomic**:

  * An update may be interrupted at any point without breaking the running
    system.
  * Update compatibility check
  * Mark boots as successful / failed

* **Cryptographic signing and verification** of updates using OpenSSL (signatures
  based on x.509 certificates)

  .. image:: images/rauc_safety_security.png
     :width: 500

  * Keys and certificates on **PKCS#11 tokens** (HSMs) are supported

* Built-In **HTTP(S) streaming** support for updates

  * No intermediate storage on target required.

* Optional **encryption** of update bundles

  * Encryption for a single or multiple recipients (public keys) supported

* **Flexible and customizable** redundancy/storage setup

  .. image:: images/rauc_update_cases.svg
     :width: 600

  * **Symmetric** setup (Root-FS A & B)
  * **Asymmetric** setup (recovery & normal)
  * Application partition, data partitions, ...
  * Allows **grouping** of multiple slots (rootfs, appfs) as update targets

* **Bootloader interface supports common bootloaders**

  .. image:: images/bootloader_interface.svg
     :width: 600

  * `grub <https://www.gnu.org/software/grub/>`_
  * `barebox <http://barebox.org/>`_

    * Well integrated with `bootchooser <http://barebox.de/doc/latest/user/bootchooser.html?highlight=bootchooser>`_ framework
  * `u-boot <http://www.denx.de/wiki/U-Boot>`_
  * `EFI <https://de.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface>`_

* Storage support:

  * ext4 filesystem
  * eMMC boot partitions (atomic update)
  * vfat filesystem
  * UBI volumes
  * UBIFS
  * JFFS2
  * raw NAND flash (using nandwrite)
  * raw NOR flash (using flashcp)
  * squashfs
  * MBR partition table
  * GPT partition table

* Independent from update sources

  * **USB Stick**
  * Software provisioning server (e.g. **Hawkbit**)

* Controllable via **D-Bus** interface

* Supports data migration

* Several layers of update customization

  * Update-specific extensions (hooks)
  * System-specific extensions (handlers)
  * Fully custom update script

* Build-system support

  .. |yocto_logo| image:: images/yocto.png
     :width: 200

  .. |ptxdist_logo| image:: images/ptxdist_logo.png
     :width: 200

  .. |buildroot_logo| image:: images/buildroot_logo.png
     :width: 200

  +-----------------------------+----------------------------------+----------------------------------+
  ||yocto_logo|                 | |ptxdist_logo|                   | |buildroot_logo|                 |
  +-----------------------------+----------------------------------+----------------------------------+
  |Yocto support in meta-rauc_  | PTXdist support since 2017.04.0. | Buildroot_ support since 2017.08 |
  +-----------------------------+----------------------------------+----------------------------------+

.. _meta-rauc: https://github.com/rauc/meta-rauc

.. _buildroot: https://www.buildroot.org

.. meta::
   :google-site-verification: wLmZ0Ehh9wAjp6f23ckkSFyQtNEIW2wUfpv-r5kYv2M
