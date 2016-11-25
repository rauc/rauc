Overview
========

Introduction
------------

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

When designing the rauc update tool, all of these requirements were taken into
consideration. In the following, we provide a short overview of basic concepts,
principles and solutions rauc provides for updating an embedded system.

Features
--------

* Supports whole-system updates using at least two redundant installations:

  * Symmetric: Root-FS A & Root-FS B
  * Asymmetric: recovery & normal
  * Also supports custom partition layouts
* Fail-Safe: no change to the running system
* Two update modes:

  * Bundle: single file containing the whole update
  * Network: separate manifest and component files
* Bootloader support:

  * [grub](https://www.gnu.org/software/grub/)
  * [barebox](http://barebox.org/)
  * [u-boot](http://www.denx.de/wiki/U-Boot)
* Storage support:

  * raw (ext2/3/4, btrfs, squashfs, ...)
  * ubi (using [UBI volume update](http://www.linux-mtd.infradead.org/doc/ubi.html#L_volupdate))
* Network protocol support using libcurl (https, http, ftp, ssh, ...)
* Cryptographic verification using OpenSSL (signatures based on x.509
  certificates)

Redundancy
----------

Being able to safely update an entire system with pre-defined images
normally requires more than one bootable device or partition available.
A minimal setup would consist of a running system on slot A and an inactive
system on slot B. A bootloader is responsible for booting the desired system.

Now, the running system may perform an update on the inactive slot B.
Once the update was performed successfully, the system must tell the bootloader
to boot from slot B from now on.
To add more safety, a third bootable slot C may be used containing a minimal
fall-back system the bootloader may choose if booting from the other slots fails.
This one might also be used to initially install a production system on a
new device.

In the following an overview of the basic concept rauc uses for realizing such
an update system is provided.

Slots
-----

Rauc's view of the target system it is running on is described using so-called
slots. Slots are possible targets for (parts of) updates. Usually, they are
partitions on an SD/eMMC, UBI volumes on NAND/NOR flash or raw block devices.
The system designer must provide a configuration file that lists all slots that
rauc should use and describe which device they are stored on, how the
bootloader may detect them, etc.

Bundles
-------

An update bundle is a squashfs-packed set of config files, scripts, and disk
images with an appended signature that allows verifying the bundle's origin and
integrity.

Booting
-------

To determine from which slot the system is booted, the bootloader must provide
a *boot chooser*.
This allows maintaining multiple boot sources with a *defined priority*, a
*number of boot attempts*, and a flag to deactivate the source.

If booting from the highest-priority system (typically the current production
system) fails for e.g. 3 times, the next lower priority boot source is chosen
(which could be the fallback system).

As updates are always installed in a currently inactive slot, the boot priority
must be changed after a successful update.

Basic Update Procedure
----------------------

The rauc service that runs on the target will perform an update when being
triggered by an install command providing an update bundle.
An update request may be initiated manually from the command line, via D-Bus or
by a script that checks for example for insertion of an USB stick containing a
firmware bundle. Then the default (and simplified) update behavior will be the
following:

1. Rauc verifies the bundle by checking its signature against the keyring
   located in the root file system. A bundle with an invalid signature will be
   rejected.

2. Rauc mounts the bundle (which simply is a squashfs image)

3. Verify bundle compatibility:

   - The compatible string in the manifest is compared against the compatible
     string stored in the system configuration file.
   - If the strings are different, the bundle will be rejected to prevent
     installing an incompatible bundle.

4. Determine the target *install group*, i.e. which slots an update will be
   installed to.

7. Mark target slots as non-bootable for bootloader.

6. Iterate over each image specified in the manifest

   * Try to read slot status informations.
   * If the provided slot image is different from the installed one:
     Update slot with a method determined by the type of slot and the image type.
   * Try to write slot status informations.

7. Mark target slots as new primary boot source for the bootloader.

8. Terminate successfully if no error occurred.

Once the update controller receives an update request instruction containing
the file path of a firmware bundle it verifies its signature based on a public
key stored in the current rootfs.
If the signature is valid, the service loopback-mounts the bundle to access its
content and installs the update.

Installing the update means either calling an *update handler* included in the
bundle (if provided) or using a default handler that performs the update
based on information about the available slots and versions.


Target Slot Selection
---------------------

The *boot chooser* (in the bootloader) passes the name of the booted slot using
the kernel command line. This allows the *controller* to identify the currently
active slots.

To select the target slot, the controller first looks for a slot marked as
non-bootable. This could be caused by an interrupted update or repeated boot
failures.

If no non-bootable slot exists, the inactive slot with the lowest priority is
selected.


* Motivation
   * Updates required: safety, security, feature updates
   * Ensure defined and consistent system state
   * Ensure the system can always boot to an updatable system
* Features
   * Remote via the network
   * Unattended/automatic vs. manual
   * Local via USB memory stick
   * Protection against user errors
   * Signed updates
   * Image vs. file updates
   * Support for different scenarios
      * two symmetric slots
      * one full + one rescue slot
   * D-Bus interface
* Requirements
   * System watchdog (optional)
   * Stage storage
* Out-of-scope cases
