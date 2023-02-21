RAUC Basics
===========

From a top view, the RAUC update framework provides a solution for four basic
tasks:

* generating update artifacts
* signing and verification of update artifacts
* robust installation handling
* interfacing with the boot process

RAUC is basically an image-based updater, i.e. it installs file images on
devices or partitions.
But, for target devices that can have a file system, it also supports
installing contents from tar archives.
This often provides much more flexibility as a tar does not have to fit a
specific partition size or type.
RAUC ensures that the target file system will be set up correctly before
unpacking the archive.

Update Artifacts -- Bundles
---------------------------

In order to know how to pack multiple file system images, properly handle
installation, being able to check system compatibility and for other
meta-information RAUC uses a well-defined update artifact format, simply
referred to as *bundles* in the following.


A RAUC bundle consists of the file system image(s) or archive(s) to be installed
on the system, a *manifest* that lists the images to install and contains
options and meta-information, and possible scripts to run before, during or
after installation.
A bundle may also contain files not referenced in the manifest,
such as scripts or archives that are referenced by files that *are*
included in the manifest.

To pack this all together, these contents are collected into a SquashFS image.
This provides good compression while allowing to mount the bundle without
having to unpack it on the target system.
This way, no additional intermediate storage is required.
For more details see the :ref:`sec_ref_formats` section.

A key design decision of RAUC is that signing a bundle is mandatory.
For development purpose a self-signed certificate might be sufficient,
for production the signing process should be integrated with your PKI
infrastructure.

.. important:: A RAUC Bundle should always unambiguously describe the
  intended target state of the entire system.

HTTP Streaming
~~~~~~~~~~~~~~

Since RAUC 1.7, bundles can be installed directly from a HTTP(S) server,
without having to download and store the bundle locally.
Simply use the bundle URL as the ``rauc install`` argument instead of a local
file.

Using streaming has a few requirements:

* configure RAUC with ``--enable-streaming``
* create bundles using the :ref:`verity format <sec_ref_format_verity>`
* host the bundle on a server which supports HTTP Range Requests
* enable NBD support in the kernel

See the :ref:`HTTP Streaming <http-streaming>` section in the Advanced chapter
for more details.

.. _sec-compatibility:

Forward and Backward Compatibility
----------------------------------

Our overall goal with regards to compatibility is a good balance between the
requirements of users and the constraints during development.
For users, it is mainly relevant how a given version of RAUC on the target
handles bundles produced by older (backward compatibility) and newer versions
(forward compatibility) of RAUC.
As developers, we want to keep the effort for supporting old versions in the
field at a reasonable level and have the flexibility to improve RAUC with new
versions.

To ensure forward compatibility, new bundle features need to be enabled
explicitly during bundle creation.
So without changing the manifest, newer RAUC versions used for bundle creation
will not require new versions on the target.
This includes new bundle formats, new hooks, adaptive updates or additional
metadata.
When a new (incompatible) feature is enabled in a bundle, older RAUC versions
will report an error during installation to ensure that the installation result
is deterministic.
As long as you don't enable new features during creation, our intention is that
bundles created by newer versions will be installable by older versions and any
such issues would be considered a bug.

To ensure backward compatibility, support for older bundle features is enabled
by default and can be disabled explicitly in the RAUC ``system.conf`` as
needed.
To keep RAUC maintainable, we may need to deprecate and later remove support
for old features over time.
This would be done with several years between deprecation and removal so that
at least one Yocto LTS version contains a RAUC version that warns when using
the deprecated feature, giving users enough time to migrate away from that
feature.
Any issues with installing bundles created by an old RAUC version using new
RAUC version would be considered a bug, except when using a feature removed
after the deprecation period.
Also, please contact us if a deprecation period is too short for your case.

Furthermore, we avoid depending on new kernel features or library versions, so
that it is possible to switch to newer RAUC versions without having to switch
to a new distribution release at the same time.
The guideline is that we can depend on new features only when they are
available in all versions still actively supported by the respective upstream
projects.

As a result, users that update at least every two years (for example by
following Yocto LTS releases) should receive deprecation warnings early enough
to handling them via normal updates.

RAUC's System View
------------------

Apart from bundle signing and verification, the main task of RAUC is to ensure
that all images in your update bundle are copied in the proper way to the proper
target device / partition on your board.

In order to allow RAUC to handle your device right, we need to give it the
right view on your system.

Slots
~~~~~

In RAUC, everything that can be updated is a *slot*.
Thus a slot can either be a full device, a partition, a volume or simply a file.

To let RAUC know which slots exists on the board that should be handled,
the slots must be configured in a *system configuration file*.
This file is the central instance that tells RAUC how to handle the board, which
bootloader to use, which custom scripts to execute, etc.

The slot description names, for example, the file path the slot can be accessed
with, the type of storage or filesystem to use, its identification from the
bootloader, etc.

Target Slot Selection
~~~~~~~~~~~~~~~~~~~~~

A very important step when installing an update is to determine the correct
mapping from the images that are contained in a RAUC bundle to the slots that
are defined on the target system.
The updated must also assure to select an inactive slot, and not accidentally a
slot the system currently runs from.

For this mapping, RAUC allows to define different *slot classes*.
A class describes always multiple redundant slots of the same type.
This can be, for example, a class for root file system slots or a
class for application slots.

Note that despite the fact that classic A+B redundancy is a common setup for
many systems, RAUC conceptually allows any number of redundant slots per class.

Now, multiple slots of different classes can be grouped as a *slot group*.
Such a group is the base for the slot selection algorithm of RAUC.

Consider, for example, a system with two redundant rootfs slots and two
redundant application slots. Then you group them together to have a fixed set
of a rootfs and application slot each that will be used together.

.. image:: images/rauc-multi-image.svg
   :width: 500
   :align: center

To detect the active slots, RAUC attempts to detect the currently booted slot.
For this, it relies on explicit mapping information provided via kernel command
line or attempts to find it out using mount information.

All slots of the group containing the active slot will be considered active,
too.

Slot Status and Skipping Slot Updates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RAUC hashes each image or archive with SHA-256 when packing it into a bundle
and stores this as the images 'checksum' in the bundle's manifest file.
This checksum allows to reliably identify and distinguish the image's content.

When installing an image, RAUC can write the images checksum together with some
status information to a central or per-slot status file
(refer :ref:`statusfile <statusfile>` option).

The next time RAUC attempts to install an image to this slot, it will first
check the current checksum of the slot by reading its status information, if
available.
If this checksum equals the checksum of the image to write, RAUC can skip
updating this slot as a configurable performance optimization
(refer :ref:`install-same <install-same>` per-slot option).

Note that this method assumes the target's file-systems are read-only as it
cannot detect modifications.
Given this restriction, slot skipping can be a lightweight optimization for
systems where some slot's update images change more frequently than others.

.. note:: When combining this with RAUC's built-in HTTP(s) bundle streaming,
   this will also prevent downloading skipped images and thus save download
   volume.

.. _sec-boot-slot:

Boot Slot Selection
~~~~~~~~~~~~~~~~~~~

A system designed to run from redundant slots must always have a component that
is responsible for selecting between the bootable slots.
Usually, this will be some kind of bootloader, but it could also be an initramfs
booting a special purpose Linux system.

Of course, as a normal user-space tool, RAUC cannot do the selection itself, but
provides a well-defined interface and abstraction for interacting with different
bootloaders (e.g. GRUB, Barebox, U-Boot) or boot selection methods.

.. image:: images/bootloader_interface.svg
   :width: 500
   :align: center

In order to enable RAUC to switch the correct slot, its system configuration
must specify the name of the respective slot from the bootloader's perspective.
You also have to set up an appropriate boot selection logic in the bootloader
itself, either by scripting (as for GRUB, U-Boot) or by using dedicated boot
selection infrastructure (such as bootchooser in Barebox).

The bootloader must also provide a set of variables the Linux userspace can
modify in order to change boot order or priority.

Having this interface ready, RAUC will care for setting the boot logic
appropriately.
It will, for example, deactivate the slot to update before writing to it
and reactivate it after having completed the installation successfully.

Installation and Storage Handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As mentioned above, RAUC basically writes images to devices or partitions, but
also allows installing file system content from (compressed) tar archives.

In addition to the need for different methods to write to storage (simple copy
for block devices, nandwrite for NAND, ubiupdatevol for UBI volumes, …) the
tar-based installation requires additional handling and preparation of storage.

Thus, the possible and required handling depends on both the type of input
image (e.g. .tar.xz, .ext4, .img) as well as the type of storage.
A tar can be installed on different file systems while an ext4 file system slot
might be filled by both an .ext4 image or a tar archive.

To deal with all these possible combinations, RAUC provides an update handler
algorithm that uses a matching table to define valid combinations of image and
slot type while specifying the appropriate handling.

.. image:: images/rauc_update_handler.svg
   :width: 400
   :align: center

Boot Confirmation & Fallback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When designing a robust redundant system, update handling does not end with the
successful installation of the update on the target slots!
Having written your image data without any errors does not mean that the system
you just installed will really boot.
And even if it boots, there may be crashes or invalid behavior only revealed
at runtime or possibly not before a number of days and reboots.

To allow the boot logic to detect if booting a slot succeeded or failed,
it needs to receive some feedback from the booted system.
For marking a boot as either successful or bad, RAUC provides the commands
`status mark-good` and `status mark-bad`.
These commands interact through the boot loader interface with the respective
bootloader implementation to indicate a successful or failed boot.

As detecting an invalid boot is often not possible, i.e. because simply nothing
boots or the booted system suddenly crashes, your system should use a hardware
watchdog to during boot and have support in the bootloader to detect watchdog
resets as failed boots.

Also you need to define what happens when a boot slot is detected to be
unusable.
For most cases it might be desired to either select one of the redundant slots
as fallback or boot into a recovery system.
This handling is up to your bootloader.
