Updating your Embedded Device
=============================

This chapter does not explicitly tell you anything about RAUC itself, but it
provides an initial overview of basic requirements and design consideration
that have to be taken into account when designing an update architecture for
your embedded device.

Some hints are already useful when designing the device itself, here you can
set the base for a great embedded system. For some other systems it might not
be (completely) in your hand to select the best hardware.
But don't fear, we can also deal with these cases.


Storage Type and Size
---------------------

The type and amount of available storage on your device has a huge impact on
the design of your updatable embedded system.

If the available storage is not much larger than the space required by your
devices rootfs, a full redundant symmetric A/B setup will not be an option.
In this case, you might need use a rescue system consisting of a minimal kernel
with an appended initramfs to install your updates.

If you can choose the storage technology for your system, *DO NOT* choose raw
NAND flash and calculate for at least 2x the size of your rootfs plus
additionally required space, e.g. for bootloader, (redundant) data storage,
etc.


Update Source and Provisioning
------------------------------

USB Stick to deployment server.

Security
--------

An update tool should ensure that no unauthorized entity is able to update your
device. This can be done by having

  a) a secure channel to transfer the update or
  b) a signed update that allows you to verify its author.

Note that the latter method is more flexible and might be the only option if
you intend to use a USB stick for example.


Interfacing with your Bootloader
--------------------------------

The bootloader is the final instance that controls which partition on your
rootfs device will be booted. In order to switch partitions after an update,
you have to have an interface to the bootloader that allows you to set the boot
order, boot priority and other possible parameters.

Some bootloaders, such as U-Boot, allow access to their environment storage
where you can freely create and modify variables the bootloader may read.
Boot logic often can be implemented by a simple boot script.

Some others have distinct redundancy boot interfaces with redundant state
storage. These often provide more features then simply switching boot
partitions and are less prone to errors when used.
The Barebox bootloader with its bootchooser framework is a good example for
this.
