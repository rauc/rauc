Updating your Embedded Device
=============================

This chapter does not explicitly tell you anything about RAUC itself, but it
provides an initial overview of basic requirements and design consideration
that have to be taken into account when designing an update architecture for
your embedded device.

Thus, if you know about updating and are interested in RAUC itself, only,
simply skip this chapter.

Nevertheless, this chapter could also provide some useful hints that can
already be useful when designing the device you intend to update later on.
In this you initial phase you can prevent yourself from making wrong decisions.


Redundancy and Atomicity
------------------------

There are two key requirements for allowing you to robustly update your system.

The first one is redundancy:
You must not update the system you are currently running on.
Otherwise a failure during updating will brick the only system you can run your
update from.

The second one is atomicity:
Writing your update to the currently inactive device is a critical operation.
A failure occurring during this installation must not brick your device.
Thus you must make sure to tell your boot logic to select the updated device
not before being very sure that the update successfully completed.
Additionally, the operation that switches the boot device must be atomic
itself.

Storage Type and Size
---------------------

The type and amount of available storage on your device has a huge impact on
the design of your updatable embedded system.

Except when optimizing for the smallest storage requirements possible, your
system should have two redundant devices or partitions for your root
file-system.
This full symmetric setup allows you to run your application while safely
updating the inactive copy.
Additionally, if the running system become corrupted for any reason, you may
fall back to you second rootfs device.

If the available storage is not much larger than the space required by your
devices rootfs, a full redundant symmetric A/B setup will not be an option.
In this case, you might need to use a rescue system consisting of a minimal kernel
with an appended initramfs to install your updates.

.. note::
  If you can choose the storage technology for your system, *DO NOT* choose raw
  NAND flash.
  NAND (especially MLC) is complex to handle correctly and comes with a
  variety of very specific effects that may cause difficult to debug problem later
  (if not all details of the storage stack are configured just right).
  Instead choose eMMC or SSDs, where the engineers who (hopefully) know the quirks
  of their technology have created layers that hide this complexity to you.

If storage size can be freely chosen, calculate for at least 2x the size of
your rootfs plus additionally required space, e.g. for bootloader, (redundant)
data storage, etc.

Security
--------

An update tool or the infrastructure around it should ensure that no
unauthorized entity is able to update your device.
This can be done by having:

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
storage. These often provide more features than simply switching boot
partitions and are less prone to errors when used.
The Barebox bootloader with its bootchooser framework is a good example for
this.

Update Source and Provisioning
------------------------------

Depending on your infrastructure or requirements, an update might be deployed in
several ways.

The two most common ones are over network, e.g. by using a deployment server,
or simply over a USB stick that will be plugged into the target system.
