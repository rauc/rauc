.. _sec-scenarios:

Scenarios
=========

Symmetric Root-FS Slots
-----------------------

This is the probably the most common setup.
In this case, two root partitions of the same size are used (often called "A"
and "B").
When running from "A", an update is installed into "B" and vice versa.
Both slots are intended to contain equivalent software, including the main
application.

To reduce complexity, the kernel and other files necessary for booting the
system (such as the device tree) are stored in the root-fs partition (usually in
/boot).
This requires a boot-loader with support for the root-fs type.

The RAUC ``system.conf`` would contain two slots similar to the following:

.. code-block:: cfg

  [slot.rootfs.0]
  device=/dev/sda0
  type=ext4
  bootname=system-a

  [slot.rootfs.1]
  device=/dev/sda1
  type=ext4
  bootname=system-b

The main advantage of this setup is its simplicity:

* An update can be started when running in either slot and while the main
  application is still active.
* The fallback logic in the boot-loader can be relatively simple.
* Easy to understand update process for end-users and technicians.

The main reasons for not using it are either:

* Too limited storage space (use asymmetric slots instead)
* Additional requirements regarding redundancy or update flexibility (see below)

Asymmetric Slots
----------------

This setup is useful if the storage space is very limited.
Instead of requiring two partitions each large enough for the full installation,
a small partition is used instead of the second one (often called "main" and
"update" or "rescue").

The slot configuration for this in ``system.conf`` could look like this:

.. code-block:: cfg

  [slot.update.0]
  device=/dev/sda0
  type=raw
  bootname=update

  [slot.main.1]
  device=/dev/sda1
  type=ext4
  bootname=main

To update the main system, a reboot into the update system is needed (as otherwise
the main slot would still be active).
Then, the update system would trigger the installation into the main slot and
finally switch back to the newly updated main system.
The update system itself can be updated directly from the running main system.

Some disadvantages of this configuration are:

* Two reboots are required for an update.
* A failed update results in an unavailable main application until a subsequent
  update is installed successfully.
* If some data in the main slot needs to be preserved during the update, it must
  be stored somewhere else before writing the new image to the slot and then
  restored.

As the update system is normally small enough to fit completely into RAM, it can
be stored as a Linux kernel with internal initramfs.
This avoids compressing kernel and user-space separately, increasing the
compression ratio.
For this, the update slot type should be configured to ``raw``.

Multiple Slots
--------------

Splitting a system into multiple slots can be useful if the application should
be updated independently of the base system.
This can be combined with either symmetric or asymmetric setups as described
above.

For example, the main application could be split of from the root file-system.
This can be useful if the base system is developed independently from the
application(s) or by a different team.
By explicitly distinguishing between the two, different versions of the
application or even completely different applications can reuse the same base
system (root-file-system).

Another reason to configure multiple slots for one system can be to store the
boot files (kernel, …) separately, which can help reduce boot time and
complexity in the boot-loader.

.. code-block:: cfg

  [slot.rootfs.0]
  device=/dev/sda0
  type=ext4
  bootname=system-a

  [slot.appfs.0]
  device=/dev/sda1
  type=ext4
  parent=rootfs.0

  [slot.rootfs.1]
  device=/dev/sdb0
  type=ext4
  bootname=system-b

  [slot.appfs.1]
  device=/dev/sdb1
  type=ext4
  parent=rootfs.1

.. warning::

   Currently, RAUC has no way to ensure compatibility between rootfs and appfs
   when installing a bundle containing only an image for one of them.
   Either always build bundles containing images for all required slots or
   ensure that incompatible updates are not installed outside of RAUC.
   To solve this, a bundle would need to contain the metadata (size and hash)
   for the missing bundle and RAUC would need to verify the state of those slots
   before installing the bundle.

Additional Rescue Slot
----------------------

By adding an additional rescue (or recovery) slot to one of the symmetric
scenarios above, the robustness against some error cases can be improved:

* A software error has remained undetected over some releases, rendering both
  normal slots inoperable over time.
* The normal slots are mounted read-write during normal operation and have
  become corrupted (for example by incorrect handling of sudden power failures).
* A configuration error causes both normal slots to fail in the same way.

.. code-block:: cfg

  [slot.rescue.0]
  device=/dev/sda0
  type=raw
  bootname=rescue

  [slot.rootfs.0]
  device=/dev/sda1
  type=ext4
  bootname=system-a

  [slot.rootfs.1]
  device=/dev/sda2
  type=ext4
  bootname=system-b

The rescue slot would not be changed by normal updates (which only write to A
and B in turn).
Depending on the use case, the boot-loader would start the rescue system after
repeated boot failures of the normal systems or on user request.
