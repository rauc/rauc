Examples
========

Full System Example
-------------------

This chapter aims to explain the basic concepts needed for RAUC using a simple
but realistic scenario.

The system is x86-based with 1GiB of disk space and 1GiB of RAM.
GRUB_ was selected as the bootloader and we want to have two symmetric
installations.
Each installation consists of an ext4 root file system only (which contains the
matching kernel image).

We want to provide update bundles using a USB memory stick.
We don't have a hardware watchdog, so we need to explicitly tell GRUB_ whether
a boot was successful.

This scenario can be easily reproduced using a QEMU_ virtual machine.

.. _GRUB: https://www.gnu.org/software/grub/
.. _QEMU: http://wiki.qemu.org/

PKI Setup
~~~~~~~~~

RAUC uses an x.509 PKI (public key infrastructure) to sign and verify updates.
To create a simple key pair for testing, we can use ``openssl``::

  > openssl req -x509 -newkey rsa:4096 -nodes -keyout demo.key.pem -out demo.cert.pem -subj "/O=rauc Inc./CN=rauc-demo"

For actual usage, setting up a real PKI (with a CA separate from the signing
keys and a revocation infrastructure) is *strongly* recommended.
OpenVPN's easy-rsa_ is a good first step.
See :ref:`sec-security` for more details.

.. _easy-rsa: https://github.com/OpenVPN/easy-rsa

RAUC Configuration
~~~~~~~~~~~~~~~~~~

We need a RAUC system configuration file to describe the slots which can be
updated

.. code-block:: cfg

  [system]
  compatible=rauc-demo-x86
  bootloader=grub
  mountprefix=/mnt/rauc
  bundle-formats=-plain

  [keyring]
  path=demo.cert.pem

  [slot.rootfs.0]
  device=/dev/sda2
  type=ext4
  bootname=A

  [slot.rootfs.1]
  device=/dev/sda3
  type=ext4
  bootname=B

In this case, we need to place the signing certificate into the same
directory as the ``system.conf``, so that it is used by RAUC for verification.

GRUB Configuration
~~~~~~~~~~~~~~~~~~

GRUB itself is stored on ``/dev/sda1``, separate from the root file system.
To access GRUB's environment file, this partition should be mounted to
``/boot``
(which means that the environment file is found at ``/boot/grub/grubenv``).

GRUB does not provide the boot target selection logic as needed by RAUC
out of the box.
Instead we use a script to implement it

.. code-block:: sh

  # set default menuentry (Slot A) and timeout (3s)
  default=0
  timeout=3

  any_ok=0

  set ORDER="A B"
  set A_OK=0
  set B_OK=0
  set A_TRY=0
  set B_TRY=0
  load_env

  # select bootable slot
  for SLOT in $ORDER; do
      if [ "$SLOT" == "A" ]; then
          INDEX=0
          OK=$A_OK
          TRY=$A_TRY
          A_TRY=1
      fi
      if [ "$SLOT" == "B" ]; then
          INDEX=1
          OK=$B_OK
          TRY=$B_TRY
          B_TRY=1
      fi
      if [ "$OK" -eq 1 -a "$TRY" -eq 0 ]; then
          default=$INDEX
          any_ok=1
          break
      fi
  done

  # reset booted flags in case both sides have failed to boot
  if [ "$any_ok" -eq 0 ]; then
      if [ "$A_OK" -eq 1 -a "$A_TRY" -eq 1 ]; then
          A_TRY=0
      fi
      if [ "$B_OK" -eq 1 -a "$B_TRY" -eq 1 ]; then
          B_TRY=0
      fi
  fi

  save_env A_TRY B_TRY

  CMDLINE="panic=60 quiet"

  menuentry "Slot A (OK=$A_OK TRY=$A_TRY)" {
      linux (hd0,2)/kernel root=/dev/sda2 $CMDLINE rauc.slot=A
  }

  menuentry "Slot B (OK=$B_OK TRY=$B_TRY)" {
      linux (hd0,3)/kernel root=/dev/sda3 $CMDLINE rauc.slot=B
  }

GRUB since 2.02-beta1 supports the ``eval`` command, which can be used
to express the logic above more concisely.

The ``grubenv`` file can be modified using ``grub-editenv``, which is shipped
by GRUB.
It can also be used to inspect the current contents::

  > grub-editenv /boot/grub/grubenv list
  ORDER="A B"
  A_OK=0
  B_OK=0
  A_TRY=0
  B_TRY=0

The initial installation of the bootloader and rootfs on the system is out of
scope for RAUC.
A common approach is to generate a complete disk image (including the partition
table) using a build system such as OpenEmbedded/Yocto, PTXdist or buildroot.

.. _sec-example-bundle-generation:

Bundle Generation
~~~~~~~~~~~~~~~~~

To create a bundle, we need to collect the components which should become part
of the update in a directory (in this case only the root file system image)::

  > mkdir temp-dir/
  > cp …/rootfs.ext4.img temp-dir/

Next, to describe the bundle contents to RAUC, we create a *manifest* file.
This must be named  ``manifest.raucm``::

  > cat >> temp-dir/manifest.raucm << EOF
  [update]
  compatible=rauc-demo-x86
  version=2015.04-1

  [bundle]
  format=verity

  [image.rootfs]
  filename=rootfs.ext4.img
  EOF

Note that we can omit the ``sha256`` and ``size`` parameters for the image
here, as RAUC will fill them out automatically when creating the bundle.

Finally, we run RAUC to create the bundle::

  > rauc --cert demo.cert.pem --key demo.key.pem bundle temp-dir/ update-2015.04-1.raucb
  > rm -r temp-dir

We now have the ``update-2015.04-1.raucb`` bundle file, which can be copied onto the
target system, in this case using a USB memory stick.

Update Installation
~~~~~~~~~~~~~~~~~~~

Having copied ``update-2015.04-1.raucb`` onto the target, we only need to run RAUC::

  > rauc install /mnt/usb/update-2015.04-1.raucb

After cyptographically verifying the bundle, RAUC will now determine the
active slots by looking at the ``rauc.slot`` variable.
Then, it can select the target slot for the update image from the inactive
slots.

When the update is installed completely, we just need to restart the system.
GRUB will then try to boot the newly installed rootfs.
Finally, if the boot was successful, we need to inform the bootloader::

  > rauc status mark-good

If systemd_ is available, it is useful to run this command late in the boot
process and declare dependencies on the main application(s).

.. _systemd: http://www.freedesktop.org/wiki/Software/systemd/

If the boot is not marked as successful, GRUB will try the other installation
on the next boot.
By configuring the kernel and systemd to reboot on critical errors and by using
a (software) watchdog, hangs in a non-working installation can be avoided.

Write Slots Without Update Mechanics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Assuming an image has been copied to or exists on the target, a manual slot
write can be performed by::

  > rauc write-slot rootfs.0 rootfs.ext4

This will write the rootfs image ``rootfs.ext4`` to the slot ``rootfs.0``.
Note that this bypasses all update mechanics like hooks, slot status etc.

.. _sec-example-slot-configs:

Example Slot Configurations
---------------------------

This provides some common examples on how to configure slots in your
system.conf for different scenarios.

Symmetric A/B Setup
~~~~~~~~~~~~~~~~~~~

This is the default case when having a fully-redundant root file system

.. code-block:: cfg
  :emphasize-lines: 3, 6, 8, 11

  [...]

  [slot.rootfs.0]
  device=/dev/sda2
  type=ext4
  bootname=A

  [slot.rootfs.1]
  device=/dev/sda3
  type=ext4
  bootname=B


Asymmetric A/Recovery Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In case storage is too restricted for a full A/B redundancy setup, an
asymmetric setup with a dedicated update/recovery slot can be used.
The recovery slot can be way smaller than the rootfs one as it needs to contain
only the tools for updating the rootfs slot.
Because the recovery slot is not meant to be updated in most cases, we can
manifest this for RAUC by setting the ``readonly=true`` option.

.. code-block:: cfg
  :emphasize-lines: 3, 6, 7, 9, 12

  [...]

  [slot.recovery.0]
  device=/dev/sda2
  type=ext4
  bootname=R
  readonly=true

  [slot.rootfs.0]
  device=/dev/sda3
  type=ext4
  bootname=A

Separate Application Partition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RAUC allows to have a separate redundant set of slots for the application (or
other purpose) that have a fixed relation to their corresponding rootfs slots.
RAUC assures that an update of the entire slot group (rootfs + appfs) is
atomic.

When defining appfs slots, be sure to set the correct `parent` relation to the
associated bootable slot.

.. code-block:: cfg
  :emphasize-lines: 14, 19

  [...]

  [slot.rootfs.0]
  device=/dev/sda2
  type=ext4
  bootname=A

  [slot.rootfs.1]
  device=/dev/sda3
  type=ext4
  bootname=B

  [slot.appfs.0]
  parent=rootfs.0
  device=/dev/sda4
  type=ext4

  [slot.appfs.1]
  parent=rootfs.1
  device=/dev/sda5
  type=ext4

Atomic Bootloader Updates (eMMC)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Updating the Bootloader is also possible with RAUC, despite this is a bit more
critical than updating the rootfs, as there is no fallback mechanism.

However, depending on the ROM loader it can at least be possible to perform the
bootloader update atomically.
The most common example for this is using the two boot partitions of an eMMC
for atomic bootloader updates which RAUC supports out-of-the-box
(refer :ref:`sec-emmc-boot`).

.. code-block:: cfg
  :emphasize-lines: 3, 5

  [...]

  [slot.bootloader.0]
  device=/dev/mmcblk0
  type=boot-emmc

  [slot.rootfs.0]
  device=/dev/mmcblk0p1
  type=ext4
  bootname=A

  [slot.rootfs.1]
  device=/dev/mmcblk0p2
  type=ext4
  bootname=B

Symmetric A/B Setup + Recovery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Booting into the recovery slot should normally be handled by the bootloader
if it fails to load the symmetric slots.

Thus from the RAUC perspective this setup is identical to the default A/B
setup.

Anyway, you can still define it as a slot if you need to be able to provide
an update for this, too.

Symmetric A/B Setup + Shared (Single-File) Artifacts Repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configuring a ``file`` *artifact repository* in addition to the A/B *system
slots* can be useful for systems which use one or several larger data files
(e.g.  map data) that should be updated more frequently and/or independently of
the main A/B rootfs.

.. code-block:: cfg
  :emphasize-lines: 13-15

  [...]

  [slot.rootfs.0]
  device=/dev/sda2
  type=ext4
  bootname=A

  [slot.rootfs.1]
  device=/dev/sda3
  type=ext4
  bootname=B

  [artifacts.map-data]
  path=/srv/maps
  type=file

The artifacts directory ``maps`` from this example must be located on a separate
(shared) partition that is mounted to the respective active rootfs slot under
``/srv``.

Example Integrations
--------------------

There are a couple of community projects that can serve as a base or blueprint
for integrating RAUC into projects or products.

OpenEmbedded / Yocto Project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: meta-rauc-community

The `meta-rauc-community repository
<https://github.com/rauc/meta-rauc-community>`_ contains layers for some
platforms, demonstrating different ways to use RAUC.

Currently supported platforms are:

* `qemux86-64 <https://github.com/rauc/meta-rauc-community/tree/master/meta-rauc-qemux86>`_
* `RaspberryPi <https://github.com/rauc/meta-rauc-community/tree/master/meta-rauc-raspberrypi>`_
* `CuBox-i <https://github.com/rauc/meta-rauc-community/tree/master/meta-rauc-nxp>`_
* `Allwinner SunXi <https://github.com/rauc/meta-rauc-community/tree/master/meta-rauc-sunxi>`_
* `NVIDIA Tegra <https://github.com/rauc/meta-rauc-community/tree/master/meta-rauc-tegra>`_

.. rubric:: Eclipse Leda

Leda, the Eclipse project for software-defined vehicles, provides an example
RAUC integration:

https://eclipse-leda.github.io/leda/docs/device-provisioning/self-update/rauc-integration/

Buildroot
~~~~~~~~~

.. rubric:: Buildroot + RAUC (br2rauc)

The `br2rauc <https://github.com/cdsteinkuehler/br2rauc>`_ project provides
an example Buildroot integration for the Raspberry PI CM4.
