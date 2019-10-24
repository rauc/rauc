Integration
===========

.. contents::
   :local:
   :depth: 2

If you intend to prepare your platform for using RAUC as an update framework,
this chapter will guide you through the required steps and show the different
ways you can choose.

To integrate RAUC, you first need to be able to build RAUC as both a host and a
target application.
The host application is needed for generating update bundles while the target
application or service performs the core task of RAUC:
updating you device.

In an update system, a lot of components have to play together and have to be
configured appropriately to interact correctly.
In principle, these are:

* Hardware setup, devices, partitions, etc.
* The bootloader
* The Linux kernel
* The init system
* System utilities (mount, mkfs, ...)
* The update tool, RAUC itself

.. note::
  When integrating RAUC into your embedded Linux system, and in general,
  we highly recommend using a Linux system build system like Yocto /
  OpenEmbedded or PTXdist that allows you to have well defined software states
  while easing integration of the different components involved.

  For information about how to integrate RAUC using these tools,
  refer to the sections :ref:`sec_int_yocto` or :ref:`sec_int_ptxdist`.

.. _sec-int-system-config:

RAUC System Configuration
-------------------------

The system configuration file is the central configuration in RAUC that
abstracts the loosely coupled storage setup, partitioning and boot strategy of
your board to a coherent redundancy setup world view for RAUC.

RAUC expects its central configuration file ``/etc/rauc/system.conf`` to
describe the system it runs on in a way that all relevant information for
performing updates and making decisions are given.

.. note:: For a full reference of the system.conf file refer to section
  :ref:`sec_ref_slot_config`.

Similar to other configuration files used by RAUC,
the system configuration uses a key-value syntax (similar to those known from
.ini files).

Slot Configuration
~~~~~~~~~~~~~~~~~~

The most important step is to describe the slots that RAUC should use
when performing updates.
Which slots are required and what you have to take care of when designing your
system will be covered in the chapter :ref:`sec-scenarios`.
This section assumes that you have already decided on a setup and want to
describe it for RAUC.

A slot is defined by a slot section.
The naming of the section must follow a simple format:
``[slot.<slot-class>.<slot-index>]``
where *<slot-class>* describes a class of possibly multiple redundant slots
(such as ``rootfs``, ``recovery`` or ``appfs``)
and *slot-index* is the index of the individual slot instance,
starting with index 0.

If you have two redundant slots used for the root file system, for example,
you should name your sections according to this example:

.. code-block:: cfg

  [slot.rootfs.0]
  device = [...]

  [slot.rootfs.1]
  device = [...]

RAUC does not have predefined class names. The only requirement is that the
class names used in the system config match those you later use in the update
manifests.

The mandatory settings for each slot are:

* the ``device`` that holds the (device) path describing *where* the slot is
  located,
* the ``type`` that defines *how* to update the target device.

If the slot is bootable, then you also need

* the ``bootname`` which is the name the bootloader uses to refer to this slot
  device.

.. _sec-slot-type:

Slot Type
^^^^^^^^^

A list of slot storage types currently supported by RAUC:

+----------+-------------------------------------------------------------------+-------------+
| Type     | Description                                                       | Tar support |
+----------+-------------------------------------------------------------------+-------------+
| raw      | A partition holding no (known) file system. Only raw image copies |             |
|          | may be performed.                                                 |             |
+----------+-------------------------------------------------------------------+-------------+
| ext4     | A block device holding an ext4 filesystem.                        |     x       |
+----------+-------------------------------------------------------------------+-------------+
| nand     | A raw NAND partition.                                             |             |
+----------+-------------------------------------------------------------------+-------------+
| ubivol   | An UBI partition in NAND.                                         |             |
+----------+-------------------------------------------------------------------+-------------+
| ubifs    | An UBI volume containing an UBIFS in NAND.                        |     x       |
+----------+-------------------------------------------------------------------+-------------+
| vfat     | A block device holding a vfat filesystem..                        |     x       |
+----------+-------------------------------------------------------------------+-------------+

Depending on this slot storage type and the slot's :ref:`image filename <image.slot-filename>`
extension, RAUC determines how to extract the image content to the target slot.

While the generic filename extension ``.img`` is supported for all filesystems,
it is strongly recommended to use explicit extensions (e.g. ``.vfat`` or ``.ext4``)
when possible, as this allows checking during installation that the slot type is correct.

Grouping Slots
^^^^^^^^^^^^^^

If multiple slots belong together in a way that they always have to be updated
together with the respective other slots, you can ensure this by grouping slots.

A group must always have a single bootable slot, then all other slots define a
parent relationship to this bootable slot as follows:

.. code-block:: cfg

  [slot.rootfs.0]
  ...

  [slot.appfs.0]
  parent = rootfs.0
  ...

  [slot.rootfs.1]
  ...

  [slot.appfs.1]
  parent = rootfs.1
  ...

Library Dependencies
--------------------

The minimal requirement for RAUC regardless of whether intended for the host or
target side is GLib (minimum version 2.45.8) as utility library and OpenSSL
(>=1.0) for signature handling.

.. note::
   In order to let RAUC detect mounts correctly, GLib must be compiled
   with libmount support (``--enable-libmount``) and at least be 2.49.5.

For network support (enabled with ``--enable-network``), additionally `libcurl`
is required. This is only useful for the target service.

For JSON-style support (enabled with ``--enable-json``), additionally
`libjson-glib` is required.

Kernel Configuration
--------------------

The kernel used on the target device must support both loop block devices and the
SquashFS file system to allow installing RAUC bundles.

In kernel Kconfig you have to enable the following options:

.. code-block:: cfg

  CONFIG_BLK_DEV_LOOP=y
  CONFIG_SQUASHFS=y

.. _sec_ref_host_tools:

Required Host Tools
-------------------

To be able to generate bundles, RAUC requires at least the following host tools:

* mksquashfs
* unsquashfs

When using the RAUC casync integration, the ``casync`` tool and ``fakeroot``
(for converting archives to directory tree indexes) must also be available.

.. _sec_ref_target_tools:

Required Target Tools
---------------------

RAUC requires and uses a set of target tools depending on the type of supported
storage and used image type.

Mandatory tools for each setup are ``mount`` and ``umount``, either from
`Busybox <http://www.busybox.net>`_ or
`util-linux <https://cdn.kernel.org/pub//linux/utils/util-linux/>`_

Note that build systems may handle parts of these dependencies automatically,
but also in this case you will have to select some of them manually as RAUC
cannot fully know how you intend to use your system.

:NAND Flash: flash_erase & nandwrite (from `mtd-utils
             <git://git.infradead.org/mtd-utils.git>`_)
:UBIFS: mkfs.ubifs (from `mtd-utils
                  <git://git.infradead.org/mtd-utils.git>`_)
:TAR archives: You may either use `GNU tar <http://www.gnu.org/software/tar/>`_
  or `Busybox tar <http://www.busybox.net>`_.

  If you intend to use Busybox tar, make sure format autodetection and also the
  compression formats you use are enabled:

    * ``CONFIG_FEATURE_TAR_AUTODETECT=y``
    * ``CONFIG_FEATURE_SEAMLESS_XZ=y``
    * ``CONFIG_FEATURE_TAR_LONG_OPTIONS=y``

:ext2/ext3/ext4: mkfs.ext2/mkfs.ext3/mkfs.ext4 (from `e2fsprogs
  <git://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git>`_)
:vfat: mkfs.vfat (from `dosfstools
                  <https://github.com/dosfstools/dosfstools>`_)

Depending on the bootloader you use on your target, RAUC also needs the right
tool to interact with it:

:Barebox: barebox-state
          (from `dt-utils <https://git.pengutronix.de/cgit/tools/dt-utils/>`_)
:U-Boot: fw_setenv/fw_getenv (from `u-boot <http://git.denx.de/?p=u-boot.git;a=summary>`_)
:GRUB: grub-editenv
:EFI: efibootmgr

Note that for running ``rauc info`` on the target (as well as on the host), you
also need to have the ``unsquashfs`` tool installed.

When using the RAUC casync integration, the ``casync`` tool must also be
available.

Interfacing with the Bootloader
-------------------------------

RAUC provides support for interfacing with different types of bootloaders.
To select the bootloader you have or intend to use on your system, set the
``bootloader`` key in the ``[system]`` section of your device's ``system.conf``.

.. note::

  If in doubt about choosing the right bootloader, we recommend to use Barebox
  as it provides a dedicated boot handling framework, called `bootchooser`.

To let RAUC handle a bootable slot, you have to mark it as bootable in your
``system.conf`` and configure the name under which the bootloader identifies this
specific slot.
This is both done by setting the ``bootname`` property.

.. code-block:: cfg

  [slot.rootfs.0]
  ...
  bootname=system0

Amongst others, the bootname property also serves as one way to let RAUC know which slot is
currently booted (running).
In the following, the different options for letting RAUC detect the currently
booted slot are described.

Booted Slot Detection
~~~~~~~~~~~~~~~~~~~~~

For RAUC it is quite essential to know from which slot the system is currently
running.
We will refer this as the *booted slot*.
Only reliable detection of the *booted slot* enables RAUC to determine the set of
currently inactive slots (that it can safely write to).

If possible, one should always prefer to signal the active slot explicitly from
the bootloader to the userspace and RAUC.
Only for cases where this explicit way is not possible or unwanted, some
alternative approaches of automatically detecting the currently booted slot
are implemented in RAUC.

A detailed list of detection mechanism follows.

Identification via Kernel Commandline
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

RAUC evaluates different kernel commandline parameters in the order they are
listed below.

.. rubric:: ``rauc.slot=``

This is the generic way to explicitly set information about which slot was
booted by the bootloader.
For slots that are handled by a bootloader slot selection mechanism (such as
A+B slots) you should specify the slot's configured ``bootname``::

  rauc.slot=system0

For special cases where some slots are not handled by the slot selection
mechanism (such as a 'last-resort' recovery fallback that never gets explicitly
selected) you can also give the name of the slot::

  rauc.slot=recovery.0

.. rubric:: ``bootchooser.active=``

This is the command-line parameter used by barebox's *bootchooser* mechanism.
It will be set automatically by the bootchooser framework and does not need any
manual configuration.
RAUC compares this against each slot's bootname (not the slot's name as above)::

  bootchooser.active=system0

.. rubric:: ``root=``

If none of the above parameters is given, the ``root=`` parameter is evaluated
by RAUC to gain information on the currently booted system.
The ``root=`` entry contains the device from which device the kernel (or
initramfs) should load the rootfs.
RAUC supports parsing different variants for giving these device as listed below.

::

  root=/dev/sda1
  root=/dev/ubi0_1

Giving the plain device name is supported, of course.

.. note::

  The alternative ubi rootfs format with ``root=ubi0:volname`` is currently
  unsupported.

::

  root=PARTUUID=01234
  root=UUID=01234

Parsing the ``PARTUUID`` and ``UUID`` is supported, which allows referring to a
special partition / file system without having to know the
enumeration-dependent `sdX` name.

RAUC converts the value to the corresponding ``/dev/disk/by-*`` symlink name
and then to the actual device name.

::

  root=/dev/nfs

RAUC automatically detects NFS boots (by checking if this parameter is set in
the kernel command line).
There is no extra slot configuration needed for this as RAUC assumes it is safe
to update all available slots in case the currently running system comes from
NFS.

Barebox
~~~~~~~

The `Barebox <http://www.barebox.org>`_ bootloader,
which is available for many common embedded platforms,
provides a dedicated boot source selection framework, called *bootchooser*,
backed by an atomic and redundant storage backend, named *state*.

*Barebox state* allows you to save the variables required by bootchooser with
memory specific storage strategies in all common storage medias,
such as block devices, mtd (NAND/NOR), EEPROM, and UEFI variables.

The *Bootchooser* framework maintains information about priority and remaining
boot attempts while being configurable on how to deal with them for different
strategies.


To enable the Barebox bootchooser support in RAUC, select it in your
system.conf:

.. code-block:: cfg

  [system]
  ...
  bootloader=barebox

Configure Barebox
^^^^^^^^^^^^^^^^^

As mentioned above, Barebox support requires you to have the *bootchooser
framework* with *barebox state* backend enabled.
In Barebox' Kconfig you can enable this by setting:

.. code-block:: cfg

  CONFIG_BOOTCHOOSER=y
  CONFIG_STATE=y
  CONFIG_STATE_DRV=y

To debug and interact with bootchooser and state in Barebox,
you should also enable these tools:

.. code-block:: cfg

  CONFIG_CMD_STATE=y
  CONFIG_CMD_BOOTCHOOSER=y

Setup Barebox Bootchooser
^^^^^^^^^^^^^^^^^^^^^^^^^

The barebox bootchooser framework allows you to specify a number of redundant
boot targets that should be automatically selected by an algorithm,
based on status information saved for each boot target.

The bootchooser itself can be used as a Barebox boot target.
This is where we start by setting the barebox default boot target to
`bootchooser`::

  nv boot.default="bootchooser"

Now, when Barebox is initialized it starts the bootchooser logic to select its
real boot target.

As a next step, we need to tell bootchooser which boot targets it should
handle. These boot targets can have descriptive names which must not equal any of
your existing boot targets, we will have a mapping for this later on.

In this example we call the virtual bootchooser boot targets ``system0`` and
``system1``::

  nv bootchooser.targets="system0 system1"

Now connect each of these virtual boot targets to a real Barebox boot target
(one of its automagical ones or custom boot scripts)::

  nv bootchooser.system0.boot="nand0.ubi.system0"
  nv bootchooser.system1.boot="nand0.ubi.system1"

To configure bootchooser to store the variables in Barebox state, you need to configure the ``state_prefix``::

  nv bootchooser.state_prefix="state.bootstate"

Beside this very basic configuration variables, you need to set up a set of
other general and slot-specific variables.

.. warning::
  It is highly recommended to read the full Barebox bootchooser
  `documentation <http://barebox.org/doc/latest/user/bootchooser.html>`_
  in order to know about the requirements and possibilities in fine-tuning the
  behavior according to your needs.

  Also make sure to have these ``nv`` settings in your compiled-in environment,
  not in your device-local environment.

Setting up Barebox State for Bootchooser
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For storing its status information, the botchooser framework requires a
*barebox,state* instance to be set up with a set of variables matching the set
of virtual boot targets defined.

To allow loading the state information in a well-defined format both from
Barebox and from the kernel,
we store the state data format definition in the Barebox devicetree.

Barebox fixups the information into the Linux devicetree when loading the
kernel.
This assures having a consistent view on the variables in Barebox and Linux.

An example devicetree node for our simple redundant setup will have the
following basic structure

.. code-block:: DTS

  state {
    bootstate {
      system0 {
      ...
      };
      system1 {
      ...
      };
    };
  };

In the state node, we set the appropriate compatible to tell the *barebox,state*
driver to care for it and define where and how we want to store our data.
This will look similar to this:

.. code-block:: DTS

  state: state {
          magic = <0x4d433230>;
          compatible = "barebox,state";
          backend-type = "raw";
          backend = <&state_storage>;
          backend-stridesize = <0x40>;
          backend-storage-type = "circular";
          #address-cells = <1>;
          #size-cells = <1>;

	  [...]
  }

where ``<&state_storage>`` is a phandle to, e.g. an EEPROM or NAND partition.

.. important::
   The devicetree only defines where and in which format the data will
   be stored. By default, no data will be stored in the deviectree itself!

The rest of the variable set definition will be made in the ``bootstate``
subnode.

For each virtual boot target handled by state,
two uint32 variables ``remaining_attempts`` and ``priority`` need to be
defined.:

.. code-block:: DTS

  bootstate {

          system0 {
                  #address-cells = <1>;
                  #size-cells = <1>;

                  remaining_attempts@0 {
                          reg = <0x0 0x4>;
                          type = "uint32";
                          default = <3>;
                  };
                  priority@4 {
                          reg = <0x4 0x4>;
                          type = "uint32";
                          default = <20>;
                  };
          };

          [...]
  };

.. note::
  As the example shows, you must also specify some useful default variables the
  state driver will load in case of uninitialized backend storage.

Additionally one single variable for storing information about the last chosen
boot target is required:

.. code-block:: DTS

  bootstate {

          [...]

          last_chosen@10 {
                  reg = <0x10 0x4>;
                  type = "uint32";
          };
  };

.. warning::
  This example shows only a highly condensed excerpt of setting up Barebox
  state for bootchooser.
  For a full documentation on how Barebox state works and how to properly
  integrate it into your platform see the official Barebox State Framework
  `user documentation <http://www.barebox.org/doc/latest/user/state.html>`_
  as well as the corresponding
  `devicetree binding <http://www.barebox.org/doc/latest/devicetree/bindings/barebox/barebox,state.html>`_
  reference!

You can verify your setup by calling ``devinfo state`` from Barebox,
which would print this for example:

.. code-block:: sh

  barebox@board:/ devinfo state
  Parameters:
  bootstate.last_chosen: 2 (type: uint32)
  bootstate.system0.priority: 10 (type: uint32)
  bootstate.system0.remaining_attempts: 3 (type: uint32)
  bootstate.system1.priority: 20 (type: uint32)
  bootstate.system1.remaining_attempts: 3 (type: uint32)
  dirty: 0 (type: bool)
  save_on_shutdown: 1 (type: bool)

Once you have set up bootchooser properly, you finally need to enable RAUC to
interact with it.

Enable Accessing Barebox State for RAUC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For this, you need to specify which (virtual) boot target belongs to which
of the RAUC slots you defined.
You do this by assigning the virtual boot target name to the slots ``bootname``
property:

.. code-block:: cfg

  [slot.rootfs.0]
  ...
  bootname=system0

  [slot.rootfs.1]
  ...
  bootname=system1


For writing the bootchooser's state variables from userspace,
RAUC uses the tool *barebox-state* from the
`dt-utils <https://git.pengutronix.de/cgit/tools/dt-utils/>`_ repository.

.. note:: RAUC requires dt-utils version v2017.03 or later!

Make sure to have this tool integrated on your target platform.
You can verify your setup by calling it manually:

.. code-block:: sh

  # barebox-state -d
  bootstate.system0.remaining_attempts=3
  bootstate.system0.priority=10
  bootstate.system1.remaining_attempts=3
  bootstate.system1.priority=20
  bootstate.last_chosen=2

Verify Boot Slot Detection
^^^^^^^^^^^^^^^^^^^^^^^^^^

As detecting the currently booted rootfs slot from userspace and matching it to
one of the slots defined in RAUC's ``system.conf`` is not always trivial and
error-prone, Barebox provides an explicit information about which slot it
selected for booting adding a `bootchooser.active` key to the commandline of
the kernel it boots. This key has the virtual bootchooser boot target assigned.
In our case, if the bootchooser logic decided to boot `system0` the kernel
commandline will contain::

  bootchooser.active=system0

RAUC uses this information for detecting the active booted slot (based on the
slot's `bootname` property).

If the kernel commandline of your booted system contains this line, you have
successfully set up bootchooser to boot your slot::

  $ cat /proc/cmdline


U-Boot
~~~~~~

To enable handling of redundant booting in U-Boot, manual scripting is
required.
U-Boot allows storing and modifying variables in its *Environment*.
Properly configured it can be accessed both from U-Boot itself as
well as from Linux userspace.

The RAUC U-Boot boot selection implementation uses a custom U-Boot script
together with the environment for managing and persisting slot selection.

To enable U-Boot support in RAUC, select it in your system.conf:

.. code-block:: cfg

  [system]
  ...
  bootloader=uboot

Set up U-Boot Environment for RAUC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The U-Boot bootloader interface of RAUC will rely on setting the U-Boot
environment variables:

* ``BOOT_ORDER``, which will contain a space-separated list of boot targets in
  the order they should be tried.
* ``BOOT_<bootname>_LEFT``, which contains the number of remaining boot
  attempts to perform for the respective slot.

An example U-Boot script for handling redundant A/B boot setups is located in
the ``contrib/`` folder of the RAUC source repository (``contrib/uboot.sh``).

You must integrate your boot selection script into U-Boot.
Refer the
`U-Boot Scripting Capabilities <https://www.denx.de/wiki/DULG/UBootScripts>`_
chapter in the U-Boot user documentation on how to achieve this.

The script uses the names ``A`` and ``B`` as the ``bootname`` for the two
different boot targets.
Thus the resulting boot attempts variables will be ``BOOT_A_LEFT`` and
``BOOT_B_LEFT``.
The ``BOOT_ORDER`` variable will contain ``A B`` if ``A`` is the primary slot or
``B A`` if ``B`` is the primary slot.

.. note::
   If you want to implement different behavior or use other variable names, you
   might need to modify the ``uboot_set_state()`` and ``uboot_set_primary()``
   functions in ``src/bootchooser.c``.

Enable Accessing U-Boot Environment from Userspace
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable reading and writing of the U-Boot environment from Linux userspace,
you need to have:

* U-Boot target tools ``fw_printenv`` and ``fw_setenv`` available on your devices rootfs.
* Environment configuration file ``/etc/fw_env.config`` in your target root filesystem.

See the corresponding
`HowTo <https://www.denx.de/wiki/DULG/HowCanIAccessUBootEnvironmentVariablesInLinux>`_
section from the U-Boot documentation for more details on how to set up the
environment config file for your device.

Support for Fail-Safe Environment Update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For atomic updates of environment, U-Boot can use redundant environment
storages that allow to write one copy while using the other as fallback if
writing fails, e.g. due to sudden power cut.

In order to enable redundant environment storage, you have to set in your U-Boot
config::

  CONFIG_ENV_OFFSET_REDUND=y
  CONFIG_ENV_ADDR_REDUND=xxx

Refer to U-Boot source code and README for more details on this.

GRUB
~~~~

.. code-block:: cfg

  [system]
  ...
  bootloader=grub

To enable handling of redundant booting in GRUB, manual scripting is required.

The GRUB bootloader interface of RAUC uses the GRUB environment variables
``<bootname>_OK``, ``<bootname>_TRY`` and ``ORDER``.

An exemplary GRUB configuration for handling redundant boot setups is located in the
``contrib/`` folder of the RAUC source repository (``grub.conf``). As the GRUB
shell only has limited support for scripting, this example uses only one try
per enabled slot.

To enable reading and writing of the GRUB environment, you need to have the tool
``grub-editenv`` available on your target.

By default RAUC expects the grubenv file to be located at
``/boot/grub/grubenv``, you can specify a custom directory by passing
``grubenv=/path/to/grubenv`` in your system.conf ``[system]`` section.

Make sure that the grubenv file is located outside your redundant rootfs
partitions as the rootfs needs to be exchangeable without affecting the
environment content.
For UEFI systems, a proper location would be to place it on the EFI partition,
e.g. at ``/EFI/BOOT/grubenv``.
The same partition can also be used for your ``grub.cfg`` (which could be
placed at ``/EFI/BOOT/grub.cfg``).

.. _sec-efi:

EFI
~~~

For x86 systems that directly boot via EFI/UEFI, RAUC supports interaction with
EFI boot entries by using the `efibootmgr` tool. To enable EFI bootloader
support in RAUC, write in your ``system.conf``:

.. code-block:: cfg

  [system]
  ...
  bootloader=efi

To set up a system ready for pure EFI-based redundancy boot without any further
bootloader or initramfs involved, you have to create an appropriate
partition layout and matching boot EFI entries.

Assuming a simple A/B redundancy, you would need:

* 2 redundant EFI partitions holding an EFI stub kernel
  (e.g. at ``EFI/LINUX/BZIMAGE.EFI``)
* 2 redundant rootfs partitions

To create boot entries for these, use the efibootmgr tool::

  efibootmgr --create --disk /dev/sdaX --part 1 --label "system0" --loader \\EFI\\LINUX\\BZIMAGE.EFI --unicode "root=PARTUUID=<partuuid-of-part-1>"
  efibootmgr --create --disk /dev/sdaX --part 2 --label "system1" --loader \\EFI\\LINUX\\BZIMAGE.EFI --unicode "root=PARTUUID=<partuuid-of-part-2>"

where you replace /dev/sdaX with the name of the disk you use for redundancy
boot, ``<partuuid-of-part-1>`` with the PARTUUID of the first rootfs
partition and ``<partuuid-of-part-2>`` with the PARTUUID of the second rootfs
partition.

You can inspect and verify your settings by running::

  efibootmgr -v

In your ``system.conf``, you have to list both the EFI partitions (each containing
one kernel) as well as the rootfs partitions.
Make the first EFI partition a child of the first rootfs partition and the
second EFI partition a child of the second rootfs partition to have valid slot
groups.
Set the rootfs slot bootnames to those we have defined with the ``--label``
argument in the ``efibootmgr`` call above:

.. code-block:: cfg

  [slot.efi.0]
  device=/dev/sdX1
  type=vfat
  parent=rootfs.0

  [slot.efi.1]
  device=/dev/sdX2
  type=vfat
  parent=rootfs.1

  [slot.rootfs.0]
  device=/dev/sdX3
  type=ext4
  bootname=system0

  [slot.rootfs.1]
  device=/dev/sdX4
  type=ext4
  bootname=system1

Others
~~~~~~

It is planned to add support for a `custom` boot selection implementation that
will allow you to use also non-conventional or yet unimplemented approaches for
selecting your boot slot.

Init System and Service Startup
-------------------------------

There are several ways to run the RAUC service on your target.
The recommended way is to use a systemd-based system and allow to start RAUC
via D-Bus activation.

You can start the RAUC service manually by executing::

  $ rauc service

Systemd Integration
~~~~~~~~~~~~~~~~~~~

When building RAUC, a default systemd ``rauc.service`` file will be generated
in the ``data/`` folder.

Depending on your configuration ``make install`` will place this file in one of
your system's service file folders.

It is a good idea to wait for the system to be fully started before marking it
as successfully booted.
In order to achieve this, a smart solution is to create a systemd service that calls
``rauc status mark-good`` and use systemd's dependency handling to assure this
service will not be executed before all relevant other services came up
successfully. It could look similar to this:

.. code-block:: cfg

  [Unit]
  Description=RAUC Good-marking Service
  ConditionKernelCommandLine=|bootchooser.active
  ConditionKernelCommandLine=|rauc.slot

  [Service]
  ExecStart=/usr/bin/rauc status mark-good

  [Install]
  WantedBy=multi-user.target


D-Bus Integration
-----------------

The D-Bus interface RAUC provides makes it easy to integrate it into your custom
application.
In order to allow sending data, make sure the D-Bus config file
``de.pengutronix.rauc.conf`` from the ``data/`` dir gets installed properly.

To only start RAUC when required, using D-Bus activation is a smart solution.
In order to enable D-Bus activation, properly install the D-Bus service file
``de.pengutronix.rauc.service`` from the ``data/`` dir.

Watchdog Configuration
----------------------

Detecting system hangs during runtime requires to have a watchdog and to have
the watchdog configured and handled properly.
Systemd provides a sophisticated watchdog multiplexing and handling allowing
you to configure separate timeouts and handlings for each of your services.

To enable it, you need at least to have these lines in your systemd
configuration::

  RuntimeWatchdogSec=20
  ShutdownWatchdogSec=10min

.. _sec_int_yocto:

Yocto
-----

Yocto support for using RAUC is provided by the `meta-rauc
<https://github.com/rauc/meta-rauc>`_ layer.

The layer supports building RAUC both for the target as well as as a host tool.
With the `bundle.bbclass` it provides a mechanism to specify and build bundles
directly with the help of Yocto.

For more information on how to use the layer, also see the layers README file.

Target System Setup
~~~~~~~~~~~~~~~~~~~

Add the `meta-rauc` layer to your setup::

  git submodule add git@github.com:rauc/meta-rauc.git

Add the RAUC tool to your image recipe (or package group)::

  IMAGE_INSTALL_append = "rauc"

Append the RAUC recipe from your BSP layer (referred to as `meta-your-bsp` in the
following) by creating a ``meta-your-bsp/recipes-core/rauc/rauc_%.bbappend``
with the following content::

  FILESEXTRAPATHS_prepend := "${THISDIR}/files:"

Write a ``system.conf`` for your board and place it in the folder you mentioned
in the recipe (`meta-your-bsp/recipes-core/rauc/files`). This file must provide
a system compatible string to identify your system type, as well as a
definition of all slots in your system. By default, the system configuration
will be placed in `/etc/rauc/system.conf` on your target rootfs.

Also place the appropriate keyring file for your target into the directory
added to ``FILESEXTRAPATHS`` above. Name it either ``ca.cert.pem`` or
additionally specify the name of your custom file by setting
``RAUC_KEYRING_FILE``. If multiple keyring certificates are required on a
single system, create a keyring directory containing each certificate.

.. note::
  For information on how to create a testing / development
  key/cert/keyring, please refer to `scripts/README` in meta-rauc.

For a reference of allowed configuration options in system.conf,
see :ref:`sec_ref_slot_config`.
For a more detailed instruction on how to write a system.conf,
see :ref:`sec-int-system-config`.

Using RAUC on the Host System
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The RAUC recipe allows to compile and use RAUC on your host system.
Having RAUC available as a host tool is useful for debugging, testing or for
creating bundles manually.
For the preferred way of creating bundles automatically, see the chapter
`Bundle Generation`_. In order to compile RAUC for your host system, simply run::

  bitbake rauc-native

This will place a copy of the RAUC binary in ``tmp/deploy/tools`` in your
current build folder. To test it, try::

  tmp/deploy/tools/rauc --version

Bundle Generation
~~~~~~~~~~~~~~~~~

Bundles can be created either manually by building and using RAUC as a native
tool, or by using the ``bundle.bbclass`` that handles most of the basic steps,
automatically.

First, create a bundle recipe in your BSP layer. A possible location for this
could be ``meta-your-bsp/recipes-core/bundles/update-bundle.bb``.

To create your bundle you first have to inherit the bundle class::

  inherit bundle

To create the manifest file, you may either use the built-in class mechanism,
or provide a custom manifest.

For using the built-in bundle generation, you need to specify some variables:

``RAUC_BUNDLE_COMPATIBLE``
  Sets the compatible string for the bundle. This should match the compatible
  you specified in your ``system.conf`` or, more generally, the compatible of the
  target platform you intend to install this bundle on.

``RAUC_BUNDLE_SLOTS``
  Use this to list all slot classes for which the bundle should contain images.
  A value of ``"rootfs appfs"`` for example will create a manifest with images
  for two slot classes; rootfs and appfs.

``RAUC_SLOT_<slotclass>``
  For each slot class, set this to the image (recipe) name which builds the
  artifact you intend to place in the slot class.

``RAUC_SLOT_<slotclass>[type]``
  For each slot class, set this to the *type* of image you intend to place in
  this slot. Possible types are: ``image`` (default), ``kernel``,
  ``boot``, or ``file``.

.. note::
  For a full list of supported variables, refer to `classes/bundle.bbclass` in
  meta-rauc.

A minimal bundle recipe, such as `core-bundle-minimal.bb` that is contained in
meta-rauc will look as follows::

  inherit bundle

  RAUC_BUNDLE_COMPATIBLE ?= "Demo Board"

  RAUC_BUNDLE_SLOTS ?= "rootfs"

  RAUC_SLOT_rootfs ?= "core-image-minimal"


To be able to build a signed image of this, you also need to configure
``RAUC_KEY_FILE`` and ``RAUC_CERT_FILE`` to point to your key and certificate
files you intend to use for signing. You may set them either from your bundle
recipe or any global configuration (layer, site.conf, etc.), e.g.::

  RAUC_KEY_FILE = "${COREBASE}/meta-<layername>/files/development-1.key.pem"
  RAUC_CERT_FILE = "${COREBASE}/meta-<layername>/files/development-1.cert.pem"

.. note::
  For information on how to create a testing / development
  key/cert/keyring, please refer to `scripts/README` in meta-rauc.

Based on this information, a call of::

  bitbake core-bundle-minimal

will build all required images and generate a signed RAUC bundle from this.
The created bundle can be found in
``${DEPLOY_DIR_IMAGE}``
(defaults to ``tmp/deploy/images/<machine>`` in your build directory).

.. _sec_int_ptxdist:

PTXdist
-------

.. note:: RAUC support in PTXdist is available since version 2017.04.0.

Integration into Your RootFS Build
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable building RAUC for your target, set::

  CONFIG_RAUC=y

in your ptxconfig (by selection ``RAUC`` via ``ptxdist menuconfig``).

You should also customize the compatible RAUC uses for your System. For this
set ``CONFIG_RAUC_COMPATIBLE`` to a string that uniquely identifies your device
type. The default value will be ``"${PTXCONF_PROJECT_VENDOR}\ ${PTXCONF_PROJECT}"``.

Place your system configuration file in
``configs/platform-<yourplatform>/projectroot/etc/rauc/system.conf`` to let the
RAUC package install it into the rootfs you build.
Also place the keyring for your device in
``configs/platform-<yourplatform>/projectroot/etc/rauc/ca.cert.pem``.
If using a keyring directory, place the keyrings for your device in
``configs/platform-<yourplatform>/projectroot/etc/rauc/certs/``.

.. note:: You should use your local PKI infrastructure for generating valid
  certificates and keys for your target. For debugging and testing purpose,
  PTXdist provides a script that generates a set of example certificates. It is
  named ``rauc-gen-test-certs.sh`` and located in PTXdist's ``scripts`` folder.

If using systemd, the recipes install both the default ``systemd.service`` file
for RAUC as well as a ``rauc-mark-good.service`` file.
This additional good-marking-service runs after user space is brought up and
notifies the underlying bootloader implementation about a successful boot of
the system.  This is typically used in conjunction with a boot attempts counter
in the bootloader that is decremented before starting the system and reset by
`rauc status mark-good` to indicate a successful system startup.


Create Update Bundles from your RootFS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable building RAUC bundles, set::

  CONFIG_IMAGE_RAUC=y

in your platformconfig (by using ``ptxdist platformconfig``).

This adds a default image recipe for building a RAUC update bundle out of the
system's rootfs. As for all image recipes, the `genimage` tool is used to
configure and generate the update bundle.

PTXdist's default bundle configuration is placed in
`config/images/rauc.config`. You may also copy this to your platform directory
to use this as a base for custom bundle configuration.

In order to sign your update (mandatory) you also need to place a valid
certificate and key file in your BSP at the following paths::

  $(PTXDIST_PLATFORMCONFIGDIR)/config/rauc/rauc.key.pem (key)
  $(PTXDIST_PLATFORMCONFIGDIR)/config/rauc/rauc.cert.pem (cert)

Once you are done with your setup, PTXdist will automatically create a RAUC
update bundle for you during the run of ``ptxdist images``.  It will be placed
under ``<platform-builddir>/images/update.raucb``.

Buildroot
---------

.. note:: RAUC support in Buildroot is available since version 2017.08.0.

To build RAUC using buildroot, enable ``BR2_PACKAGE_RAUC`` in your
configuration.
