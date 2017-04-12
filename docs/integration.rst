Integration
===========

When integrating RAUC (and in general) we recommend using a Linux system build
tool like Yocto / OpenEmbedded or PTXdist. For information about how
to integrate RAUC using these tools, refer to section :ref:`sec_int_yocto` or
:ref:`sec_int_ptxdist`.

System Configuration
--------------------

RAUC expects the file ``/etc/rauc/system.conf`` to describe the system it runs
on in a way that all relevant information for performing updates and making
decisions are given.

.. note:: For a full reference of the system.conf file refer to section
  :ref:`sec_ref_slot_config`

Similar to other configuration files used by RAUC, the system configuration
uses a key-value syntax (similar to those known from .ini files).

Slot Configuration
~~~~~~~~~~~~~~~~~~

The most important step is to describe the slots that RAUC should use
when performing updates. Which slots are required and what you have to take
care of when designing your system will be covered in the chapter :ref:`todo`.
This section assumes that you have already decided on a setup and want to describe
it for RAUC.

A slot is defined by a slot section. The naming of the section must follow a
simple format: `slot.<slot-class>.<slot-index>` where *slot-class* describes a
group used for redundancy and *slot-index* is the index of the individual slot
starting with 0.
If you have two rootfs slots, for example, one slot section will be named
``[slot.rootfs.0]``, the other will be named ``[slot.rootfs.1]``.
RAUC does not have predefined class names. The only requirement is that the
class names used in the system config match those in the update manifests.

The mandatory settings for each slot are: the ``device`` that holds the
(device) path describing *where* the slot is located, the ``type`` that
defines *how* to update the target device, and the ``bootname`` which is
the name the bootloader uses to refer to this slot device.

Type
^^^^

A list of common types supported by RAUC:

+----------+-------------------------------------------------------------------+
| Type     | Description                                                       |
+----------+-------------------------------------------------------------------+
| raw      | A partition holding no (known) file system. Only raw image copies |
|          | may be performed.                                                 |
+----------+-------------------------------------------------------------------+
| ext4     | A partition holding an ext4 filesystem.                           |
+----------+-------------------------------------------------------------------+
| nand     | A NAND partition.                                                 |
+----------+-------------------------------------------------------------------+
| ubivol   | A NAND partition holding an UBI volume                            |
+----------+-------------------------------------------------------------------+
| ubifs    | A NAND partition holding an UBI volume containing an UBIFS.       |
+----------+-------------------------------------------------------------------+

Kernel Configuration
--------------------

The kernel used on the target device must support both loop devices and the
SquashFS file system to allow installing bundles.

In kernel Kconfig you have to enable the following options:

  * `CONFIG_BLK_DEV_LOOP=y`
  * `CONFIG_SQUASHFS=y`

Required Target Tools
---------------------

RAUC requires and uses a set of target tools depending on the type of supported
storage and used image type.

Note that build systems may handle parts of these dependencies automatically,
but also in this case you will have to select some of them manually as RAUC
cannot fully know how you intend to use your system.

:NAND Flash: nandwrite (from `mtd-utils
             <git://git.infradead.org/mtd-utils.git>`_)
:UBIFS: mkfs.ubifs (from `mtd-utils
                  <git://git.infradead.org/mtd-utils.git>`_)
:TAR archives: You may either use `GNU tar <http://www.gnu.org/software/tar/>`_
  or `Busybox tar <http://www.busybox.net>`_.

  If you intend to use Busybox tar, make sure format autodetection is enabled:

    * ``CONFIG_FEATURE_TAR_AUTODETECT=y``
:ext2/3/4: mkfs.ext2/3/4 (from `e2fsprogs
  <git://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git>`_)


Interfacing with the Bootloader
-------------------------------

RAUC provides support for interfacing with different types of bootloaders. To
select the bootloader you have or intend to use on your system, set the
``bootloader`` key in the ``[system]`` section of your devices ``system.conf``.

.. note::

  If in doubt about choosing the right bootloader, we recommend to use Barebox
  as it provides a dedicated boot handling framework, called `bootchooser`.

To allow RAUC handling a bootable slot, you have to mark it bootable in your
system.conf and configure the name under which the bootloader is able to
identify this distinct slot. This is both done by setting the ``bootname``
property.

.. code-block:: cfg

  [slot.rootfs.0]
  ...
  bootname=system0

Barebox
~~~~~~~

.. code-block:: cfg

  [system]
  ...
  bootloader=barebox

Barebox support requires you to have the **bootchooser framework** with
**barebox state** backend enabled. In Barebox Kconfig you can enable this by
setting:

.. code-block:: cfg

  CONFIG_BOOTCHOOSER=y
  CONFIG_STATE=y

To enable reading and writing of the required state variables, you also have
to add the ``barebox-state`` tool from the `dt-utils
<https://git.pengutronix.de/cgit/tools/dt-utils/>`_ repository to your
systems rootfs.

.. note::
  For details on how to set it up, which storage backend to use, etc. refer to
  the Barebox `bootchooser documentation
  <http://barebox.org/doc/latest/user/bootchooser.html>`_.

U-Boot
~~~~~~

.. code-block:: cfg

  [system]
  ...
  bootloader=uboot

To enable handling of redundant booting in U-Boot, manual scripting is required.

The U-Boot bootloader interface of RAUC will rely on setting the U-Boot
environment variables ``BOOT_<bootname>_LEFT`` which should mark the number of
remaining boot attempts for the respective slot in your bootloader script.

To enable reading and writing of the U-Boot environment, you need to have the
U-Boot target tool ``fw_setenv`` available on your devices rootfs.

An examplary U-Boot script for handling redundant boot setups is located in the
``contrib/`` folder of the RAUC source repository (``uboot.sh``).


GRUB
~~~~

.. code-block:: cfg

  [system]
  ...
  bootloader=grub

To enable handling of redundant booting in GRUB, manual scripting is required.

The GRUB bootloader interface of RAUC uses the GRUB environment variables
``<bootname>_OK``, ``<bootname>_TRY`` and ``ORDER``.

To enable reading and writing of the GRUB environment, you need to have the tool
``grub-editenv`` available on your target.

An examplary GRUB configuration for handling redundant boot setups is located in the
``contrib/`` folder of the RAUC source repository (``grub.conf``). As the GRUB
shell only has limited support for scripting, this example uses only one try
per enabled slot.

Others
~~~~~~

System Boot
-----------
   * Watchdog vs. Confirmation
   * Kernel Command Line: booted slot
   * D-Bus-Service vs. Single Binary
   * Cron

Backend
-------

Persistent Data
---------------

   * SSH-Keys?

Feel free to extend RAUC with support for your bootloader.

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
  
  SRC_URI_append := "file://system.conf"

Write a ``system.conf`` for your board and place it in the folder you mentioned
in the recipe (`meta-your-bsp/recipes-core/rauc/files`). This file must provide
a system compatible string to identify your system type, as well as a
definition of all slots in your system. By default, the system configuration
will be placed in `/etc/rauc/system.conf` on your target rootfs.

For a reference of allowed configuration options in system.conf, see `system
configuration file`_.
For a more detailed instruction on how to write a system.conf, see `chapter`_.

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
could be ``meta-your-pbsp/recipes-core/bundles/update-bundle.bb``.

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
  this slot. Possible types are: ``rootfs`` (default), ``kernel``,
  ``bootloader``.

Based on this information, your bundle recipe will build all required
components and generate a bundle from this. The created bundle can be found in
``tmp/deploy/images/<machine>/bundles`` in your build directory.

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
RAUC recipe install it into the rootfs you build.
Also place the keyring for your device in
``configs/platform-<yourplatform>/projectroot/etc/rauc/ca.cert.pem``.

.. note:: You should use your local PKI infrastructure for generating valid
  certificates and keys for your target. For debugging and testing purpose,
  PTXdist provides a script that generates a set of example certificates. It is
  named ``rauc-gen-test-certs.sh`` and located in PTXdist's ``scripts`` folder.

If using systemd, the recipes install both the default ``systemd.service`` file
for RAUC as well as a ``rauc-mark-good.service`` file.
This additional good-marking-service runs after user space is brought up and
notifies the underlying bootloader implementation about a successful boot of
the system.  This is typically used in conjunction with a boot attempts counter
in the bootloader that is decremented before starting the systemd and reset by
`rauc status mark-good` to indicate a successful system startup.


Create Update Bundles from your RootFS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable building RAUC bundles, set::

  CONFIG_IMAGE_RAUC=y

in your platformconfig (by using ``ptxdist platformconfig``).

This adds a default image recipe for building a RAUC update Bundle out of the
systems rootfs. As for all image recipes, the `genimage` tool is used to
configure and generate the update Bundle.

PTXdist's default bundle configuration is placed in
`config/images/rauc.config`. You may also copy this to your platform directory
to use this as a base for custom bundle configuration.

In order to sign your update (mandatory) you also need to place a valid
certificate and key file in your BSP at the following paths:

  $(PTXDIST_PLATFORMCONFIGDIR)/config/rauc/rauc.key.pem (key)
  $(PTXDIST_PLATFORMCONFIGDIR)/config/rauc/rauc.cert.pem (cert)

Once you are done with you setup, PTXdist will automatically create a RAUC
update Bundle for you during the run of ``ptxdist images``.  It will be placed
under ``<platform-builddir>/images/update.raucb``.
