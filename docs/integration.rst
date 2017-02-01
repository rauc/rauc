Integration
===========

System configuration
--------------------

RAUC expects the file ``/etc/rauc/system.conf`` to describe the system it runs
on in a way that all relevant information for performing updates and making
decisions are given.

.. note:: For a full reference of the system.conf file refert to section
  :ref:`sec_ref_slot_config`

Similar to other configuration files used by RAUC, the system configuration
uses a key-value syntax (similar to those known from .ini files).

Slot configuration
~~~~~~~~~~~~~~~~~~

The most important step is to describe the slots that RAUC should use
when performing updates. Which slots are required and what you have to take
care of when designing your system will be covered in the chapter :ref:`todo`.
This section assumes, you have already decided on a setup and want to describe
it for RAUC.

A slot is defined by a slot section. The naming of the section must follow a
simple format: `slot.<slot-class>.<slot-index>` where *slot-class* describes a
group used for redundancy and *slot-index* is the index of the individual slot
starting with 0.
If you have two rootfs slots, for example, one slot section will be named
``[slot.rootfs.0]``, the other will be named ``[slot.rootfs.1]``.
RAUC does not have predefined class names. The only requirement is that the
class names used in the system config match those in the update manifests.

The mandatory settings for each slot are, the ``device`` that holds the
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


Yocto
-----

Yocto support for using RAUC is provided by the `meta-ptx
<http://git-public.pengutronix.de/?p=meta-ptx.git>`_ layer.

The layer supports building RAUC both for the target as well as a host tool.
With the `bundle.bbclass` it provides a mechanism to specify and build bundles
directly with the help of Yocto.

Target system setup
~~~~~~~~~~~~~~~~~~~

Add the `meta-ptx` layer to your setup::

  git submodule add http://git-public.pengutronix.de/git-public/meta-ptx.git

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

Using RAUC on the Host system
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The RAUC recipe allows to compile and use RAUC on your host system.
Having RAUC available as a host tool is useful for debugging, testing or for
creating bundles manually.
For the preferred way to creating bundles automatically, see the chapter
`Bundle generation`_. In order to compile RAUC for you host system, simply run::

  bitbake rauc-native

This will place a copy of the RAUC binary in ``tmp/deploy/tools`` in your
current build folder. To test it, try::

  tmp/deploy/tools/rauc --version

Bundle generation
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
  you specified in your ``system.conf`` or, more general, the compatible of the
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


PTXdist
-------
   * System setup (system conf, keys, ...)
   * Bundle creation

System Boot
-----------
   * Watchdog vs. Confirmation
   * Kernel Command Line: booted slot
   * D-Bus-Service vs. Single Binary
   * Cron

Barebox
-------
   * State/Bootchooser

GRUB
----

   * Grub-Environment
   * Scripting

Backend
-------

Persistent Data
---------------

   * SSH-Keys?
