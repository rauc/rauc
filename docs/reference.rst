Reference
=========

.. contents::
   :local:
   :depth: 1

.. _sec_ref_slot_config:

System Configuration File
-------------------------

A configuration file located in ``/etc/rauc/system.conf`` describes the
number and type of available slots.
It is used to validate storage locations for update images.
Each board type requires its special configuration.

This file is part of the root file system.

Example configuration:

.. code-block:: cfg

  [system]
  compatible=FooCorp Super BarBazzer
  bootloader=barebox

  [keyring]
  path=/etc/rauc/keyring.pem

  [handlers]
  system-info=/usr/lib/rauc/info-provider.sh
  post-install=/usr/lib/rauc/postinst.sh

  [slot.rootfs.0]
  device=/dev/sda0
  type=ext4
  bootname=system0

  [slot.rootfs.1]
  device=/dev/sda1
  type=ext4
  bootname=system1


**[system] section**

``compatible``
  A user-defined compatible string that describes the target hardware as
  specific enough as required to prevent faulty updating systems with the wrong
  firmware. It will be matched against the ``compatible`` string defined in the
  update manifest.

``bootloader``
  The bootloader implementation RAUC should use for its slot switching
  mechanism. Currently supported values (and bootloaders) are ``barebox``,
  ``grub``, ``u-boot``.

``mountprefix``
  Prefix of the path where bundles and slots will be mounted. Can be overwritten
  by the command line option ``--mount``.

``grubenv``
  Only valid when ``bootloader`` is set to ``grub``.
  Specifies the path under which the GRUB environment can be accessed.

.. _activate-installed:

``activate-installed``
  This boolean value controls if a freshly installed slot is automatically
  marked active with respect to the used bootloader. Its default value is
  ``true`` which means that this slot is going to be started the next time the
  system boots. If the value of this parameter is ``false`` the slot has to be
  activated manually in order to be booted, see section :ref:`mark-active`.

**[keyring] section**

The ``keyring`` section refers to the trusted keyring used for signature
verification.

``path``
  Path to the keyring file in PEM format. Either absolute or relative to the
  system.conf file.

**[autoinstall] section**

The auto-install feature allows to configure a path that will be checked upon
RAUC service startup.
If there is a bundle placed under this specific path, this bundle will be
installed automatically without any further interaction.

This feature is useful for automatically updating the slot RAUC currently runs
from, like for asymmetric redundancy setups where the update is always
performed from a dedicated (recovery) slot.

``path``
  The full path of the bundle file to check for.
  If file at ``path`` exists, auto-install will be triggered.

**[handlers] section**

Handlers allow to customize RAUC by placing scripts in the system that RAUC can
call for different purposes. All parameters expect pathnames to the script to
be executed. Pathnames are either absolute or relative to the system.conf file
location.

RAUC passes a set of environment variables to handler scripts.
See details about using handlers in `Custom Handlers (Interface)`_.

``system-info``
  This handler will be called when RAUC starts up, right after loading the
  system configuration file.
  It is used for obtaining further information about the individual system RAUC
  runs on.
  The handler script must print the information to standard output in form of
  key value pairs ``KEY=value``.
  The following variables are supported:

  ``RAUC_SYSTEM_SERIAL``
    Serial number of the individual board

``pre-install``
  This handler will be called right before RAUC starts with the installation.
  This is after RAUC has verified and mounted the bundle, thus you can access
  bundle content.

``post-install``
  This handler will be called after a successful installation.
  The bundle is still mounted at this moment, thus you could access data in it
  if required.

.. note::
  When using a full custom installation
  (see :ref:`[handler] section <sec-manifest-handler>`)
  RAUC will not execute any system handler script.

.. _slot.slot-class.idx-section:

**[slot.<slot-class>.<idx>] section**

Each slot is identified by a section starting with ``slot.`` followed by
the slot class name, and a slot number.
The *slot class* name is used in the *update manifest* to target the correct
set of slots.

``device``
  The slot's device path.

``type``
  The type describing the slot. Currently supported values are ``raw``,
  ``nand``, ``ubivol``, ``ubifs``, ``ext4``, ``vfat``.
  See table :ref:`sec-slot-type` for a more detailed list of these different types.

``bootname``
  For bootable slots, the name the bootloader uses to identify it. The real
  meaning of this depends on the bootloader implementation used.

``parent``
  The ``parent`` entry is used to bind additional slots to a bootable root
  file system slot.
  This is used together with the ``bootname`` to identify the set of currently
  active slots, so that the inactive one can be selected as the update target.
  The parent slot is referenced using the form ``<slot-class>.<idx>``.

``readonly``
  Marks the slot as existing but not updatable. May be used for sanity checking
  or informative purpose. A ``readonly`` slot cannot be a target slot.


Manifest
--------

A valid manifest file must have the file extension ``.raucm``.

.. code-block:: cfg

  [update]
  compatible=FooCorp Super BarBazzer
  version=2016.08-1
  
  [image.rootfs]
  filename=rootfs.ext4
  size=419430400
  sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3
  
  [image.appfs]
  filename=appfs.ext4
  size=219430400
  sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca


**[update] section**

``compatible``
  A user-defined compatible string that must match the compatible string of the
  system the bundle should be installed on.

``version``
  A free version field that can be used to provide and track version
  information. No checks will be performed on this version by RAUC itself,
  although a handler can use this information to reject updates.

``description``
  A free-form description field that can be used to provide human-readable
  bundle information.

``build``
  A build id that would typically hold the build date or some build
  information provided by the bundle creation environment. This can help to
  determine the date and origin of the built bundle.


**[hooks] section**

``filename``
  Hook script path name, relative to the bundle content.

``hooks``
  List of hooks enabled for this bundle.

.. _sec-manifest-handler:

**[handler] section**

``filename``
  Handler script path name, relative to the bundle content. Used to fully
  replace default update process.

``args``
  Arguments to pass to the handler script, such as ``args=--verbose``


**[image.<slot-class>] section**

``filename``
  Name of the image file (relative to bundle content).

``sha256``
  sha256 of image file. RAUC determines this value automatically when creating
  a bundle, thus it is not required to set this by hand.

``size``
  size of image file. RAUC determines this value automatically when creating a
  bundle, thus it is not required to set this by hand.

``hooks``
  List of per-slot hooks enabled for this image.


Slot Status File
----------------

A slot status file is generated by RAUC after having updated a slot. If the
slot is writeable for RAUC (because it contains a writable filesystem), it will
place a small file named ``slot.raucs`` in its root directory, containing the
sha256 of the installed image.

.. code-block:: cfg

  [slot]
  status=ok
  sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3


Command Line Tool
-----------------

.. code-block:: man

  Usage:
    rauc [OPTION...] <COMMAND>
  
  Options:
    -c, --conf=FILENAME               config file
    --cert=PEMFILE                    cert file
    --key=PEMFILE                     key file
    --keyring=PEMFILE                 keyring file
    --intermediate=PEMFILE            intermediate CA file name
    --mount=PATH                      mount prefix
    --override-boot-slot=SLOTNAME     override auto-detection of booted slot
    --handler-args=ARGS               extra handler arguments
    -d, --debug                       enable debug output
    --version                         display version
    -h, --help
  
  List of rauc commands:
    bundle        Create a bundle
    resign        Resign an already signed bundle
    checksum      Update a manifest with checksums (and optionally sign it)
    install       Install a bundle
    info          Show file information
    status        Show status


.. _sec-handler-interface:

Custom Handlers (Interface)
---------------------------

Interaction between RAUC and custom handler shell scripts is done using shell
variables.

.. glossary::

  ``RAUC_SYSTEM_CONFIG``
    Path to the system configuration file (default path is ``/etc/rauc/system.conf``)

  ``RAUC_CURRENT_BOOTNAME``
    Bootname of the slot the system is currently booted from

  ``RAUC_UPDATE_SOURCE``
    Path to mounted update bundle, e.g. ``/mnt/rauc/bundle``

  ``RAUC_MOUNT_PREFIX``
    Provides the path prefix that may be used for RAUC mount points

  ``RAUC_SLOTS``
    An iterator list to loop over all existing slots. Each item in the list is
    an integer referencing one of the slots. To get the slot parameters, you have to
    resolve the per-slot variables (suffixed with <N> placeholder for the
    respective slot number).

  ``RAUC_TARGET_SLOTS``
    An iterator list similar to ``RAUC_SLOTS`` but only containing slots that
    were selected as target slots by the RAUC target slot selection algorithm.
    You may use this list for safely installing images into these slots.

  ``RAUC_SLOT_NAME_<N>``
    The name of slot number <N>, e.g. ``rootfs.0``

  ``RAUC_SLOT_CLASS_<N>``
    The class of slot number <N>, e.g. ``rootfs``

  ``RAUC_SLOT_DEVICE_<N>``
    The device path of slot number <N>, e.g. ``/dev/sda1``

  ``RAUC_SLOT_BOOTNAME_<N>``
    The bootloader name of slot number <N>, e.g. ``system0``

  ``RAUC_SLOT_PARENT_<N>``
    The name of slot number <N>, empty if none, otherwise name of parent slot


.. code::

  for i in $RAUC_TARGET_SLOTS; do
          eval RAUC_SLOT_DEVICE=\$RAUC_SLOT_DEVICE_${i}
          eval RAUC_IMAGE_NAME=\$RAUC_IMAGE_NAME_${i}
          eval RAUC_IMAGE_DIGEST=\$RAUC_IMAGE_DIGEST_${i}
  done


D-Bus API
---------

RAUC provides a D-Bus API that allows other applications to easily communicate
with RAUC for installing new firmware.


de.pengutronix.rauc.Installer

Methods
~~~~~~~
:ref:`Install <gdbus-method-de-pengutronix-rauc-Installer.Install>` (IN  s source);

Signals
~~~~~~~
:ref:`Completed <gdbus-signal-de-pengutronix-rauc-Installer.Completed>` (i result);

Properties
~~~~~~~~~~
:ref:`Operation <gdbus-property-de-pengutronix-rauc-Installer.Operation>` readable   s

:ref:`LastError <gdbus-property-de-pengutronix-rauc-Installer.LastError>` readable   s

:ref:`Progress <gdbus-property-de-pengutronix-rauc-Installer.Progress>` readable   (isi)

Description
~~~~~~~~~~~

Method Details
~~~~~~~~~~~~~~

.. _gdbus-method-de-pengutronix-rauc-Installer.Install:

The Install() Method
^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer.Install()
  Install (IN  s source);

Triggers the installation of a bundle.

IN s *source*:
    Path to bundle to be installed

Signal Details
~~~~~~~~~~~~~~

.. _gdbus-signal-de-pengutronix-rauc-Installer.Completed:

The "Completed" Signal
^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer::Completed
  Completed (i result);

This signal is emitted when an installation completed, either
successfully or with an error.

i *result*:
    return code (0 for success)

Property Details
~~~~~~~~~~~~~~~~

.. _gdbus-property-de-pengutronix-rauc-Installer.Operation:

The "Operation" Property
^^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:Operation
  Operation  readable   s

Represents the current (global) operation RAUC performs.

.. _gdbus-property-de-pengutronix-rauc-Installer.LastError:

The "LastError" Property
^^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:LastError
  LastError  readable   s

Holds the last message of the last error that occured.

.. _gdbus-property-de-pengutronix-rauc-Installer.Progress:

The "Progress" Property
^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:Progress
  Progress  readable   (isi)

Provides installation progress informations in the form

(percentage, message, nesting depth)

RAUC's Basic Update Procedure
-----------------------------

Performing an update using the default RAUC mechanism will work as follows:

1. Startup, read system configuration
#. Determine slot states
#. Verify bundle signature (reject if invalid)
#. Mount bundle (SquashFS)
#. Parse and verify manifest
#. Determine target install group

   A. Execute `pre install handler` (optional)

#. Verify bundle compatible against system compatible (reject if not matching)
#. Mark target slots as non-bootable for bootloader
#. Iterate over each image specified in the manifest

   A. Determine update handler (based on image and slot type)
   #. Try to mount slot and read slot status information

      a. Skip update if new image hash matches hash of insalled one

   #. Perform slot update (image copy / mkfs+tar extract / ...)
   #. Try to write slot status information

#. Mark target slots as new primary boot source for the bootloader

   A. Execute `post install` handler (optional)

#. Unmount bundle
#. Terminate successfully if no error occurred
