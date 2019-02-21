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

.. note:: When changing the configuration file on your running target you need
  to restart the RAUC service in order to let the changes take effect.

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

.. _system-section:

**[system] section**

``compatible``
  A user-defined compatible string that describes the target hardware as
  specific enough as required to prevent faulty updating systems with the wrong
  firmware. It will be matched against the ``compatible`` string defined in the
  update manifest.

``bootloader``
  The bootloader implementation RAUC should use for its slot switching
  mechanism. Currently supported values (and bootloaders) are ``barebox``,
  ``grub``, ``uboot``.

``mountprefix``
  Prefix of the path where bundles and slots will be mounted. Can be overwritten
  by the command line option ``--mount``. Defaults to ``/mnt/rauc/``.

``grubenv``
  Only valid when ``bootloader`` is set to ``grub``.
  Specifies the path under which the GRUB environment can be accessed.

``barebox-statename``
  Only valid when ``bootloader`` is set to ``barebox``.
  Overwrites the default state ``state`` to a user-defined state name. If this
  key not exists, the bootchooser framework searches per default for ``/state``
  or ``/aliases/state``.

``efi-use-bootnext``
  Only valid when ``bootloader`` is set to ``efi``.
  If set to ``false``, this disables using efi variable ``BootNext`` for
  marking a slot primary.
  This is useful for setups where the BIOS already handles the slot switching
  on watchdog resets.
  Behavior defaults to ``true`` if option is not set.

.. _activate-installed:

``activate-installed``
  This boolean value controls if a freshly installed slot is automatically
  marked active with respect to the used bootloader. Its default value is
  ``true`` which means that this slot is going to be started the next time the
  system boots. If the value of this parameter is ``false`` the slot has to be
  activated manually in order to be booted, see section :ref:`mark-active`.

.. _statusfile:

``statusfile``
  If this key exists, it points to a file where slot status information should
  be stored (e.g. slot specific metadata, see :ref:`slot-status`).
  This file should be located on a filesystem which is not overwritten during
  updates.

``max-bundle-download-size``
  Defines the maximum downloadable bundle size in bytes, and thus must be
  a simple integer value (without unit) greater than zero.
  It overwrites the compiled-in default value of 8 MiB.

.. _keyring-section:

**[keyring] section**

The ``keyring`` section refers to the trusted keyring used for signature
verification.
Both ``path`` and ``directory`` options can be used together if
desired, though only one or the other is necessary to verify the bundle
signature.

``path``
  Path to the keyring file in PEM format. Either absolute or relative to the
  system.conf file.

``directory``
  Path to the keyring directory containing one or more certificates.
  Each file in this directory must contain exactly one certificate in CRL or
  PEM format.
  The filename of each certificate must have the form hash.N for a certificate
  or hash.rN for CRLs;
  where hash is obtained by ``X509_NAME_hash(3)`` or the ``--hash`` option of
  ``openssl(1)`` ``x509`` or ``crl`` commands.
  See documentation in ``X509_LOOKUP_hash_dir(3)`` for details.

``use-bundle-signing-time=<true/false>``
  If this boolean value is set to ``true`` then the bundle signing time
  is used instead of the current system time for certificate validation.

**[casync] section**

The ``casync`` section contains casync-related settings.
For more information about using casync support of RAUC, refer to
:ref:`casync-support`.

``storepath``
  Allows to set the path to use as chunk store path for casync to a fixed one.
  This is useful if your chunk store is on a dedicated server and will be the
  same pool for each update you perform.
  By default, the chunk store path is derived from the location of the RAUC
  bundle you install.

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
The `<slot-class>` name is used in the *update manifest* to target the correct
set of slots. It must not contain any `.` (dots) as these are used as
hierarchical separator.

``device=</path/to/dev>``
  The slot's device path. This one is mandatory.

``type=<type>``
  The type describing the slot. Currently supported ``<type>`` values are ``raw``,
  ``nand``, ``ubivol``, ``ubifs``, ``ext4``, ``vfat``.
  See table :ref:`sec-slot-type` for a more detailed list of these different types.
  Defaults to ``raw`` if none given.

``bootname=<name>``
  Registers the slot for being handled by the
  :ref:`bootselection interface <bootloader-interaction>` with the ``<name>``
  specified.
  The actual meaning of the name provided depends on the bootloader
  implementation used.

``parent=<slot>``
  The ``parent`` entry is used to bind additional slots to a bootable root
  file system ``<slot>``.
  This is used together with the ``bootname`` to identify the set of currently
  active slots, so that the inactive one can be selected as the update target.
  The parent slot is referenced using the form ``<slot-class>.<idx>``.

``readonly=<true/false>``
  Marks the slot as existing but not updatable. May be used for sanity checking
  or informative purpose. A ``readonly`` slot cannot be a target slot.

``force-install-same=<true/false>``
  If set to ``true`` this will bypass the default hash comparison for this slot
  and force RAUC to unconditionally update it. The default value is ``false``,
  which means that updating this slot will be skipped if new image's hash
  matches hash of installed one.
  This replaces the deprecated entry ``ignore-checksum``.

``resize=<true/false>``
  If set to ``true`` this will tell RAUC to resize the filesystem after having
  written the image to this slot. This only has an effect when writing an ext4
  file system to an ext4 slot, i.e. if the slot has``type=ext4`` set.

``extra-mount-opts=<options>``
  Allows to specify custom mount options that will be passed to the slots
  ``mount`` call as ``-o`` argument value.

.. _sec_ref_manifest:

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


.. _sec-manifest-update:

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
  See :ref:`sec-install-hooks` for more details.

  Valid items are: ``install-check``

.. _sec-manifest-handler:

**[handler] section**

``filename``
  Handler script path name, relative to the bundle content. Used to fully
  replace default update process.

``args``
  Arguments to pass to the handler script, such as ``args=--verbose``


.. _image.slot-class-section:

**[image.<slot-class>] section**

.. _image.slot-filename:

``filename``
  Name of the image file (relative to bundle content).
  RAUC uses the file extension and the slot type to decide how to extract the
  image file content to the slot.

``sha256``
  sha256 of image file. RAUC determines this value automatically when creating
  a bundle, thus it is not required to set this by hand.

``size``
  size of image file. RAUC determines this value automatically when creating a
  bundle, thus it is not required to set this by hand.

``hooks``
  List of per-slot hooks enabled for this image.
  See :ref:`sec-slot-hooks` for more details.

  Valid items are: ``pre-install``, ``install``, ``post-install``

.. _slot-status:

Slot Status
-----------

There is some slot specific metadata that are of interest for RAUC, e.g. a hash
value of the slot's content (SHA-256 per default) that is matched against its
counterpart of an image inside a bundle to decide if an update of the slot has
to be performed or can be skipped.
These slot metadata can be persisted in one of two ways:
either in a slot status file stored on each slot containing a writable
filesystem or in a central status file that lives on a persistent filesystem
untouched by updates.
The former is RAUC's default whereas the latter mechanism is enabled by making
use of the optional key :ref:`statusfile <statusfile>` in the ``system.conf``
file.
Both are formatted as INI-like key/value files where the slot information is
grouped in a section named [slot] for the case of a per-slot file or in sections
termed with the slot name (e.g. [slot.rootfs.1]) for the central status file:

.. code-block:: cfg

  [slot]
  bundle.compatible=FooCorp Super BarBazzer
  bundle.version=2016.08-1
  bundle.description=Introduction of Galactic Feature XYZ
  bundle.build=2016.08.1/imx6/20170324-7
  status=ok
  sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3
  size=419430400
  installed.timestamp=2017-03-27T09:51:13Z
  installed.count=3

For a description of ``sha256`` and ``size`` keys see :ref:`this
<image.slot-class-section>` part of the section :ref:`Manifest
<sec_ref_manifest>`.
Having the slot's content's size allows to re-calculate the hash via ``head -c
<size> <slot-device> | sha256sum` or `dd bs=<size> count=1 if=<slot-device> |
sha256sum``.

The properties ``bundle.compatible``, ``bundle.version``, ``bundle.description``
and ``bundle.build`` are copies of the respective manifest properties.
More information can be found in this :ref:`subsection <sec-manifest-update>` of
section :ref:`Manifest <sec_ref_manifest>`.

RAUC also stores the point in time of installing the image to the slot in
``installed.timestamp`` as well as the number of updates so far in
``installed.count``.
Additionally RAUC tracks the point in time when a bootable slot is activated in
``activated.timestamp`` and the number of activations in ``activated.count``,
see section :ref:`mark-active`.
Comparing both timestamps is useful to decide if an installed slot has ever been
activated or if its activation is still pending.


Command Line Tool
-----------------

.. code-block:: man

  Usage:
    rauc [OPTION...] <COMMAND>

  Options:
    -c, --conf=FILENAME               config file
    --cert=PEMFILE|PKCS11-URL         cert file or PKCS#11 URL
    --key=PEMFILE|PKCS11-URL          key file or PKCS#11 URL
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

  Environment variables:
    RAUC_PKCS11_MODULE  Library filename for PKCS#11 module (signing only)
    RAUC_PKCS11_PIN     PIN to use for accessing PKCS#11 keys (signing only)

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

  ``RAUC_SLOT_TYPE_<N>``
    The type of slot number <N>, e.g. ``raw``

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

:ref:`Info <gdbus-method-de-pengutronix-rauc-Installer.Info>` (IN  s bundle, s compatible, s version);

:ref:`Mark <gdbus-method-de-pengutronix-rauc-Installer.Mark>` (IN  s state, IN  s slot_identifier, s slot_name, s message);

:ref:`GetSlotStatus <gdbus-method-de-pengutronix-rauc-Installer.GetSlotStatus>` (a(sa{sv}) slot_status_array);

:ref:`GetPrimary <gdbus-method-de-pengutronix-rauc-Installer.GetPrimary>` s primary);

Signals
~~~~~~~
:ref:`Completed <gdbus-signal-de-pengutronix-rauc-Installer.Completed>` (i result);

Properties
~~~~~~~~~~
:ref:`Operation <gdbus-property-de-pengutronix-rauc-Installer.Operation>` readable   s

:ref:`LastError <gdbus-property-de-pengutronix-rauc-Installer.LastError>` readable   s

:ref:`Progress <gdbus-property-de-pengutronix-rauc-Installer.Progress>` readable   (isi)

:ref:`Compatible <gdbus-property-de-pengutronix-rauc-Installer.Compatible>` readable   s

:ref:`Variant <gdbus-property-de-pengutronix-rauc-Installer.Variant>` readable   s

:ref:`BootSlot <gdbus-property-de-pengutronix-rauc-Installer.BootSlot>` readable   s

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
This method call is non-blocking.
After completion, the :ref:`"Completed" <gdbus-signal-de-pengutronix-rauc-Installer.Completed>` signal will be emitted.

IN s *source*:
    Path to bundle to be installed

.. _gdbus-method-de-pengutronix-rauc-Installer.Info:

The Info() Method
^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer.Info()
  Info (IN  s bundle, s compatible, s version);

Provides bundle info.

IN s *bundle*:
    Path to bundle information should be shown

s *compatible*:
    Compatible of bundle

s *version*:
    Version string of bundle

.. _gdbus-method-de-pengutronix-rauc-Installer.Mark:

The Mark() Method
^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer.Mark()
  Mark (IN  s state, IN  s slot_identifier, s slot_name, s message);

Keeps a slot bootable (state == "good"), makes it unbootable (state == "bad")
or explicitly activates it for the next boot (state == "active").

IN s *state*:
    Operation to perform (one out of "good", "bad" or "active")

IN s *slot_identifier*:
    Can be "booted", "other" or <SLOT_NAME> (e.g. "rootfs.1")

s *slot_name*:
    Name of the slot which has ultimately been marked

s *message*:
    Message describing what has been done successfully
    (e.g. "activated slot rootfs.0")

.. _gdbus-method-de-pengutronix-rauc-Installer.GetSlotStatus:

The GetSlotStatus() Method
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer.GetSlotStatus()
  GetSlotStatus (a(sa{sv}) slot_status_array);

Access method to get all slots' status.

a(sa{sv}) *slot_status_array*:
    Array of (slotname, dict) tuples with each dictionary representing the
    status of the corresponding slot

.. _gdbus-method-de-pengutronix-rauc-Installer.GetPrimary:

The GetPrimary() Method
^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer.GetPrimary()
  GetPrimary (s primary);

Get the current primary slot.

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
Possible values are ``idle`` or ``installing``.

.. _gdbus-property-de-pengutronix-rauc-Installer.LastError:

The "LastError" Property
^^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:LastError
  LastError  readable   s

Holds the last message of the last error that occurred.

.. _gdbus-property-de-pengutronix-rauc-Installer.Progress:

The "Progress" Property
^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:Progress
  Progress  readable   (isi)

Provides installation progress information in the form

(percentage, message, nesting depth)

Refer :ref:`Processing Progress Data <sec_processing_progress>` section.

.. _gdbus-property-de-pengutronix-rauc-Installer.Compatible:

The "Compatible" Property
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:Compatible
  Compatible  readable   s

Represents the system's compatible. This can be used to check for usable bundles.


.. _gdbus-property-de-pengutronix-rauc-Installer.Variant:

The "Variant" Property
^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:Variant
  Variant  readable   s

Represents the system's variant. This can be used to select parts of an bundle.


.. _gdbus-property-de-pengutronix-rauc-Installer.BootSlot:

The "BootSlot" Property
^^^^^^^^^^^^^^^^^^^^^^^

.. code::

  de.pengutronix.rauc.Installer:BootSlot
  BootSlot  readable   s

Represents the used boot slot.


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

      a. Skip update if new image hash matches hash of installed one

   #. Perform slot update (image copy / mkfs+tar extract / ...)
   #. Try to write slot status information

#. Mark target slots as new primary boot source for the bootloader

   A. Execute `post install` handler (optional)

#. Unmount bundle
#. Terminate successfully if no error occurred

.. _bootloader-interaction:

Bootloader Interaction
----------------------

RAUC comes with a generic interface for interacting with the bootloader.
It handles *all* slots that have a `bootname` property set.

It provides two base functions:

1) Setting state 'good' or 'bad', reflected by API routine `r_boot_set_state()`
   and command line tool option `rauc status mark <good/bad>`
2) Marking a slot 'primary', reflected by API routine `r_boot_set_primary()`
   and command line tool option `rauc status mark-active`

The default flow of how they will be called during the installation of a new
bundle (on Slot 'A') looks as follows::

  start   ->  install  ->  reboot  -> operating state  ->
          |            |                               |
     set A bad   set A primary                     set A good/bad

The aim of setting state 'bad' is to disable a slot in a way that the
bootloader will not select it for booting anymore.
As shown above this is either the case before an installation to make the
update atomic from the bootloader's perspective, or optionally after the
installation and a reboot into the new system, when a service detects that the
system is in an unusable state. This potentially allows falling back to a
working system.

The aim of setting a slot 'primary' is to let the bootloader select this slot
upon next reboot in case of having completed the installation successfully.
An alternative to directly marking a slot primary after installation is to
manually mark it primary at a later point in time, e.g. to let a complete set
of devices change their software revision at the same time.

Setting the slot 'good' is relevant for the first boot but for all subsequent
boots, too.
In most cases, this interaction with the bootloader is required by the
mechanism that enables fallback capability; rebooting a system one or several times
without calling `rauc status mark-good` will
let the bootloader boot an alternative system or abort boot operation
(depending on configuration).
Usually, bootloaders implement this fallback mechanism by some kind of counters
they maintain and decrease upon each boot.
In these cases *marking good* means resetting these counters.

A normal reboot of the system will look as follows::

  operating state  ->  reboot  -> operating state  ->
                                                   |
                                             set A good/bad

Some bootloaders do not require explicitly setting state 'good' as they are able
to differentiate between a POR and a watchdog reset, for example.

.. note: Despite the naming might suggest it, marking a slot bad and good are
  not reversible operations, meaning you have no guarantee that a slot first
  set to 'bad' and then set to 'good' again will be in the same state as
  before.
  Actually reactivating it will only work by marking it primary (active).

What the high-level functions described above actually do mainly depends on the underlying
bootloader used and the capabilities it provides.
Below is a short description about behavior of each bootloader interface
currently implemented:

U-Boot
~~~~~~

The U-Boot implementation assumes to have variables `BOOT_ORDER` and
`BOOT_x_ATTEMPTS` handled by the bootloader scripting.

:state bad:
  Sets the `BOOT_x_ATTEMPTS` variable of the slot to `0` and removes it from
  the `BOOT_ORDER` list

:state good:
  Sets the `BOOT_x_ATTEMPTS` variable back to its default value (`3`).

:primary:
  Moves the slot from its current position in the list in `BOOT_ORDER` to the
  first place and sets `BOOT_x_ATTEMPTS` to its initial value (`3`).
  If BOOT_ORDER was unset before, it generates a new list of all slots known to
  RAUC with the one to activate at the first position.


Barebox
~~~~~~~

The barebox implementation assumes using
`barebox bootchooser <https://barebox.org/doc/latest/user/bootchooser.html>`_.

:state bad:
  Sets both the `bootstate.systemX.priority` and
  `bootstate.systemX.remaining_attempts` to `0`.

:state good:
  Sets the `bootstate.systemX.remaining_attempts` to its default value
  (`3`).

:primary:
  Sets `bootstate.systemX.priority` to `20` and all other priorities that were
  non-zero before to `10`.
  It also sets `bootstate.systemX.remaining_attempts` to its initial value (`3`).

GRUB
~~~~

:state bad:
  Sets slot `x_OK` to `0` and resets `x_TRY` to `0`.

:state good:
  Sets slot `x_OK` to `1` and resets `x_TRY` to `0`.

:primary:
  Sets slot `x_OK` to `1` and resets `x_TRY` to `0`.
  Sets `ORDER` to contain slot ``x`` as first element and all other after.

EFI
~~~

:state bad:
  Removes the slot from `BootOrder`

:state good:
  Prepends the slot to the `BootOrder` list.
  This behaves slightly different than the other implementations because we use
  `BootNext` for allowing setting primary with an initial fallback option.
  Setting state good is then used to persist this.

:primary:
  Sets the slot as `BootNext` by default.
  This will make the slot being booted upon next reboot only!

  The behavior is different when ``efi-use-bootnext`` is set to ``false``.
  Then this prepends the slot to the `BootOrder` list as described for 'state
  good'.

.. note:: EFI implementations differ in how they handle new or unbootable
  targets etc. It may also depend on the actual implementation if EFI variable
  writing is atomic or not.
  Thus make sure your EFI works as expected and required.
