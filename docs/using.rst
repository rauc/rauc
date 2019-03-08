Using RAUC
==========

For using RAUC in your embedded project, you will need to build at least two
versions of it:

* One for your **host** (build or development) system.
  This will allow you to create, inspect and modify bundles.

* One for your **target** system.
  This can act both as the service for handling the installation on your system,
  as a command line tool that allows triggering the installation and inspecting your
  system or obtaining bundle information.

All common embedded Linux build system recipes for RAUC will solve the task of
creating appropriate binaries for you as well as caring for bundle creation and
partly system configuration.
If you intend to use RAUC with Yocto, use the
`meta-rauc <https://github.com/rauc/meta-rauc>`_ layer, in case you use
PTXdist, simply enable RAUC in your configuration.

.. note::
  When using the RAUC service from your application, the D-Bus interface is
  preferable to using the provided command-line tool.

Creating Bundles
----------------

To create an update bundle on your build host, RAUC provides the ``bundle``
sub-command:

.. code-block:: sh

  rauc bundle --cert=<certfile> --key=<keyfile> --keyring=<keyringfile> <input-dir> <output-file>

Where ``<input-dir>`` must be a directory containing all images and scripts the
bundle should include, as well as a manifest file ``manifest.raucm`` that
describes the content of the bundle for the RAUC updater on the target:
which image to install to which slot, which scripts to execute etc.
``<output-file>`` must be the path of the bundle file to create. Note that RAUC
bundles must always have a ``.raucb`` file name suffix in order to ensure that
RAUC treats them as bundles.

Instead of the ``certfile`` and ``keyfile`` arguments, PKCS#11 URLs such as
``'pkcs11:token=rauc;object=autobuilder-1'`` can be used to avoid storing
sensitive key material as files (see :ref:`PKCS#11 Support <pkcs11-support>`
for details).

While the ``--cert`` and ``--key`` argument are mandatory for signing and must
provide the certificate and private key that should be used for creating the
signature, the ``--keyring`` argument is optional and (if given) will be used
for verifying the trust chain validity of the signature after creation.
Note that this is very useful to prevent from signing with obsolete
certificates, etc.

Obtaining Bundle Information
----------------------------

.. code-block:: sh

  rauc info [--output-format=<format>] <input-file>

The ``info`` command lists the basic meta data of a bundle (compatible, version,
build-id, description) and the images and hooks contained in the bundle.

You can control the output format depending on your needs.
By default it will print a human readable representation of the bundle not
intended for being processed programmatically.
Alternatively you can obtain a shell-parsable description or a JSON
representation of the bundle content.

Installing Bundles
------------------

To actually install an update bundle on your target hardware, RAUC provides the
``install`` command:

.. code-block:: sh

  rauc install <input-file>

Alternatively you can trigger a bundle installation `using the D-Bus API`_.

Viewing the System Status
-------------------------

For debugging purposes and for scripting it is helpful to gain an overview of
the current system as RAUC sees it.
The ``status`` command allows this:

.. code-block:: sh

  rauc status [--detailed] [--output-format=<format>]

You can choose the output style of RAUC status depending on your needs.
By default it will print a human readable representation of your system's most
important properties. Alternatively you can obtain a shell-parsable description,
or a JSON representation of the system status.
If more information is needed such as the slots' :ref:`status <slot-status>` add
the command line option ``--detailed``.

React to a Successfully Booted System/Failed Boot
-------------------------------------------------

Normally, the full system update chain is not complete before being sure that
the newly installed system runs without any errors.
As the definition and detection of a `successful` operation is really
system-dependent, RAUC provides commands to preserve a slot as being the
preferred one to boot or to discard a slot from being bootable.

.. code-block:: sh

  rauc status mark-good

After verifying that the currently booted system is fully operational, one
wants to signal this information to the underlying bootloader implementation
which then, for example, resets a boot attempt counter.

.. code-block:: sh

  rauc status mark-bad

If the current boot failed in some kind, this command can be used to communicate
that to the underlying bootloader implementation. In most cases this will
disable the currently booted slot or at least switch to a different one.

Although not very useful in the field, both commands recognize an optional
argument to explicitly identify the slot to act on:

.. code-block:: sh

  rauc status mark-{good,bad} [booted | other | <SLOT_NAME>]

This is to maintain consistency with respect to ``rauc status mark-active``
where that argument is definitively wanted, see :ref:`here
<optional-slot-identifier-argument>`.

.. _mark-active:

Manually Switch to a Different Slot
-----------------------------------

One can think of a variety of reasons to switch the preferred slot for the next
boot by hand, for example:

* Recurrently test the installation of a bundle in development starting from a
  known state.
* Activate a slot that has been installed sometime before and whose activation
  has explicitly been prevented at that time using the system configuration
  file's parameter :ref:`activate-installed <activate-installed>`.
* Switch back to the previous slot because one really knows |better (TM)|.

.. |better (TM)| unicode:: better U+2122 .. with trademark sign

To do so, RAUC offers the subcommand

.. _optional-slot-identifier-argument:

.. code-block:: sh

  rauc status mark-active [booted | other | <SLOT_NAME>]

where the optional argument decides which slot to (re-)activate at the expense
of the remaining slots. Choosing ``other`` switches to the next bootable slot
that is not the one that is currently booted. In a two-slot-setup this is
just... the other one. If one wants to explicitly address a known slot, one can
do so by using its slot name which has the form ``<slot-class>.<idx>`` (e.g.
``rootfs.1``), see :ref:`this <slot.slot-class.idx-section>` part of section
:ref:`System Configuration File <sec_ref_slot_config>`. Last but not least,
after switching to a different slot by mistake, before having rebooted this can
be remedied by choosing ``booted`` as the argument which is, by the way, the
default if the optional argument has been omitted.
The date and time of activation as well as the number of activations is part of
the slot's metadata which is stored in the slot status file, see section
:ref:`slot-status`.

Customizing the Update
----------------------

RAUC provides several ways to customize the update process. Some allow adding
and extending details more fine-grainedly, some allow replacing major parts of
the default behavior of RAUC.

In general, there exist three major types of customization: configuration,
handlers and hooks.

The first is configuration through variables.
This allow controlling the update in a predefined way.

The second type is using `handlers`. Handlers allow extending or replacing the
installation process. They are executables (most likely shell scripts) located
in the root filesystem and configured in the system's configuration file. They
control static behavior of the system that should remain the same over future
updates.

The last type are `hooks`. They are similar to `handlers`, except that they are
contained in the update bundle. Thus they allow to flexibly extend or customize
one or more updates by some special behavior.
A common example would be using a per-slot post-install hook that handles
configuration migration for a new software version. Hooks are especially useful
to handle details of installing an update which were not considered in the
previously deployed version.

In the following, handlers and hooks will be explained in more detail.

System Configuration File
~~~~~~~~~~~~~~~~~~~~~~~~~

Beside providing the basic slot layout, RAUC's system configuration file also
allows you to configure parts of its runtime behavior, such as handlers (see
below), paths, etc.
For a detailed list of possible configuration options,
see :ref:`sec_ref_slot_config` section in the Reference chapter.

System-Based Customization: Handlers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a detailed list of all environment variables exported for the handler
scripts, see  the :ref:`sec-handler-interface` section.

.. rubric:: Pre-Install Handler

.. code-block:: cfg

  [handlers]
  pre-install=/usr/lib/rauc/pre-install

RAUC will call the pre-install handler (if given) during the bundle
installation process, right before calling the default or custom installation
process. At this stage, the bundle is mounted, its content is accessible and the
target group has been determined successfully.

If calling the handler fails or the handler returns a non-zero exit code, RAUC
will abort installation with an error.

.. rubric:: Post-Install Handler

.. code-block:: cfg

  [handlers]
  post-install=/usr/lib/rauc/post-install

The post-install handler will be called right after RAUC successfully performed
a system update. If any error occurred during installation, the post-install
handler will not be called.

Note that a failed call of the post-install handler or a non-zero exit code
will cause a notification about the error but will not change the result of the
performed update anymore.

A possible usage for the post-install handler could be to trigger an automatic
restart of the system.

.. rubric:: System-Info Handler

.. code-block:: cfg

  [handlers]
  system-info=/usr/lib/rauc/system-info

The system-info handler is called after loading the configuration file. This
way it can collect additional variables from the system, like the system's
serial number.

The handler script must return a system serial number by echoing
`RAUC_SYSTEM_SERIAL=<value>` to standard out.

.. _sec-hooks:

Bundle-Based Customization: Hooks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike handlers, hooks allow the author of a bundle to add or replace
functionality for the installation of a specific bundle. This can be useful for
performing additional migration steps, checking for specific previously
installed bundle versions or for manually handling updates of images RAUC
cannot handle natively.

To reduce the complexity and number of files in a bundle, all hooks must be
handled by a single executable that is registered in the bundle's manifest:

.. code-block:: cfg

  [hooks]
  filename=hook

Each hook must be activated explicitly and leads to a call of the hook executable
with a specific argument that allows to distinguish between the different hook
types. Multiple hook types must be separated with a ``;``.

In the following the available hooks are listed. Depending on their purpose,
some are image-specific, i.e. they will be executed for the installation of a
specific image only, while some other are global.

.. _sec-install-hooks:

Install Hooks
^^^^^^^^^^^^^

Install hooks operate globally on the bundle installation.

The following environment variables will be passed to the hook executable:

.. glossary::

  ``RAUC_SYSTEM_COMPATIBLE``
    The compatible value set in the system configuration file

  ``RAUC_SYSTEM_VARIANT``
    The system's variant as obtained by the variant source
    (refer ref:`sec-variants`)

  ``RAUC_MF_COMPATIBLE``
    The compatible value provided by the current bundle

  ``RAUC_MF_VERSION``
    The value of the version field as provided by the current bundle

  ``RAUC_MOUNT_PREFIX``
    The global RAUC mount prefix path

.. rubric:: Install-Check Hook

.. code-block:: cfg

  [hooks]
  filename=hook
  hooks=install-check

This hook will be executed instead of the normal compatible check in order to
allow performing a custom compatibility check based on compatible and/or version
information.

To indicate that a bundle should be rejected, the script must return with an
exit code >= 10.

If available, RAUC will use the last line printed to standard error by
the hook executable as the rejection reason message and provide it to the user:

.. code-block:: sh

  #!/bin/sh

  case "$1" in
          install-check)
                  if [[ "$RAUC_MF_COMPATIBLE" != "$RAUC_SYSTEM_COMPATIBLE" ]]; then
                          echo "Compatible does not match!" 1>&2
                          exit 10
                  fi
                  ;;
          *)
                  exit 1
                  ;;
  esac

  exit 0

.. _sec-slot-hooks:

Slot Hooks
^^^^^^^^^^

Slot hooks are called for each slot an image will be installed to. In order to
enable them, you have to specify them in the ``hooks`` key under the respective
``image`` section.

Note that hook slot operations will be passed to the executable with the prefix
``slot-``. Thus if you intend to check for the pre-install hook, you have to
check for the argument to be ``slot-pre-install``.

The following environment variables will be passed to the hook executable:

.. glossary::

  ``RAUC_SYSTEM_COMPATIBLE``
    The compatible value set in the system configuration file

  ``RAUC_SYSTEM_VARIANT``
    The system's variant as obtained by the variant source
    (refer ref:`sec-variants`)

  ``RAUC_SLOT_NAME``
    The name of the currently installed slot

  ``RAUC_SLOT_STATE``
    The state of the currently installed slot
    (will always be 'inactive' for slots we install to)

  ``RAUC_SLOT_CLASS``
    The class of the currently installed slot

  ``RAUC_SLOT_TYPE``
    The type of the currently installed slot

  ``RAUC_SLOT_DEVICE``
    The device of the currently installed slot

  ``RAUC_SLOT_BOOTNAME``
    If set, the bootname of the currently installed slot

  ``RAUC_SLOT_PARENT``
    If set, the parent of the currently installed slot

  ``RAUC_SLOT_MOUNT_POINT``
    If available, the mount point of the currently installed slot

  ``RAUC_IMAGE_NAME``
    If set, the file name of the image currently to be installed

  ``RAUC_IMAGE_DIGEST``
    If set, the digest of the image currently to be installed

  ``RAUC_IMAGE_CLASS``
    If set, the target class of the image currently to be installed

  ``RAUC_MOUNT_PREFIX``
    The global RAUC mount prefix path

.. rubric:: Pre-Install Hook

The pre-install hook will be called right before the update procedure for the
respective slot will be started. For slot types that represent a mountable file
system, the hook will be executed with having the file system mounted.

.. code-block:: cfg

  [hooks]
  filename=hook

  [image.rootfs]
  filename=rootfs.img
  size=...
  sha256=...
  hooks=pre-install


.. rubric:: Post-Install Hook

The post-install hook will be called right after the update procedure for the
respective slot was finished successfully. For slot types that represent a
mountable file system, the hook will be executed with having the file system
mounted. This allows to write some post-install information to the slot. It is
also useful to copy files from the currently active system to the newly
installed slot, for example to preserve application configuration data.

.. code-block:: cfg

  [hooks]
  filename=hook

  [image.rootfs]
  filename=rootfs.img
  size=...
  sha256=...
  hooks=post-install

An example on how to use a post-install hook:

.. code-block:: sh

  #!/bin/sh

  case "$1" in
          slot-post-install)
                  # only rootfs needs to be handled
                  test "$RAUC_SLOT_CLASS" = "rootfs" || exit 0

                  touch "$RAUC_SLOT_MOUNT_POINT/extra-file"
                  ;;
          *)
                  exit 1
                  ;;
  esac

  exit 0


.. rubric:: Install Hook

The install hook will replace the entire default installation process for the
target slot of the image it was specified for. Note that when having the install
hook enabled, pre- and post-install hooks will *not* be executed.
The install hook allows to fully customize the way an image is installed. This
allows performing special installation methods that are not natively supported
by RAUC, for example to upgrade the bootloader to a new version while also
migrating configuration settings.

.. code-block:: cfg

  [hooks]
  filename=hook

  [image.rootfs]
  filename=rootfs.img
  size=...
  sha256=...
  hooks=install

Full Custom Update
~~~~~~~~~~~~~~~~~~

For some special tasks (recovery, testing, migration) it might be required to
completely replace the default RAUC update mechanism and to only use its
infrastructure for executing an application or a script on the target side.

For this case, you may replace the entire default installation handler of rauc
by a custom handler script or application.

Refer manifest :ref:`[handler] <sec-manifest-handler>` section description
on how to achieve this.


Using the D-Bus API
-------------------

The RAUC D-BUS API allows seamless integration into existing or
project-specific applications, incorporation with bridge services such as the
`rauc-hawkbit` client and also the rauc CLI uses it.

The API's service domain is ``de.pengutronix.rauc`` while the object path is
``/``.

Installing a Bundle
~~~~~~~~~~~~~~~~~~~

The D-Bus API's main purpose is to trigger and monitor the installation
process via its ``Installer`` interface.

The ``Install`` method call triggers the installation of a given bundle in the
background and returns immediately.
Upon completion of the installation RAUC emits the ``Completed`` signal,
indicating either successful or failed installation.
For details on triggering the installation process, see the
:ref:`gdbus-method-de-pengutronix-rauc-Installer.Install` chapter in the
reference documentation.

While the installation is in progress, constant progress information will be
emitted in form of changes to the ``Progress`` property.

.. _sec_processing_progress:

Processing Progress Data
~~~~~~~~~~~~~~~~~~~~~~~~

The progress property will be updated upon each change of the progress value.
For details see the :ref:`gdbus-property-de-pengutronix-rauc-Installer.Progress`
chapter in the reference documentation.

To monitor ``Progress`` property changes from your application, attach to the
``PropertiesChanged`` signal and filter on the ``Operation`` properties.

Each progress step emitted is a tuple ``(percentage, message, nesting depth)``
describing a tree of progress steps::

  ├"Installing" (0%)
  │ ├"Determining slot states" (0%)
  │ ├"Determining slot states done." (20%)
  │ ├"Checking bundle" (20%)
  │ │ ├"Verifying signature" (20%)
  │ │ └"Verifying signature done." (40%)
  │ ├"Checking bundle done." (40%)
  │ ...
  └"Installing done." (100%)

This hierarchical structure allows applications to decide for the appropriate
granularity to display information.
Progress messages with a nesting depth of 1 are only ``Installing`` and
``Installing done.``.
A nesting depth of 2 means more fine-grained information while larger depths
are even more detailed.

Additionally, the nesting depth information allows the application to print
tree-like views as shown above.
The ``percentage`` value always goes from 0 to 100 while the ``message`` is
always a human-readable English string.
For internationalization you may use a
`gettext <https://www.gnu.org/software/gettext/>`_-based approach.

Examples Using ``busctl`` Command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Triggering an installation:

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Install s "/path/to/bundle"

Mark a slot as good:

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Mark ss "good" "rootfs.0"

Mark a slot as active:

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Mark ss "active" "rootfs.0"

Get the `Operation` property containing the current operation:

.. code-block:: sh

  busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer Operation

Get the `Progress` property containing the progress information:

.. code-block:: sh

  busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer Progress

Get the `LastError` property, which contains the last error that occurred
during an installation.

.. code-block:: sh

  busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer LastError

Get the status of all slots

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer GetSlotStatus

Get the current primary slot

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer GetPrimary

Monitor the D-Bus interface

.. code-block:: sh

  busctl monitor de.pengutronix.rauc

.. _debugging:

Debugging RAUC
--------------

When RAUC fails to start on your target during integration or later during
installation of new bundles it can have a variety of causes.

This section will lead you trough the most common options you have for
debugging what actually went wrong.

In each case it is quite essential to know that RAUC, if not compiled with
``--disable-service`` runs as a service on your target that is either
controlled by your custom application or by the RAUC command line interface.

The frontend will always only show the 'high level' error outpt, e.g. when an
installation failed:

.. code-block:: sh

  rauc-Message: 08:27:12.083: installing /home/enrico/Code/rauc/good-bundle-hook.raucb: LastError: Failed mounting bundle: failed to run mount: Child process exited with code 1
  rauc-Message: 08:27:12.083: installing /home/enrico/Code/rauc/good-bundle-hook.raucb: idle
  Installing `/home/enrico/Code/rauc/good-bundle-hook.raucb` failed

In simple cases this might be sufficient for identifying the actual problem, in
more complicated cases this may give a rough hint.
For a more detailed look on what went wrong you need to inspect the rauc
service log instead.

If you run RAUC using systemd, the log can be obtained using

.. code-block:: sh

  journalctl -u rauc

When using SysVInit, your service script needs to configure logging itself.
A common way is to dump the log e.g. /var/log/rauc.

It may also be worth starting the RAUC service via command line on a second
shell to have a live view of what is going on when you invoke e.g. ``rauc
install`` on the first shell.

Increasing Debug Verbosity
~~~~~~~~~~~~~~~~~~~~~~~~~~

Both for the service and the command line interface it is often useful to
increase the log level for narrowing down the actual error cause or gaining
more information about the circumstances when the error occurs.

RAUC uses glib and the
`glib logging framework <https://developer.gnome.org/programming-guidelines/stable/logging.html.en>`_ with the basic log domain 'rauc'.

For simple cases, you can activate logging by passing the ``-d`` or ``--debug`` option to either the CLI:

.. code-block:: sh

  rauc install -d bundle.raucb ..

or the service (you might need to modify your systemd or SysVInit
service file).

.. code-block:: sh

  rauc service -d

For more fine grained and advanced debugging options, use the
``G_MESSAGES_DEBUG`` environment variable.
This allows enabling different log domains. Currently available are:

:all: enable all log domains

:rauc: enable default RAUC log domain (same as calling with ``-d``)

:rauc-subprocess: enable logging of subprocess calls

  This will dump the entire program call invoked by RAUC and can help tracing
  down or reproducing issues caused by other programs invoked.

Example invocation:

.. code-block:: sh

  G_MESSAGES_DEBUG="rauc rauc-subprocess" rauc service

