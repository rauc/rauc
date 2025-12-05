Using RAUC
==========

For using RAUC in your embedded project, you will need to build at least two
versions of it:

* One for your **host** (build or development) system.
  This will allow you to create, inspect and modify bundles.

* One for your **target** system.
  This can act both as the service for handling the installation on your system,
  or as a command line tool that allows triggering the installation, inspecting your
  system and obtaining bundle information.

All common embedded Linux build system recipes for RAUC will solve the task of
creating appropriate binaries for you as well as caring for bundle creation and
partly system configuration.
If you intend to use RAUC with Yocto, use the
`meta-rauc <https://github.com/rauc/meta-rauc>`_ layer, in case you use
PTXdist, simply enable RAUC in your configuration.

.. note::
  When using the RAUC service from your application, the D-Bus interface is
  preferable to using the provided command-line tool.

.. contents::
   :local:
   :depth: 1

Creating Bundles
----------------

To create an update bundle on your build host, RAUC provides the ``bundle``
sub-command:

.. code-block:: console

  $ rauc bundle --cert=<certfile|certurl> --key=<keyfile|keyurl> <input-dir> <bundle-name>

The ``<input-dir>`` must point to a directory containing all images, scripts
and other files that should be part of the created update bundle.
Additionally, a :ref:`RAUC manifest <sec_ref_manifest>` file ``manifest.raucm``
is expected in ``<input-dir>``.
The manifest describes the bundle content and the purpose of each included
image.

The created bundle will be stored under the given ``<bundle-name>``.

The ``--cert`` and ``--key`` argument specify the certificate and private key
for signing the bundle.
They can be provided either as PEM files or as :ref:`PKCS#11-URIs
<pkcs11-support>` (to avoid storing sensitive key material as plain files).

With the optional ``--signing-keyring=<certfile>`` argument, the signed bundle
can be verified against the keyring file as part of the bundle creation
process, for example to prevent signing with invalid or expired certificates.

.. note:: A more detailed description of how to create bundles can be found in
   the :ref:`sec-integration-bundle` section in the :ref:`sec-integration`
   chapter.

Obtaining Bundle Information
----------------------------

.. code-block:: console

  $ rauc info --keyring=<certfile> [--output-format=<format>] <input-file>

The ``info`` command lists the basic meta data of a bundle (compatible, version,
build-id, description) and the images and hooks contained in the bundle.

To authenticate the bundle information, it needs to be verified against a
keyring.
You can provide it via the system configuration or the ``--keyring``
argument.
If the verification should explicitly be skipped, you may also use
``--no-verify`` instead.

You can control the output ``<format>`` depending on your needs.
By default (or with ``readable``), it will print a human readable representation of the
bundle not intended for being processed programmatically.
Alternatively, with ``shell`` you can obtain a shell-parsable description or a JSON
representation of the bundle content with ``json-2``.

Installing Bundles
------------------

To actually install an update bundle on your target hardware, RAUC provides the
``install`` command:

.. code-block:: console

  # rauc install <bundle>

The ``<bundle>`` argument can be a local path, a local file URI, or a remote
(HTTP/HTTPS) URL.

Alternatively you can trigger a bundle installation `using the D-Bus API`_.

.. note:: Installing a bundle requires RAUC to be integrated in your system.
   Refer to the :ref:`sec-integration` chapter for more.

Accessing the System Status
---------------------------

For debugging purposes and for scripting it is helpful to gain an overview of
the current system as RAUC sees it.
The ``status`` command allows this:

.. code-block:: console

  # rauc status [--detailed] [--output-format=<format>]

You can choose the output ``<format>`` depending on your needs.
By default (or with ``readable``), it will print a human readable representation
of your system's most important properties.
Alternatively, with ``shell`` you can obtain a shell-parsable description,
or with ``json`` or ``json-pretty`` a JSON representation of the system status.
If more information is needed such as the slots' :ref:`status <slot-status>` add
the command line option ``--detailed``.

.. _sec-run-links:

Symbolic Links in ``/run/rauc``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Especially for use by other programs and services, RAUC creates symbolic links
in ``/run/rauc`` during service startup.

For example, on a system with A/B rootfs slots and corresponding appfs slots,
``/run/rauc/slots/active/appfs`` would point to the appfs slot that corresponds
to the booted rootfs.
This could be used to mount the correct appfs without replicating the status
determination already implemented in RAUC.

For each artifact repository, a link at ``/run/rauc/artifacts/<repository-name>``
points to the correct directory.
That way, installed artifacts can be found by following
``/run/rauc/artifacts/<repository-name>/<artifact-name>``.

React to a Successfully Booted System/Failed Boot
-------------------------------------------------

Normally, the full system update chain is not complete before being sure that
the newly installed system runs without any errors.
As the definition and detection of a `successful` operation is really
system-dependent, RAUC provides commands to preserve a slot as being the
preferred one to boot or to discard a slot from being bootable.

.. code-block:: console

  # rauc status mark-good

After verifying that the currently booted system is fully operational, one
wants to signal this information to the underlying bootloader implementation
which then, for example, resets a boot attempt counter.

.. code-block:: console

  # rauc status mark-bad

If the current boot failed in some kind, this command can be used to communicate
that to the underlying bootloader implementation. In most cases this will
disable the currently booted slot or at least switch to a different one.

Although not very useful in the field, both commands recognize an optional
argument to explicitly identify the slot to act on:

.. code-block:: console

  # rauc status mark-{good,bad} [booted | other | <SLOT_NAME>]

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

.. code-block:: console

  # rauc status mark-active [booted | other | <SLOT_NAME>]

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

In general, there exist three major types of customization:

* configuration parameters (in the rootfs' ``rauc/system.conf`` file)
* handlers (executables in rootfs)
* hooks (executables in bundle)

The first type, configuration parameters, allow controlling parameters of the
update in a predefined way.

The second type, using `handlers`, allows extending or replacing the
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


In the following, configuration parameters, handlers and hooks will be
explained in more detail.

System Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Beside providing the basic slot layout, RAUC's system configuration file
(``system.conf``) also allows you to configure parts of its runtime behavior,
such as handlers (see below), paths, etc.
For a detailed list of possible configuration options,
see :ref:`sec_ref_slot_config` section in the :ref:`sec_ref` chapter.

System-Based Customization: Handlers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handlers are executables located in the target's *root file system* that allow
extending the installation process on system side.
They must be specified in the targets :ref:`sec_ref_slot_config`.

For a detailed list of all environment variables exported for the handler
scripts, see the :ref:`sec-handler-interface` section.

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

.. _sec-post-install-handler:

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

The handler script can return variables by echoing ``<VARIABLE-NAME>=<value>``
to stdout, like ``RAUC_SYSTEM_SERIAL`` or ``RAUC_SYSTEM_VARIANT``.

.. _sec-hooks:

Bundle-Based Customization: Hooks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike handlers, hooks are defined in the update bundle and must be
specified in the bundle's :ref:`sec_ref_manifest` file.
All hooks are handled by a common executable that must be included in the
bundle.
Hooks allow the author of a bundle to add or replace functionality for the
installation of a specific bundle.
This can be useful for performing additional migration steps, checking for
specific previously installed bundle versions or for manually handling updates
of images RAUC cannot handle natively.

To reduce the complexity and number of files in a bundle, all hooks must be
handled by a single executable that is registered in the bundle's manifest:

.. code-block:: cfg

  [hooks]
  filename=hook

The ``filename`` must match the name of the script or binary executable placed
inside the content folder the bundle is generated from.

The actual hook invocations must be registered in the respective ``[image.*]``
or ``[hooks]`` manifest sections via ``hooks=<hook-names>`` settings where
``<hook-names>`` is a ``;``-separated list of hooks to invoke.

For each invoked hook, the common hook executable will be called with a
specific argument indicating the name of the invoked hook.
The executable is responsible for multiplexing the different hook calls.

In the following the available hooks are listed. Depending on their purpose,
some are image-specific, i.e. they will be executed for the installation of a
specific image only, while some other are global.

.. _sec-install-hooks:

Install Hooks
^^^^^^^^^^^^^

Install hooks operate globally on the bundle installation.

For a detailed list of all environment variables exported for the hooks
executable, see the :ref:`sec-install-hook-interface` section.

For install hooks, the hook call argument is just the hook name itself (e.g.
``install-check``).

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

For a detailed list of all environment variables exported for the hooks
executable, see the :ref:`sec-slot-hook-interface` section.

.. rubric:: Pre-Install Hook

The pre-install hook will be called right before the update procedure for the
respective slot will be started.
For target slot types that represent a mountable file system, the hook will be
executed with the target slots' file system mounted.
Note that a broken or unformatted target slot will currently cause the
installation to be aborted with an error.

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
hook enabled, pre- and post-install hooks will *not* be executed and having
an image (i.e. ``filename`` set) is optional, too!
The install hook allows to fully customize the way a slot is updated. This
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

or, without ``filename``:

.. code-block:: cfg

  [hooks]
  filename=hook

  [image.datafs]
  hooks=install


Bundle-Based Customization: Handlers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _full-custom-update:

Full Custom Update
^^^^^^^^^^^^^^^^^^

For some special tasks (recovery, testing, migration), it might be required to
completely replace the default RAUC update mechanism and to only use its
infrastructure and the signature verification for executing an application or a
script on the target side.

For this case, RAUC allows to define a **full custom handler** in a bundle's
manifest that will be executed instead of the built-in slot update handling:

.. code-block:: cfg

   [update]
   compatible=Test Platform

   [handler]
   filename=custom-handler.sh

The handler script/binary must be part of the bundle.

Refer manifest :ref:`[handler] <sec-manifest-handler>` section description
for details about how the full custom handler can be configured and gets
called.


.. _pre-post-install-handlers:

Pre/Post-Install Handlers
^^^^^^^^^^^^^^^^^^^^^^^^^

In addition to system-based handlers defined in the system configuration file (``system.conf``),
RAUC supports pre-install and post-install handlers defined per bundle. 
These handlers are specified in the bundle's :ref:`sec_ref_manifest` file and
allow update-specific actions to be executed before or after all slots are updated.

This feature enables the author of a bundle to define custom actions that are executed
in the context of the new system, rather than relying on the old system's configuration.
This is useful for scenarios where update logic or migration steps need to be bundled
with the update itself, and not predetermined by the old system.

To use this feature, add the following fields to your bundle manifest:

.. code-block:: cfg

  [handler]
  pre-install=preinstall-handler.sh
  post-install=postinstall-handler.sh

The values must match the names of the scripts or executables placed inside the content
folder from which the bundle is generated.

The pre-install handler will be executed after pre-install handlers defined in
the system configuration file. The post-install handler will be executed before post-install
handlers defined in the system configuration file.

This allows you to, for example, copy files between slots, perform custom checks, or
execute migration scripts as part of the update process, without modifying the old
system's configuration.


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

The ``InstallBundle`` method call triggers the installation of a given bundle in the
background and returns immediately.
Upon completion of the installation RAUC emits the ``Completed`` signal,
indicating either successful or failed installation.
For details on triggering the installation process, see the
:ref:`gdbus-method-de-pengutronix-rauc-Installer.InstallBundle` chapter in the
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

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer InstallBundle sa{sv} "<bundle-path>/<bundle-url>" 0

Mark a slot as good:

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Mark ss "good" "rootfs.0"

Mark a slot as active:

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Mark ss "active" "rootfs.0"

Get the `Operation` property containing the current operation:

.. code-block:: console

  $ busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer Operation

Get the `Progress` property containing the progress information:

.. code-block:: console

  $ busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer Progress

Get the `LastError` property, which contains the last error that occurred
during an installation.

.. code-block:: console

  $ busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer LastError

Get the status of all slots

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer GetSlotStatus

Get the current primary slot

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer GetPrimary

Monitor the D-Bus interface

.. code-block:: console

  $ busctl monitor de.pengutronix.rauc

Obtain bundle information

.. code-block:: console

  $ busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer InspectBundle sa{sv} "<bundle-path>/<bundle-url>" 0

.. _debugging:

Debugging RAUC
--------------

When RAUC fails to start on your target during integration or later during
installation of new bundles it can have a variety of causes.

This section will lead you through the most common options you have for
debugging what actually went wrong.

In each case it is quite essential to know that RAUC, if not compiled with
``-Dservice=false`` runs as a service on your target that is either
controlled by your custom application or by the RAUC command line interface.

The frontend will always only show the 'high level' error output, e.g. when an
installation failed:

.. code-block:: console

  rauc-Message: 08:27:12.083: installing /home/enrico/Code/rauc/good-bundle-hook.raucb: LastError: Failed mounting bundle: failed to run mount: Child process exited with code 1
  rauc-Message: 08:27:12.083: installing /home/enrico/Code/rauc/good-bundle-hook.raucb: idle
  Installing `/home/enrico/Code/rauc/good-bundle-hook.raucb` failed

In simple cases this might be sufficient for identifying the actual problem, in
more complicated cases this may give a rough hint.
For a more detailed look on what went wrong you need to inspect the rauc
service log instead.

If you run RAUC using systemd, the log can be obtained using

.. code-block:: console

  $ journalctl -u rauc

When using SysVInit, your service script needs to configure logging itself.
A common way is to dump the log, e.g. to ``/var/log/rauc``.

It may also be worth starting the RAUC service via command line on a second
shell to have a live view of what is going on when you invoke e.g. ``rauc
install`` on the first shell.

Inspecting Bundle Contents
~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes during development, it is useful to check whether the bundle contents
are as expected.
While RAUC bundles could just be mounted as a squashfs, using ``rauc mount``
also uses the same checks and mechanisms as ``rauc install``
(device-mapper/loopback & network support).
The bundle is mounted below the configured mount prefix (``/mnt/rauc/bundle`` by
default).
When you are done, just use ``umount <mount point>`` to unmount the bundle.

.. code-block:: console

  $ rauc mount /var/tmp/test/good-verity-bundle.raucb
  rauc-Message: 12:37:36.869: Reading bundle: /var/tmp/test/good-verity-bundle.raucb
  rauc-Message: 12:37:36.889: Verifying bundle signature...
  rauc-Message: 12:37:36.894: Verified inline signature by 'O = Test Org, CN = Test Org Release-1'
  rauc-Message: 12:37:36.896: Mounting bundle '/var/tmp/test/good-verity-bundle.raucb' to '/mnt/rauc/bundle'
  rauc-Message: 12:37:36.931: Configured loop device '/dev/loop0' for 24576 bytes
  rauc-Message: 12:37:36.934: Configured dm-verity device '/dev/dm-0'
  Mounted bundle at /mnt/rauc/bundle. Use 'umount /mnt/rauc/bundle' to unmount.
  $ ls -l /mnt/rauc/bundle
  total 21
  -rw-r--r-- 1 root root 8192 Jun 21 14:51 appfs.img
  -rwxr-xr-x 1 root root 2241 Sep 15  2017 custom_handler.sh
  -rwxr-xr-x 1 root root 1421 Aug 31  2017 hook.sh
  -rw-r--r-- 1 root root  308 Jun 21 14:51 manifest.raucm
  -rw-r--r-- 1 root root 8192 Jun 21 14:51 rootfs.img
  $ umount /mnt/rauc/bundle

.. note::
  This command is only intended for use during development.

Increasing Debug Verbosity
~~~~~~~~~~~~~~~~~~~~~~~~~~

Both for the service and the command line interface it is often useful to
increase the log level for narrowing down the actual error cause or gaining
more information about the circumstances when the error occurs.

RAUC uses glib and the
`glib logging framework <https://docs.gtk.org/glib/logging.html>`_ with the basic log domain 'rauc'.

For simple cases, you can activate logging by passing the ``-d`` or ``--debug`` option to either the CLI:

.. code-block:: console

  # rauc install -d bundle.raucb ..

or the service (you might need to modify your systemd or SysVInit
service file).

.. code-block:: console

  # rauc service -d

For more fine grained and advanced debugging options, use the
``G_MESSAGES_DEBUG`` environment variable.
This allows enabling different log domains. Currently available are:

:all: enable all log domains

:rauc: enable default RAUC log domain (same as calling with ``-d``)

:rauc-signature: enable logging of signature details

  This will dump the full CMS structure during verification and can help
  identify problems with the signature details.

:rauc-subprocess: enable logging of subprocess calls

  This will dump the entire program call invoked by RAUC and can help tracing
  down or reproducing issues caused by other programs invoked.

Example invocation:

.. code-block:: console

  # G_MESSAGES_DEBUG="rauc rauc-subprocess" rauc service

Enabling Verbose CURL Output
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you suspect an issue is related to network access (using the CURL library),
you can set ``RAUC_CURL_VERBOSE=1``.
This will cause RAUC to enable `CURLOPT_VERBOSE
<https://curl.se/libcurl/c/CURLOPT_VERBOSE.html>`_ when configuring a CURL
context.

Reproducing Issues using QEMU Test Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The RAUC source code repository provides a :ref:`qemu-test
<sec-contributing-qemu-test>` script, mainly meant to be used for running the
unit tests in a safe environment.
It can also be used to reproduce issues and debug basic functionality of RAUC.

When running:

.. code-block:: console

  $ ./qemu-test system

you will boot into a QEMU shell that has a mocked RAUC setup allowing you to
inspect status, install procedure, etc.
For example:

.. code-block:: console

  root@qemu-test:/home/user/git/rauc# rauc status
  === System Info ===
  Compatible:  Test Config
  Variant:
  Booted from: rootfs.0 (A)

  === Bootloader ===
  Activated: rootfs.0 (A)

  === Slot States ===
  x [rootfs.0] (/dev/root, raw, booted)
          bootname: A
          mounted: /
          boot status: good
      [appfs.0] (/dev/null, raw, active)

  o [rootfs.1] (/tmp/rootdev, raw, inactive)
          bootname: B
          boot status: good
      [appfs.1] (/tmp/appdev, raw, inactive)

