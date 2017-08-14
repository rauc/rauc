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

  rauc bundle --cert=<certfile> --key=<keyfile> <input-dir> <output-file>

Where ``<input-dir>`` must be a directory containing all images and scripts the
bundle should include, as well as a manifest file ``manifest.raucm`` that
describes the content of the bundle for the RAUC updater on the target:
which image to install to which slot, which scripts to execute etc.
``<output-file>`` must be the path of the bundle file to create. Note that RAUC
bundles must always have a ``.raucb`` file name suffix in order to ensure that
RAUC treats them as bundles.

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

Alternatively you can trigger a bundle installation via D-Bus.

Viewing the System Status
-------------------------

For debugging purposes and for scripting it is helpful to gain an overview of
the current system as RAUC sees it.
The ``status`` command allows this:

.. code-block:: sh

  rauc status [--output-format=<format>]

You can choose the output style of RAUC status depending on your needs.
By default it will print a human readable representation of your system.
Alternatively you can obtain a shell-parsable description, or a JSON
representation of the system status.

Resigning Bundles
-----------------

.. note:: This feature is not fully implemented yet

RAUC allows to resign a bundle from your build host, e.g. for making a testing
bundle a release bundle that should have a key that is accepted by
non-debugging platforms:

.. code-block:: sh

  rauc resign --cert=<certfile> --key=<keyfile> <input-file> <output-file>

Reacting to a Successfully/Failed Boot
--------------------------------------

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

System-Based Customization: Handlers
------------------------------------

* system.conf
* multiple scripts?

For a detailed list of all environment variables exported to the handler
scripts, see  the :ref:`sec-handler-interface` section.

Pre-Install Handler
~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  pre-install=/usr/lib/rauc/pre-install

RAUC will call the pre-install handler (if given) during the bundle
installation process, right before calling the default or custom installation
process. At this stage, the bundle is mounted, its content is accessible and the
target group has been determined successfully.

If calling the handler fails or the handler returns a non-zero exit code, RAUC
will abort installation with an error.

Install Handler
~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  install=/usr/lib/rauc/install

The install handler is the most powerful one RAUC provides. If you use
this, you replace the entire default update procedure of RAUC. It will be
executed between the pre-install and post-install handlers.

If calling the handler fails or the handler returns a non-zero exit code, RAUC
will abort installation with an error.

Post-Install Handler
~~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  post-install=/usr/lib/rauc/post-install

The post install handler will be called right after RAUC successfully performed
a system update. If any error occurred during installation, the post-install
handler will not be called.

Note that a failed call of the post-install handler or a non-zero exit code
will cause a notification about the error but will not change the result of the
performed update anymore.

A possible usage for the post-install handler could be to trigger an automatic
restart of the system.

System-Info Handler
~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  system-info=/usr/lib/rauc/system-info

The system-info handler is called after loading the configuration file. This
way it can collect additional variables from the system, like the system's
serial number.

The handler script must return a system serial number by echoing
`RAUC_SYSTEM_SERIAL=<value>` to standard out.


Bundle-Based Customization: Hooks
---------------------------------

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

Install Hooks
~~~~~~~~~~~~~

Install hooks operate globally on the bundle installation.

The following environment variables will be passed to the hook executable:

.. glossary::

  ``RAUC_SYSTEM_COMPATIBLE``
    The compatible value set in the system configuration file

  ``RAUC_MF_COMPATIBLE``
    The compatible value provided by the current bundle

  ``RAUC_MF_VERSION``
    The value of the version field as provided by the current bundle

  ``RAUC_MOUNT_PREFIX``
    The global RAUC mount prefix path

Install-Check Hook
^^^^^^^^^^^^^^^^^^

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
                          echo "Comptaible does not match!" 1>&2
                          exit 10
                  fi
                  ;;
          *)
                  exit 1
                  ;;
  esac

  exit 0

Slot Hooks
~~~~~~~~~~

Slot hooks are called for each slot an image will be installed to. In order to
enable them, you have to specify them in the ``hooks`` key under the respective
``image`` section.

Note that hook slot operations will be passed to the executable with the prefix
``slot-``. Thus if you intend to check for the pre-install hook, you have to
check for the argument to be ``slot-pre-install``.

The following environment variables will be passed to the hook executable:

.. glossary::

  ``RAUC_SLOT_NAME``
    The name of the currently installed slot

  ``RAUC_SLOT_CLASS``
    The class of the currently installed slot

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

Pre-Install Hook
^^^^^^^^^^^^^^^^

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


Post-Install Hook
^^^^^^^^^^^^^^^^^

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


Install Hook
^^^^^^^^^^^^

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

Using the D-Bus API
-------------------

Examples Using ``busctl`` Command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Triggering an installation:

.. code-block:: sh

  busctl call de.pengutronix.rauc / de.pengutronix.rauc.Installer Install s "/path/to/bundle"

Get the `operation` property containing the current operation:

.. code-block:: sh

  busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer Operation

Get the `lasterror` property, which contains the last error that occured during
an installation.

.. code-block:: sh

  busctl get-property de.pengutronix.rauc / de.pengutronix.rauc.Installer LastError

Monitor the D-Bus interface

.. code-block:: sh

  busctl monitor de.pengutronix.rauc
