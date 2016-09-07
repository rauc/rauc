Using Rauc
==========

For using rauc in your embedded project, you will need to build at least two
instances of it.

* One for your host (development) system, where you create new updates.
* One that will run on the target for performing updates.


Creating bundles
----------------

To create an update bundle on your build host, rauc provides the `bundle`
command::

  rauc bundle --cert=<certfile> --key=<keyfile> <input-dir> <output-file>

Where `<input-dir>` must be a directory containing all images and scripts the
bundle should contain, as well as a Manifest file that describes the content of
the bundle in a way the rauc updater on the target can handle them and knows
which image to install to which slot, which scripts to execute, etc.

Resigning bundles
------------------

Rauc allows to resign a bundle from your build host, e.g. for making a testing
bundle a productive bundle that should have a key that is accepted by
non-debugging platforms.

.. code-block:: sh

  rauc resign --cert=<certfile> --key=<keyfile> <input-file> <output-file>

Obtaining bundle information
----------------------------

.. code-block:: sh

  rauc info [--output-format=<format>] <input-file>

You can control the output type of rauc info depending on your needs. By
default it will print a human readable representation of the bundle.
Alternatively you can obtain a shell-parsable description, or a json
representation of the bundle content.

Installing bundles
------------------

To install an update bundle on your target hardware, rauc provides the
`install` command:

.. code-block:: sh

  rauc install <input-file>

Alternatively you can trigger a bundle installation via dbus.

See system status
-----------------

For debugging purposes and for scripts maybe it can be helpful to gain an
overview over the current system as rauc sees it. The `status` command allows
this:

.. code-block:: sh

  rauc status [--output-format=<format>]

You can choose the output style of rauc status depending on your needs. By
default it will print a human readable representation of your system.
Alternatively you can obtain a shell-parsable description, or a JSON
representation of the system status.

Customizing the Update
----------------------

rauc provides several ways to customize the update process. Some allow to add
and extend details more fine-grained, some allow to replace major parts of the
default behavior of rauc.

In general, there exist three major types of customization: configuration,
handlers, and hooks.

The first is configuration through pre-defined variables. This allows to
control the update on a predefined way.

The second type is using `handlers`. Handlers allow to extend or replace
installation process. They are scripts located in the root filesystem and
configured in the system's configuration file. They control static behavior of
the system that should remain the same over all future updates.

The last type are `hooks`. They are much like `handlers`, except that they are
contained in the update bundle. Thus they allow to flexibly extend or customize
a single (or multiple) updates by some special behavior.
A common example would be using a per-slot post-install hook that handles
configuration migration for a new system version. Hooks are especially useful
to handle details of installing an update which were not considered in the
previously deployed version.

In the following, handlers and hooks will be explained in more detail.

System-based Customization: Handlers
------------------------------------

* system.conf
* multiple scripts?

For a detailed list of all environment variables exported for the handler
scripts, see ...

Pre-install Handler
~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  pre-install=/usr/lib/rauc/pre-install.sh

Rauc will call the pre-install handler (if given) during the bundle
installation process, right before calling the default or custom installation
process. At this stage, the bundle is mounted and its content accessible, the
target group was determined successfully.

If calling the handler fails or the handler returns a non-zero exit code, rauc
will abort installation with an error.

Install Handler
~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  install=/usr/lib/rauc/install.sh

The install handler is the most powerful one rauc provides. If you provide
this, you replace the entire default update procedure of rauc. It will be
executed right after the pre-install handler and right before the post-install
handler.

If calling the handler fails or the handler returns a non-zero exit code, rauc
will abort installation with an error.

Post-install Handler
~~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  post-install=/usr/lib/rauc/post-install.sh

The post install handler will be called right after rauc successfully performed
a system update. If any error occurred during installation, the post-install
handler will not be called.

Note that a failed call of the post-install handler or a non-zero exit code
will cause a notification about the error but will not change the result of the
performed update anymore.

A possible usage for the post-install handler could be to trigger an automatic
restart of the system.

System-info Handler
~~~~~~~~~~~~~~~~~~~

.. code-block:: cfg

  [handlers]
  system-info=/usr/lib/rauc/system-info.sh

The system-info handler is called after loading the configuration file. This
way it can collect additional variables from the system, like the system's
serial number.

The handler script must return a system serial number by echoing
`RAUC_SYSTEM_SERIAL=<value>` to standard out.


Bundle-based Customization: Hooks
---------------------------------

Unlike handlers, hooks allow the author of a bundle to add or replace
functionality for the installation of a specific bundle. This can be useful for
performing additional migration steps, checking for specific previously
installed bundle versions, or for manually handling updates of images rauc
cannot handle natively.

To reduce the complexity and number of files in a bundle, all hooks must be
handled by a single script that is registered in the bundles manifest:

.. code-block:: cfg

  [hooks]
  filename=hook.sh

Each hook must be activated explicitly and leads to a call of the hook script
with a specific argument that allows to distinguish between the different hook
types. Multiple hooks must be separated with a ``;``.

In the following the available hooks are listed. Depending on their purpose,
some are image-specific, i.e. they will be executed for the currently installed
image only, while some other are global.

Install Hooks
~~~~~~~~~~~~~

Install hooks operate globally on the bundle installation.

The following environment variables will be passed to the executed hook script.

.. glossary::

  ``RAUC_SYSTEM_COMPATIBLE``
    The compatible value set in the system configuration file
  ``RAUC_MF_COMPATIBLE``
    The compatible value provided by the current bundle
  ``RAUC_MF_VERSION``
    The value of the version field as provided by the current bundle
  ``RAUC_MOUNT_PREFIX``
    The global rauc mount prefix path

Install-check Hook
^^^^^^^^^^^^^^^^^^

.. code-block:: cfg

  [hooks]
  filename=hook.sh
  hooks=install-check

This hook will be executed instead of the normal compatible check in order to
allow performing a custom compatibility check based on compatible and/or version
information.

To indicate that a bundle should be rejected, the script must return with an
exit code >= 10.

If available, Rauc will use that last string printed to standard error by
the hook script as the rejection reason message and provide it to the user.

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

Slot hooks
~~~~~~~~~~

Slot hooks are called for each slot an image will be installed to. In order to
enable them, you have to specify them in the ``hooks`` key under the respective
``image`` section.

Note that Hook slot operations will be passed to the script with the prefix
``slot-``. Thus if you intend to check for the pre-install hook, you have to
check for the argument to be ``slot-pre-install``.

The following environment variables will be passed to the executed hook script.

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
    The global rauc mount prefix path

Pre-Install Hook
^^^^^^^^^^^^^^^^

The pre-install hook will be called right before the update procedure for the
respective slot will be started. For slot types that represent a mountable file
system, the hook will be executed with having the file system mounted.

.. code-block:: cfg

  [hooks]
  filename=hook.sh

  [image.rootfs]
  filename=rootfs.img
  size=...
  sha256=...
  hooks=pre-install


Post-Install Hook
~~~~~~~~~~~~~~~~~

The post-install hook will be called right after the update procedure for the
respective slot was finished successfully. For slot types that represent a
mountable file system, the hook will be executed with having the file system
mounted. This allows to write some post-install information to the slot. It is
also useful to copy files from the currently active system to the newly
installed slot, for example to preserve application configuration data.

.. code-block:: cfg

  [hooks]
  filename=hook.sh

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
          *)
                  exit 1
                  ;;
  esac

  exit 0


Install Hook
~~~~~~~~~~~~

The install hook will replace the entire default installation process for the
target slot of the image it was specified for. Note that when having the install
hook enabled, pre- and post-install hooks will *not* be executed.
The install hook allows to fully customize the way an image is installed. This
allows performing special installation methods that are not natively supported
by rauc, for example to upgrade the bootloader to a new version while also
migrating configuration settings.

.. code-block:: cfg

  [hooks]
  filename=hook.sh

  [image.rootfs]
  filename=rootfs.img
  size=...
  sha256=...
  hooks=install
