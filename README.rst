.. image:: rauc_logo_small.png
   :alt: RAUC logo
   :align: center

RAUC - Robust Auto-Update Controller
====================================

|LGPLv2.1| |CI_branch| |Codecov_branch| |Coverity| |codeql| |Documentation| |Matrix| |CII Best Practices|

RAUC controls the update process on embedded Linux systems. It is both a target
application that runs as an update client and a host/target tool
that allows you to create, inspect and modify installation artifacts.

Source Code: https://github.com/rauc/rauc

Documentation: https://rauc.readthedocs.org/

Chat: IRC channel ``#rauc`` on libera.chat (bridged to the
`Matrix channel #rauc:matrix.org <https://matrix.to/#/#rauc:matrix.org>`_)

Features
--------

* **Fail-Safe & Atomic**:

  * An update may be interrupted at any point without breaking the running
    system.
  * Update compatibility check
  * Atomic bootloader updates (eMMC boot partitions, MBR, GPT)
* **Cryptographic signing and verification** of updates using OpenSSL (signatures
  based on x.509 certificates)

  * Keys and certificates on **PKCS#11 tokens** (HSMs) are supported
* **Flexible and customizable** redundancy/storage setup

  * **Symmetric** setup (Root-FS A & B)
  * **Asymmetric** setup (recovery & normal)
  * Application partition, data partitions, ...
  * Allows **grouping** of multiple slots (rootfs, appfs) as update targets
* Built-in network streaming mode
* Network delta-streaming mode (using **casync**)

  * chunk-based binary delta updates
  * significantly reduce download size
  * no extra storage required
* Bundle **encryption** for multiple recipients
* **Bootloader support**:

  * `grub <https://www.gnu.org/software/grub/>`_
  * `barebox <http://barebox.org/>`_
  * `u-boot <http://www.denx.de/wiki/U-Boot>`_
  * `EFI <https://de.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface>`_
  * Custom implementation
* Storage support:

  * read-only filesystems: SquashFS, EROFS, dm-verity protected images, ...
  * read-write filesystems: ext4, VFAT, UBIFS, JFFS2
  * eMMC boot partitions (atomic update)
  * UBI volumes
  * raw NAND flash (using nandwrite)
  * raw NOR flash (using flashcp)
  * MBR partition table
  * GPT partition table
* Independent from update source

  * **USB Stick**
  * Software provisioning server (e.g. **hawkBit**)
* Controllable via **D-Bus** interface
* Supports data migration
* Network protocol support using libcurl (https, http, ftp, ssh, ...)
* Several layers of update customization

  * Update-specific extensions (hooks)
  * System-specific extensions (handlers)
  * fully custom update script

Host Features
~~~~~~~~~~~~~

*  Create update bundles
*  Sign/resign bundles
*  Inspect bundle files

Target Features
~~~~~~~~~~~~~~~

*  Run as a system service (D-Bus interface)
*  Install bundles
*  View system status information
*  Change status of symmetric/asymmetric/custom slots

Target Requirements
-------------------

* Boot state storage

  * GRUB: environment file on SD/eMMC/SSD/disk
  * Barebox: State partition on EEPROM/FRAM/MRAM or NAND flash
  * U-Boot: environment variable
  * EFI: EFI variables
  * Custom: depends on implementation
* Boot target selection support in the bootloader
* Enough mass storage for two symmetric/asymmetric/custom slots
* For normal bundle mode:

  * Enough storage for the compressed bundle file (in memory, in a temporary
    partition or on an external storage device)
* For casync bundle mode:

  * No additional storage needed
  * Network interface
* Hardware watchdog (optional, but recommended)
* RTC (optional, but recommended)

Usage
-----

Please see the `documentation <https://rauc.readthedocs.org/>`__ for
details.

Prerequisites
-------------

Host (Build) Prerequisites
~~~~~~~~~~~~~~~~~~~~~~~~~~

-  build-essential
-  meson (or automake)
-  libtool
-  libdbus-1-dev
-  libglib2.0-dev
-  libcurl3-dev
-  libssl-dev

::

   sudo apt-get install build-essential meson automake libtool libdbus-1-dev libglib2.0-dev libcurl3-dev libssl-dev

For HTTP(S) streaming support, you also need netlink protocol headers:

::

    sudo apt-get install libnl-genl-3-dev

If you intend to use json-support you also need

::

    sudo apt-get install libjson-glib-dev

Target Prerequisites
~~~~~~~~~~~~~~~~~~~~

Required kernel options (either ``y`` or ``m``):

-  ``CONFIG_MD``
-  ``CONFIG_BLK_DEV_DM``
-  ``CONFIG_BLK_DEV_LOOP``
-  ``CONFIG_DM_VERITY``
-  ``CONFIG_SQUASHFS``
-  ``CONFIG_CRYPTO_SHA256``
-  ``CONFIG_BLK_DEV_NBD`` (for streaming support)
-  ``CONFIG_DM_CRYPT`` (for encryption support)

For using tar archive in RAUC bundles with Busybox tar, you have to enable the
following Busybox feature:

-  ``CONFIG_FEATURE_TAR_AUTODETECT=y``
-  ``CONFIG_FEATURE_TAR_LONG_OPTIONS=y``

Depending on the actual storage type and/or filesystem used, further target
tools might be required.
The documentation chapter
`Required Target Tools <http://rauc.readthedocs.io/en/latest/integration.html#required-target-tools>`_
gives a more detailed list on these.

Building from Sources
---------------------

.. note:: RAUC is intended to be built both as a host tool as well as a target
   tool (service). Therefore it is fully prepared for cross-compilation with meson.

::

    git clone https://github.com/rauc/rauc
    cd rauc
    meson setup build
    ninja -C build

.. note:: At the moment, also `automake cross-compilation
   <https://www.gnu.org/software/automake/manual/html_node/Cross_002dCompilation.html>`_
   is still supported, but the plan is to deprecate this soon.

   ::

       git clone https://github.com/rauc/rauc
       cd rauc
       ./autogen.sh
       ./configure
       make

Manual Installation
-------------------

.. note:: To prepare RAUC for the target device, it is highly recommended to
  use an embedded Linux distribution build suite such as Yocto/OE, PTXdist or
  Buildroot.

On the host system RAUC can be used directly from the build dir, or optionally
be installed. On the target instead, installing is highly recommended as it
also unpacks service and D-Bus configuration files required to run RAUC
properly::

    make install

Running the Test Suite
----------------------

::

    sudo apt-get install qemu-system-x86 time squashfs-tools
    # Optional to run all tests:
    # sudo apt-get install faketime casync grub-common openssl softhsm2 opensc opensc-pkcs11 libengine-pkcs11-openssl mtd-utils
    ./qemu-test

Creating a Bundle (Host)
------------------------

Create a directory with the content that should be installed::

    mkdir content-dir/
    cp $SOURCE/rootfs.ext4 content-dir/

Create a manifest describing which image to install where together with some
meta info::

    cat >> content-dir/manifest.raucm << EOF
    [update]
    compatible=FooCorp Super BarBazzer
    version=2019.01-1
    [image.rootfs]
    filename=rootfs.ext4
    EOF

Let RAUC create a bundle from this::

    rauc --cert autobuilder.cert.pem --key autobuilder.key.pem bundle content-dir/ update-2019.01-1.raucb

Starting the RAUC Service (Target)
----------------------------------

Create a system configuration file in ``/etc/rauc/system.conf`` and start the
service process in background::

    rauc service &

Installing a Bundle (Target)
----------------------------

To install the bundle on your target device, run::

    rauc install update-2019.01-1.raucb

Contributing
------------

Fork the repository and send us a pull request.

Please read the Documentation's
`Contributing <http://rauc.readthedocs.io/en/latest/contributing.html>`_
section for more details.

.. |LGPLv2.1| image:: https://img.shields.io/badge/license-LGPLv2.1-blue.svg
   :target: https://raw.githubusercontent.com/rauc/rauc/master/COPYING
.. |CI_branch| image:: https://github.com/rauc/rauc/workflows/tests/badge.svg
   :target: https://github.com/rauc/rauc/actions?query=workflow%3Atests
.. |Codecov_branch| image:: https://codecov.io/gh/rauc/rauc/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/rauc/rauc
.. |Coverity| image:: https://scan.coverity.com/projects/22299/badge.svg
   :target: https://scan.coverity.com/projects/22299
.. |Documentation| image:: https://readthedocs.org/projects/rauc/badge/?version=latest
   :target: http://rauc.readthedocs.org/en/latest/?badge=latest
.. |Matrix| image:: https://img.shields.io/matrix/rauc:matrix.org?label=matrix%20chat
   :target: https://matrix.to/#/#rauc:matrix.org
.. |codeql| image:: https://github.com/rauc/rauc/workflows/CodeQL/badge.svg
   :target: https://github.com/rauc/rauc/actions/workflows/codeql.yml
.. |CII Best Practices| image:: https://bestpractices.coreinfrastructure.org/projects/5075/badge
   :target: https://bestpractices.coreinfrastructure.org/projects/5075
