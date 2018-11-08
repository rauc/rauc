.. image:: rauc_logo_small.png
   :alt: RAUC logo
   :align: center

RAUC - Robust Auto-Update Controller
====================================


.. image:: https://img.shields.io/badge/license-LGPLv2.1-blue.svg
   :alt: LGPLv2.1
   :target: https://raw.githubusercontent.com/rauc/rauc/master/COPYING
.. image:: https://img.shields.io/travis/rauc/rauc/master.svg
   :alt: Travis branch
   :target: https://travis-ci.org/rauc/rauc
.. image:: https://codecov.io/gh/rauc/rauc/branch/master/graph/badge.svg
   :alt: Codecov.io branch
   :target: https://codecov.io/gh/rauc/rauc
.. image:: https://img.shields.io/coverity/scan/5085.svg
   :alt: Coverity
   :target: https://scan.coverity.com/projects/5085
.. image:: https://readthedocs.org/projects/rauc/badge/?version=latest
   :alt: Documentation
   :target: http://rauc.readthedocs.org/en/latest/?badge=latest
.. image:: https://matrix.to/img/matrix-badge.svg
   :alt: Chat
   :target: https://riot.im/app/#/room/#rauc:matrix.org

RAUC controls the update process on embedded linux systems. It is both a target
application that runs as an update client and a host/target tool
that allows you to create, inspect and modify installation artifacts.

Source Code: https://github.com/rauc/rauc

Documentation: https://rauc.readthedocs.org/

Chat: IRC channel ``#rauc`` on freenode (bridged to the
`Matrix channel #rauc:matrix.org <https://riot.im/app/#/room/#rauc:matrix.org>`_)

Features
--------

* **Fail-Safe & Atomic**:

  * An update may be interrupted at any point without breaking the running
    system.
  * Update compatibility check
* **Cryptographic signing and verification** of updates using OpenSSL (signatures
  based on x.509 certificates)

  * Keys and certificates on **PKCS#11 tokens** (HSMs) are supported
* **Flexible and customizable** redundancy/storage setup

  * **Symmetric** setup (Root-FS A & B)
  * **Asymmetric** setup (recovery & normal)
  * Application partition, Data Partitions, ...
  * Allows **grouping** of multiple slots (rootfs, appfs) as update targets
* Two update modes:

  * Bundle: single file containing the whole update
  * Network: separate manifest and component files
* **Bootloader support**:

  * `grub <https://www.gnu.org/software/grub/>`_
  * `barebox <http://barebox.org/>`_
  * `u-boot <http://www.denx.de/wiki/U-Boot>`_
  * `EFI <https://de.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface>`_
* Storage support:

  * ext2/3/4 filesystem
  * eMMC boot partitions (atomic update)
  * vfat filesystem
  * UBI volumes
  * UBIFS
  * raw NAND (using nandwrite)
  * squashfs
* Independent from updates source

  * **USB Stick**
  * Software provisioning server (e.g. **Hawkbit**)
* Controllable via **D-Bus** interface
* Supports Data migration
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

*  Run as a system service (d-bus interface)
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
* Boot target selection support in the bootloader
* Enough mass storage for two symmetric/asymmetric/custom slots
* For bundle mode:

  * Enough storage for the compressed bundle file (in memory, in a temporary
    partition or on an external storage device)
* For network mode:

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

-  automake
-  libtool
-  libglib2.0-dev
-  libcurl3-dev
-  libssl-dev

::

   sudo apt-get install automake libtool libglib2.0-dev libcurl3-dev libssl-dev

If you intend to use json-support you also need

::

    sudo apt-get install libjson-glib-dev

Target Prerequisites
~~~~~~~~~~~~~~~~~~~~

Required kernel options:

-  ``CONFIG_BLK_DEV_LOOP=y``
-  ``CONFIG_SQUASHFS=y``

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

::

    git clone https://github.com/rauc/rauc
    cd rauc
    ./autogen.sh
    ./configure
    make

Testing
-------

::

    sudo apt-get install user-mode-linux slirp
    make check
    ./uml-test

Creating a Bundle
-----------------

::

    mkdir content-dir/
    cp $SOURCE/rootfs.ext4.img content-dir/
    cat >> content-dir/manifest.raucm << EOF
    [update]
    compatible=FooCorp Super BarBazzer
    version=2015.04-1
    [image.rootfs]
    filename=rootfs.ext4.img
    EOF
    rauc --cert autobuilder.cert.pem --key autobuilder.key.pem bundle content-dir/ update-2015.04-1.raucb

Installing a Bundle
-------------------

::

    rauc install update-2015.04-1.raucb

Contributing
------------

Fork the repository and send us a pull request.

Please read the Documentation's
`Contributing <http://rauc.readthedocs.io/en/latest/contributing.html>`_
section for more details.

.. |LGPLv2.1| image:: https://img.shields.io/badge/license-LGPLv2.1-blue.svg
   :target: https://raw.githubusercontent.com/rauc/rauc/master/COPYING
.. |Travis branch| image:: https://img.shields.io/travis/rauc/rauc/master.svg
   :target: https://travis-ci.org/rauc/rauc
.. |Coveralls branch| image:: https://img.shields.io/coveralls/rauc/rauc/master.svg
   :target: https://coveralls.io/r/rauc/rauc
.. |Coverity| image:: https://img.shields.io/coverity/scan/5085.svg
   :target: https://scan.coverity.com/projects/5085
.. |Documentation| image:: https://readthedocs.org/projects/rauc/badge/?version=latest
   :target: http://rauc.readthedocs.org/en/latest/?badge=latest
