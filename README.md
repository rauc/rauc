# rauc - Robust Auto-Update Controller

[![LGPLv2.1](https://img.shields.io/badge/license-LGPLv2.1-blue.svg)](https://raw.githubusercontent.com/jluebbe/rauc/master/COPYING)
[![Travis branch](https://img.shields.io/travis/jluebbe/rauc/master.svg)](https://travis-ci.org/jluebbe/rauc)
[![Coveralls branch](https://img.shields.io/coveralls/jluebbe/rauc/master.svg)](https://coveralls.io/r/jluebbe/rauc)
[![Coverity](https://img.shields.io/coverity/scan/5085.svg)](https://scan.coverity.com/projects/5085)
[![Documentation](https://readthedocs.org/projects/rauc/badge/?version=latest)](http://rauc.readthedocs.org/en/latest/?badge=latest)

> rauc controls the update process on embedded linux systems

Source Code: https://github.com/jluebbe/rauc

Documentation: https://rauc.readthedocs.org/

## Features

* Supports whole-system updates using at least two redundant installations
  * Symmetric: Root-FS A & Root-FS B
  * Asymmetric: recovery & normal
  * Also supports custom partition layouts
* Fail-Safe: no change to the running system
* Two update modes:
  * Bundle: single file containing the whole update
  * Network: separate manifest and component files
* Bootloader support:
  * [grub](https://www.gnu.org/software/grub/)
  * [barebox](http://barebox.org/)
* Storage support:
  * raw (ext2/3/4, btrfs, squashfs, ...)
  * ubi (using [UBI volume update](http://www.linux-mtd.infradead.org/doc/ubi.html#L_volupdate))
* Network protocol support using libcurl (https, http, ftp, ssh, ...)
* Cryptographic verification using OpenSSL (signatures based on x.509
  certificates)

## Requirements

* Boot state storage
  * grub environment file on SD/eMMC/SSD/disk
  * State partition on EEPROM/FRAM/MRAM or NAND flash
  * ...
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

### Host features
* Create update bundles
* Sign/resign bundles
* Inspect bundle files

### Target Features
* Run as a system service (d-bus interface)
* Install bundles
* View system status information
* Change status of symmetric/asymmetric/custom slots

## Usage

Please see the [documentation](https://rauc.readthedocs.org/) for details.

### Building from sources

    git clone https://github.com/jluebbe/rauc
    cd rauc
    ./autogen.sh
    ./configure
    make

### Testing

    sudo apt-get install user-mode-linux slirp
    make check
    ./uml-test

### Creating a bundle

    mkdir content-dir/
    cp $SOURCE/rootfs.ext4.img content-dir/
    cat >> content-dir/manifest << EOF
    [update]
    compatible=FooCorp Super BarBazzer
    version=2015.04-1
    [image.rootfs]
    sha256=de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
    size=24117248
    filename=rootfs.ext4.img
    EOF
    rauc --cert autobuilder.cert.pem --key autobuilder.key.pem bundle content-dir/ update.raucb

### Installing a bundle

    rauc install update.raucb

## Contributing

Fork the repository and send us a pull request.
