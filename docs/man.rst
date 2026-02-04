Man Page
========

SYNOPSIS
--------

**rauc** [*OPTIONS*...] **bundle** *INPUTDIR* *BUNDLE*

**rauc** [*OPTIONS*...] **resign** *INBUNDLE* *OUTBUNDLE*

**rauc** [*OPTIONS*...] **extract** *BUNDLE* *OUTPUTDIR*

**rauc** [*OPTIONS*...] **extract-signature** *BUNDLE* *OUTPUTSIG*

**rauc** [*OPTIONS*...] **convert** *INBUNDLE* *OUTBUNDLE*

**rauc** [*OPTIONS*...] **encrypt** *INBUNDLE* *OUTBUNDLE*

**rauc** [*OPTIONS*...] **install** *BUNDLE*

**rauc** [*OPTIONS*...] **info** *BUNDLE*

**rauc** [*OPTIONS*...] **mount** *BUNDLE*

**rauc** [*OPTIONS*...] **status** [*SLOTNAME* \|
**mark-**\ {**good**,\ **bad**,\ **active**}
[**booted**\ \|\ **other**\ \|\ *SLOTNAME*]]

**rauc** [*OPTIONS*...] **write-slot** *SLOTNAME* *IMAGEFILE*

DESCRIPTION
-----------

RAUC is a lightweight update client that runs on an Embedded Linux
device and reliably controls the procedure of updating the device with a
new firmware.

RAUC is also the tool on the host system that is used to create, inspect
and modify update files ("bundles") for the device.

This manual page documents briefly the **rauc** command line utility.

It was written for the Debian GNU/Linux distribution to satisfy the
packaging requirements.
Thus it should only serve as a summary, reading the comprehensive online manual
(**https://rauc.readthedocs.io/**) is recommended.

OPTIONS
-------

The following general options can be used with most commands, however
not all combinations make sense.

**-c** *FILENAME*, **--conf=**\ *FILENAME*
   use the given config file instead of the one at the compiled-in
   default path

**-C** *SECTION:KEY=VALUE*, **--confopt=**\ *SECTION:KEY=VALUE*
   Override parameters from the config file with the specified
   configuration settings. If specified parameter is not present in the
   config file it will still be set by this option.

**--keyring=**\ *PEMFILE*
   use specific keyring file

**--mount=**\ *PATH*
   mount prefix (/mnt/rauc by default)

**-d**, **--debug**
   enable debug output

**--version**
   display version

**-h**, **--help**
   print usage

COMMANDS
--------

**bundle** *INPUTDIR* *BUNDLE*

   Create a bundle from a content directory.

   **Options:**

      **--cert=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given certificate file or the certificate referenced by the
         given PKCS#11 URL

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given private key file or the key referenced by the given
         PKCS#11 URL

      **--intermediate=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         intermediate CA file or the certificate referenced by the given
         PKCS#11 URL

      **--signing-keyring=**\ *PEMFILE*
         verification keyring file

      **--mksquashfs-args=**\ *ARGS*
         mksquashfs extra args

**resign** *INBUNDLE* *OUTBUNDLE*

   Resign an already signed bundle.

   **Options:**

      **--append**
         append instead of replace signature

      **--cert=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given certificate file or the certificate referenced by the
         given PKCS#11 URL

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given private key file or the key referenced by the given
         PKCS#11 URL

      **--intermediate=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         intermediate CA file or the certificate referenced by the given
         PKCS#11 URL

      **--no-verify**
         disable bundle verification

      **--no-check-time**
         don't check validity period of certificates against current
         time

      **--signing-keyring=**\ *PEMFILE*
         verification keyring file

**extract** *BUNDLE* *OUTPUTDIR*

   Extract the bundle content to a directory.

   **Options:**

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given decryption key file or the decryption key referenced
         by the given PKCS#11 URL

      **--trust-environment**
         trust environment and skip bundle access checks

**extract-signature** *BUNDLE* *OUTPUTSIG*

   Extract the bundle signature.

   **Options:**

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given decryption key file or the decryption key referenced
         by the given PKCS#11 URL

      **--trust-environment**
         trust environment and skip bundle access checks

**convert** *INBUNDLE* *OUTBUNDLE*

   Convert an existing bundle to casync index bundle and store.

   **Options:**

      **--cert=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given certificate file or the certificate referenced by the
         given PKCS#11 URL

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given private key file or the key referenced by the given
         PKCS#11 URL

      **--intermediate=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         intermediate CA file or the certificate referenced by the given
         PKCS#11 URL

      **--trust-environment**
         trust environment and skip bundle access checks

      **--no-verify**
         disable bundle verification

      **--signing-keyring=**\ *PEMFILE*
         verification keyring file

      **--mksquashfs-args=**\ *ARGS*
         mksquashfs extra args

      **--casync-args=**\ *ARGS*
         casync extra args

      **--ignore-image=**\ *SLOTCLASS*
         ignore image during conversion

**encrypt** *INBUNDLE* *OUTBUNDLE*

   Encrypt a crypt bundle.

   **Options:**

      **--to** *PEMFILE*
         recipient cert(s)

**install** *BUNDLE*

   Install a bundle.

   **Options:**

      **--ignore-compatible**
         disable compatible check

      **--ignore-version-limit=**
         disable version check

      **--transaction-id=**\ *UUID*
         custom transaction ID

      **--require-manifest-hash=**\ *HASH*
         require a specific manifest hash

      **--progress**
         show progress bar

      **--tls-cert=**\ *PEMFILE|PKCS11-URL*
         TLS client certificate file or PKCS#11 URL

      **--tls-key=**\ *PEMFILE|PKCS11-URL*
         TLS client key file or PKCS#11 URL

      **--tls-ca=**\ *PEMFILE*
         TLS CA file

      **--tls-no-verify**
         do not verify TLS server certificate

      **-H**, **--http-header**\ =\ *'HEADER: VALUE'*
         HTTP request header (multiple uses supported)

      **--handler-args=**\ *ARGS*
         extra arguments for full custom handler

      **--override-boot-slot=**\ *BOOTNAME*
         overrides auto-detection of booted slot

**info** *BUNDLE*

   Print bundle info.

   **Options:**

      **--no-verify**
         disable bundle verification

      **--no-check-time**
         don't check validity period of certificates against current
         time

      **--key=**\ *PEMFILE*\ \|\ *PKCS11-URL*
         use given decryption key file or the decryption key referenced
         by the given PKCS#11 URL

      **--output-format=**\ [**readable**\ \|\ **shell**\ \|\ **json**\ \|\ **json-pretty**\ \|\ **json-2**]
         select output format

      The json-2 output format matches the structure of the
      InspectBundle D-Bus API and should be used instead of **json** or
      **json-pretty**.

      **--dump-cert**
         dump certificate

      **--dump-recipients**
         dump recipients

**mount** *BUNDLE*

   Mount a bundle for development purposes to the bundle directory in
   RAUC's mount prefix. It must be unmounted manually by the user.

**status** [*SLOTNAME* \| **mark-**\ {**good**,\ **bad**,\ **active**}
[**booted**\ \|\ **other**\ \|\ *SLOTNAME*]]

   Without further subcommand, it simply shows the system status or
   status of a specific slot.

   The subcommands **mark-good** and **mark-bad** can be used to set the
   state of a slot explicitly. These subcommands usually operate on the
   currently booted slot if not specified per additional parameter.

   The subcommand **mark-active** allows one to manually switch to a
   different slot. Here too, the desired slot can be given per
   parameter, otherwise the currently booted one is used.

   **Options:**

      **--detailed**
         show more status details

      **--output-format=**\ [**readable**\ \|\ **shell**\ \|\ **json**\ \|\ **json-pretty**]
         select output format

      **--override-boot-slot=**\ *BOOTNAME*
         overrides auto-detection of booted slot

**write-slot** *SLOTNAME* *IMAGEFILE*

   Manually write image to slot (using slot update handler). This
   bypasses all other update logic and is for development or special use
   only!

   **Options:**

      **--image-type**
         Select explicit image type to use.

ENVIRONMENT
-----------

**RAUC_KEY_PASSPHRASE**
   Passphrase to use for accessing key files (signing only)

**RAUC_PKCS11_MODULE**
   Library filename for PKCS#11 module (signing only)

**RAUC_PKCS11_PIN**
   PIN to use for accessing PKCS#11 keys (signing only)

FILES
-----

**/etc/rauc/system.conf, /run/rauc/system.conf, /usr/lib/rauc/system.conf**

The system configuration file is the central configuration in RAUC
that abstracts the loosely coupled storage setup, partitioning and
boot strategy of your board to a coherent redundancy setup world view
for RAUC.

RAUC configuration files are loaded from one of the listed directories
in order of priority, only the first file found is used: **/etc/rauc/**,
**/run/rauc/**, **/usr/lib/rauc/**.

The **system.conf** is expected to describe the system RAUC runs on in a
way that all relevant information for performing updates and making
decisions are given.

Similar to other configuration files used by RAUC, the system
configuration uses a key-value syntax (similar to those known from .ini
files).

AUTHORS
-------

rauc is developed by Jan Luebbe, Enrico Joerns, Juergen Borleis and
contributors.

This manual page was written by Michael Heimpold <mhei@heimpold.de>, for
the Debian GNU/Linux system (but may be used by others).

SEE ALSO
--------

**casync**\ (1), **mksquashfs**\ (1), **unsquashfs**\ (1)
