Design Checklist
================

Watchdog vs. Confirmation

* WD must reset the whole system (DVFS, flash state)

Symmetric vs. Rescue+Normal

Image Signing

* Development + Release
* PKI
* Certificate Revocation

Configuration
-------------

Most systems require a location for storing configuration data. Unlike for
example the root or application filesystems which are often mounted
read-only, a configuration partition would be writable to allow modifying
configuration data.

The decision about how to set up a configuration storage depends on several
aspects:

* May configuration format change over different application versions?
* 
