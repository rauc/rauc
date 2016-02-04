Design Decisions
================

Bundle Mode
-----------
* squashfs
   * mountable
   * avoids copies
   * signature location
   * easy to use for USB memory sticks or upload via a web interface

Network Mode
------------
* manifest should define complete consistent system
* manifest is signed with a detached CMS signature
* manifest contains size and cryptographic hash of each file
* rauc detects files which have not changed and skips the download
* server can control update process

Custom Handlers
---------------
* a handler can override default rauc behaviour to handle special cases (which
  were not anticipated during the initial project development)
   * sanity checks
   * modifications to the partition layout
   * bootloader updates
