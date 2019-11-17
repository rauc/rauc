Frequently Asked Questions
==========================

Why doesn't the installed system use the whole partition?
---------------------------------------------------------

The filesystem image installed via RAUC was probably created for a size smaller
than the partition on the target device.

Especially in cases where the same bundle will be installed on devices which use
different partition sizes, tar archives are preferable to filesystem images.
When RAUC installs from a tar archive, it will first create a new filesystem on
the target partition, allowing use of the full size.

Is it possible to use RAUC without D-Bus (Client/Server mode)?
--------------------------------------------------------------

Yes. If you compile RAUC using the ``--disable-service`` configure option, you
will be able to compile RAUC without service mode and without D-Bus support::

  ./configure --disable-service

Then every call of the command line tool will be executed directly rather than
being forwarded to the RAUC service process running on your machine.

Why does RAUC not have an ext2 / ext3 file type?
------------------------------------------------

ext4 is the successor of ext3. There is no advantage in using ext3 over ext4.

Some people still tend to select ext2 when they want a file system without
journaling. This is not necessary, as one can turn off journaling in ext4,
either during creation::

  mkfs.ext4 -O ^has_journal

or later with::

  tune2fs -O ^has_journal

Note that even if there is only an ext4 slot type available, potentially each
file system mountable as ext4 should work (with the filename suffix adapted).
