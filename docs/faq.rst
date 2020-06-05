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

Is the RAUC bundle format forwards/backwards compatible?
--------------------------------------------------------

The basic bundle format has not changed so far (squashfs containing images and
the manifest, with a CMS signature), which means that newer versions can
install old bundles.
Going forward, any issue with installing old bundles would be considered a bug.

Newer RAUC versions have added features and slot types, though (such as casync,
eMMC boot partitions, MBR/GPT partition switching).
If you use those features, older versions of RAUC that cannot handle them will
refuse to install the bundle.
As long as you don't use new features, our intention is that bundles created by
newer versions will be installable by older versions.

There are ideas of introducing a new bundle format to allow streaming
installation (over the network), but we won't remove support for the original
format.

If there are ever reasons that require an incompatible change, you can use a
two step migration:
You can use an intermediate update to ship a new RAUC binary in a bundle
created by the old (compatible) version.
Then use the newly installed RAUC binary for the real update.
