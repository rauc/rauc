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
