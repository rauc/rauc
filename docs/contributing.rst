Contributing
============

Thank you for thinking about contributing to RAUC!
Some different backgrounds and use-cases are essential for making RAUC work
well for all users.

The following should help you with submitting your changes, but don't let these
guidelines keep you from opening a pull request.
If in doubt, we'd prefer to see the code earlier as a work-in-progress PR and
help you with the submission process.

Workflow
--------

- Changes should be submitted via a `GitHub pull request
  <https://github.com/rauc/rauc/pulls>`_.
- Try to limit each commit to a single conceptual change.
- Add a signed-off-by line to your commits according to the `Developer's
  Certificate of Origin` (see below).
- Check that the tests still work before submitting the pull request. Also
  check the CI's feedback on the pull request after submission.
- When adding new features, please also add the corresponding
  documentation and test code.
- If your change affects backward compatibility, describe the necessary changes
  in the commit message and update the examples where needed.

Code
----

- Basically follow the Linux kernel coding style

Documentation
-------------
- Use `semantic linefeeds
  <http://rhodesmill.org/brandon/2012/one-sentence-per-line/>`_ in .rst files.

Check Scripts & Test Suite
--------------------------

To ensure we do not break existing behavior and detect potential bugs, RAUC
runs a test suite consisting of several components.
Some of them only run in CI, but most of them can be executed locally.
When working on a new feature or fixing a bug, please make sure these tests
succeed.

Code Style - uncrustify 
~~~~~~~~~~~~~~~~~~~~~~~

To maintain a consistent code style, we use the `uncrustify
<https://github.com/uncrustify/uncrustify>`_ code beautifier that also runs in
the CI loop.

To make sure your changes match the expected code style, run::

  ./uncrustify.sh

from the RAUC source code's root directory.
It will adapt style where necessary.

CLI Tests - sharness
~~~~~~~~~~~~~~~~~~~~

For high-level tests of the RAUC command line interface we use the `sharness
<https://github.com/chriscool/sharness>`_ shell library.

You can run these checks manually by executing::

  cd test
  ./rauc.t

from the RAUC source code's root directory but they will also be triggered by
the general test suite run (see below).
If you add or change subcommands or arguments of the CLI tool, make sure these
tests succeed and extend them if possible.
As many of these tests need root permissions, we recommend running them using the 
``qemu-test`` helper below.

glib Unit Tests - gtest
~~~~~~~~~~~~~~~~~~~~~~~

For testing the different C modules of RAUC's source code, we use the `glib
Test Framework <https://developer.gnome.org/glib/stable/glib-Testing.html>`_.

All tests reside in the ``test/`` folder and are named according to the module
they test (``test/bundle.c`` contains tests for ``src/bundle.c``).

To build and run an individual test, do::

  make test/bundle.test
  ./test/bundle.test

To run all tests, run::

  make check

This will also run the sharness CLI tests mentioned above.

.. note:: Although some of the tests need to run as root, do NOT use 'sudo', but
   use our ``qemu-test`` helper instead!

.. _sec-contributing-qemu-test:

QEMU Test Runner - qemu-test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As many of the unit tests require root privileges and thus could potentially
damage your host system, we provide a QEMU-based test environment where one can
safely run all checks in a virtual environment.

To run the entire test suite, type::

  ./qemu-test

For optimal performance, run::

  ./qemu-test passthrough

which will pass through your host's CPU features to the guest.

For interactive access to the test environment, use::

  ./qemu-test shell

Developer's Certificate of Origin
---------------------------------

RAUC uses the `Developer's Certificate of Origin 1.1
<https://developercertificate.org/>`_ with the same `process
<https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin>`_
as used for the Linux kernel:

  Developer's Certificate of Origin 1.1

  By making a contribution to this project, I certify that:

  (a) The contribution was created in whole or in part by me and I
      have the right to submit it under the open source license
      indicated in the file; or

  (b) The contribution is based upon previous work that, to the best
      of my knowledge, is covered under an appropriate open source
      license and I have the right under that license to submit that
      work with modifications, whether created in whole or in part
      by me, under the same open source license (unless I am
      permitted to submit under a different license), as indicated
      in the file; or

  (c) The contribution was provided directly to me by some other
      person who certified (a), (b) or (c) and I have not modified
      it.

  (d) I understand and agree that this project and the contribution
      are public and that a record of the contribution (including all
      personal information I submit with it, including my sign-off) is
      maintained indefinitely and may be redistributed consistent with
      this project or the open source license(s) involved.

Then you just add a line (using ``git commit -s``) saying:

  Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions).
