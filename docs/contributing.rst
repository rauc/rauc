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
- Add a signed-off-by line to your commits according to the :ref:`Developer's
  Certificate of Origin <sec-dco>`.
- Check that the tests still work before submitting the pull request. Also
  check the CI's feedback on the pull request after submission.
- When adding new features, please also add the corresponding
  documentation and test code.
- If your change affects backward compatibility, describe the necessary changes
  in the commit message and update the examples where needed.

Code
----

- The projects coding style is inspired by the Linux kernel, but also deviates
  from it in some points.
  For details, see :ref:`sec-code-style`.

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

.. _sec-code-style:

Code Style - uncrustify
~~~~~~~~~~~~~~~~~~~~~~~

To maintain a consistent code style, we use the `uncrustify
<https://github.com/uncrustify/uncrustify>`_ code beautifier that also runs in
the CI loop.

To make sure your changes match the expected code style, run::

  ./uncrustify.sh

from the RAUC source code's root directory.
It will adapt style where necessary.

CLI Tests - pytest
~~~~~~~~~~~~~~~~~~

For high-level tests of the RAUC command line interface we use `pytest
<https://docs.pytest.org/>`_.

You can run these checks manually by executing::

  pytest test/

from the RAUC source code's root directory but they will also be triggered by
the general test suite run (see below).
If you add or change subcommands or arguments of the CLI tool, make sure these
tests succeed and extend them if possible.
When touching the test code, make sure to run the 'ruff' linter/formatter on
the changed code::

  ruff format test/
  ruff check test/

As many of these tests need root permissions, we recommend running them using the
``qemu-test`` helper below.

glib Unit Tests - gtest
~~~~~~~~~~~~~~~~~~~~~~~

For testing the different C modules of RAUC's source code, we use the `glib
Test Framework <https://developer.gnome.org/glib/stable/glib-Testing.html>`_.

All tests reside in the ``test/`` folder and are named according to the module
they test (``test/bundle.c`` contains tests for ``src/bundle.c``).

The tests are built by default.
To explicitly switch them on or off in meson, use ``-Dtest=`` option::

  meson setup -Dtests=true build

You can run each compiled test individually::

  ./build/test/bundle-test

To run all tests, run::

  meson test -C build

This will also run the pytest CLI tests mentioned above.

.. note:: Although some of the tests need to run as root, do NOT use 'sudo', but
   use our ``qemu-test`` helper instead!

.. _sec-contributing-qemu-test:

QEMU Test Runner - qemu-test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As many of the unit tests require root privileges and thus could potentially
damage your host system, we provide a QEMU-based test environment where one can
run all checks in a virtual environment.
By using a VM, the tests can access diverse emulated storage devices (block,
NAND/MTD, eMMC) without any dependency on or risk to the host environment.
Furthermore no root privileges are needed on the host.

Note that this does **not** run in a full VM with its own filesystem,
but instead passes the host's VFS to the guest using virtfs (and adds some
tmpfs overlays).
This allows seamless access to the sources and binaries built on the host,
which saves a lot of time during the edit-compile-test loop.
Accordingly, the test dependencies need to be installed on the host.

To run the entire test suite, type::

  ./qemu-test

To run individual tests, you can either specify them by using the ``test=``
parameter::

  ./qemu-test test=install

The test name will be forwarded to ``meson test`` and thus must match the meson
test names (e.g. ``install`` for a glib-based unit test or ``pytest-install``
for a pytest-based test).

Or you start an interactive shell with access to the test environment::

  ./qemu-test shell

From which you run the tests manually (as shown in the previous sections).

Additional parameters that you can add to a ``./qemu-test`` call are:

:passthrough: for optimal performance (by passing through your host's CPU
  features to the guest).

:asan: sets up environment variables to support the address sanitizer.
  This requires meson was set up with ``-Db_sanitize=address,undefined``.

If you want to collect coverage information (built with ``-Db_coverage=true``),
you need to copy the generated gcov files from the VM back to the host system
using the ``save_gcov_data`` helper before using ``ninja coverage-html`` on the
host.
To avoid inconsistent coverage data when recompiling without restarting
qemu-test or to remove any coverage data in the VM, use ``clear_gcov_data``.

Interactive Test System
^^^^^^^^^^^^^^^^^^^^^^^

Beside providing a safe test environment, the ``./qemu-test`` script also
supports running RAUC interactively in the QEMU environment by calling::

  ./qemu-test system

This setup initializes QEMU to run with the RAUC service started, alongside a
configured D-Bus and dummy target slots to simulate a real firmware update
scenario.
The configuration uses GRUB as a mock boot selection backend, allowing RAUC to
interact with it as it would in a real system.
Notably, rebooting the environment is not supported in this setup, meaning the
testing is limited to a single boot cycle.
This is sufficient for testing RAUC’s update mechanism but does not cover
reboot-based validation.

.. _sec-dco:

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
