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
- Add a signed-of-by line to your commits according to the `Developer's
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
