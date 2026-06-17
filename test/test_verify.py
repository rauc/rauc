import shutil

from conftest import have_faketime
from helper import run

# all tests require faketime to be available
pytestmark = have_faketime


def prepare_signing_time_conf(tmp_path):
    shutil.copyfile("openssl-ca/dev-ca.pem", tmp_path / "test-ca.pem")
    with (tmp_path / "use-bundle-signing-time.conf").open("a") as f:
        f.write("""
[system]
compatible=Test Config
bootloader=grub
grubenv=grubenv.test

[keyring]
path=test-ca.pem
use-bundle-signing-time=true
""")


def test_verify_with_use_bundle_signing_time_valid_signing_invalid_current(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")
    prepare_signing_time_conf(tmp_path)

    out, err, exitcode = run(
        'faketime "2018-01-01" '
        "rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f" bundle {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "out.raucb").exists()

    out, err, exitcode = run(
        f'faketime "2022-01-01" rauc --conf {tmp_path}/use-bundle-signing-time.conf info {tmp_path}/out.raucb'
    )

    assert exitcode == 0


def test_verify_with_use_bundle_signing_time_invalid_signing_valid_current(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")
    prepare_signing_time_conf(tmp_path)

    out, err, exitcode = run(
        'faketime "2022-01-01" '
        "rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        f" bundle {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "out.raucb").exists()

    out, err, exitcode = run(
        f'faketime "2018-01-01" rauc --conf {tmp_path}/use-bundle-signing-time.conf info {tmp_path}/out.raucb'
    )

    assert exitcode == 1


def test_info_no_check_time(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        'faketime "2018-01-01" '
        "rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        f" bundle {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "out.raucb").exists()

    out, err, exitcode = run(f'faketime "2018-01-01" rauc --keyring openssl-ca/rel-ca.pem info {tmp_path}/out.raucb')

    assert exitcode == 0

    out, err, exitcode = run(f'faketime "2022-01-01" rauc --keyring openssl-ca/rel-ca.pem info {tmp_path}/out.raucb')

    assert exitcode == 1

    out, err, exitcode = run(
        f'faketime "2022-01-01" rauc --keyring openssl-ca/rel-ca.pem --no-check-time info {tmp_path}/out.raucb'
    )

    assert exitcode == 0


def test_verify_with_use_bundle_signing_time_no_signing_time(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")
    prepare_signing_time_conf(tmp_path)

    # create a signed bundle
    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/rel/release-1.cert.pem "
        "--key openssl-ca/rel/private/release-1.pem "
        f" bundle {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert (tmp_path / "out.raucb").exists()

    # sign the same manifest with '-noattr' again
    out, err, exitcode = run(
        f"openssl cms -sign -noattr  -signer openssl-ca/rel/release-1.cert.pem -inkey openssl-ca/rel/private/release-1.pem -nodetach -in {tmp_path}/install-content/manifest.raucm -outform der -out {tmp_path}/new-signature.cms"
    )
    assert exitcode == 0
    assert (tmp_path / "new-signature.cms").exists()

    # replace original signature
    out, err, exitcode = run(
        f"rauc --keyring openssl-ca/rel-ca.pem replace-signature {tmp_path}/out.raucb {tmp_path}/new-signature.cms {tmp_path}/invalid-bundle.raucb"
    )
    assert exitcode == 0
    assert (tmp_path / "invalid-bundle.raucb").exists()

    # test verification with missing signing time
    out, err, exitcode = run(
        f"rauc --conf {tmp_path}/use-bundle-signing-time.conf info {tmp_path}/invalid-bundle.raucb"
    )

    assert exitcode == 1
    assert "Bundle signing time attribute not found in signature" in err
