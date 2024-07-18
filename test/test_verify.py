import os
import shutil

from conftest import have_faketime
from helper import run

# all tests require faketime to be available
pytestmark = have_faketime


def prepare_signing_time_conf(tmp_path):
    shutil.copyfile("openssl-ca/dev-ca.pem", tmp_path / "test-ca.pem")
    with open(f"{tmp_path}/use-bundle-signing-time.conf", "a") as f:
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

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(
        'faketime "2022-01-01" '
        "rauc "
        f"--conf {tmp_path}/use-bundle-signing-time.conf "
        f"info {tmp_path}/out.raucb"
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

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(
        'faketime "2018-01-01" '
        "rauc "
        f"--conf {tmp_path}/use-bundle-signing-time.conf "
        f"info {tmp_path}/out.raucb"
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

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(
        'faketime "2018-01-01" ' "rauc " f"--keyring openssl-ca/rel-ca.pem " f"info {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    out, err, exitcode = run(
        'faketime "2022-01-01" ' "rauc " f"--keyring openssl-ca/rel-ca.pem " f"info {tmp_path}/out.raucb"
    )

    assert exitcode == 1

    out, err, exitcode = run(
        'faketime "2022-01-01" '
        "rauc "
        f"--keyring openssl-ca/rel-ca.pem "
        "--no-check-time "
        f"info {tmp_path}/out.raucb"
    )

    assert exitcode == 0
