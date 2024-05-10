import os
import shutil

from conftest import have_faketime
from helper import run


def test_resign(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {tmp_path}/good-bundle.raucb {tmp_path}/out.raucb"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run("rauc" " --keyring openssl-ca/rel-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 1

    out, err, exitcode = run("rauc" " --keyring openssl-ca/dev-only-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_resign_verity(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {tmp_path}/good-verity-bundle.raucb {tmp_path}/out.raucb"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run("rauc" " --keyring openssl-ca/rel-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 1

    out, err, exitcode = run("rauc" " --keyring openssl-ca/dev-only-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_resign_crypt(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-crypt-bundle-unencrypted.raucb", tmp_path / "good-crypt-bundle-unencrypted.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/dev-only-ca.pem"
        f" resign {tmp_path}/good-crypt-bundle-unencrypted.raucb {tmp_path}/out.raucb"
        " --signing-keyring openssl-ca/rel-ca.pem"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run("rauc" " --keyring openssl-ca/dev-only-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 1

    out, err, exitcode = run("rauc" " --keyring openssl-ca/rel-ca.pem" f" info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_resign_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    open(f"{tmp_path}/out.raucb", "a").close()

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" resign {tmp_path}/good-bundle.raucb {tmp_path}/out.raucb"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert os.path.exists(f"{tmp_path}/out.raucb")


@have_faketime
def test_resign_extend_not_expired(tmp_path):
    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {tmp_path}/out1.raucb"
    )
    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        'faketime "2018-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {tmp_path}/out1.raucb {tmp_path}/out2.raucb"
    )
    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_faketime
def test_resign_extend_expired_no_verify(tmp_path):
    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {tmp_path}/out1.raucb"
    )
    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        'faketime "2020-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --no-verify "
        f" resign {tmp_path}/out1.raucb {tmp_path}/out2.raucb"
    )
    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out2.raucb")
