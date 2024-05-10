import os
import shutil

from conftest import have_casync, have_desync
from helper import run


@have_casync
def test_convert(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/casync.raucb")


@have_casync
def test_convert_ignore_image(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " convert"
        " --ignore-image appfs"
        f" {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/casync.raucb")


@have_casync
def test_convert_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    open(f"{tmp_path}/casync.raucb", "a").close()

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert os.path.exists(f"{tmp_path}/casync.raucb")


@have_casync
def test_convert_error(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 1

    assert not os.path.exists(f"{tmp_path}/casync.raucb")


@have_casync
def test_convert_casync_extra_args(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " convert"
        ' --casync-args="--chunk-size=64000"'
        f" {tmp_path}/good-bundle.raucb {tmp_path}/casync-extra-args.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/casync-extra-args.raucb")
    assert os.path.isdir(f"{tmp_path}/casync-extra-args.castr")


@have_casync
def test_convert_verity(tmp_path):
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        f" bundle install-content/ {tmp_path}/tmp-verity.raucb"
    )
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " --trust-environment"
        f" convert {tmp_path}/tmp-verity.raucb {tmp_path}/casync-verity.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/casync-verity.raucb")
    assert os.path.isdir(f"{tmp_path}/casync-verity.castr")


@have_desync
def test_convert_desync(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " --conf minimal-desync-test.conf"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/desync.raucb")
    assert os.path.isdir(f"{tmp_path}/desync.castr")


@have_desync
def test_convert_desync_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    open(f"{tmp_path}/desync.raucb", "a").close()

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " --conf minimal-desync-test.conf"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert os.path.exists(f"{tmp_path}/desync.raucb")


@have_desync
def test_convert_desync_error(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        " --conf minimal-desync-test.conf"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 1

    assert not os.path.exists(f"{tmp_path}/desync.raucb")


@have_desync
def test_convert_desync_extra_args(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " --conf minimal-desync-test.conf"
        " convert"
        ' --casync-args="--chunk-size=32:128:512"'
        f" {tmp_path}/good-bundle.raucb {tmp_path}/desync-extra-args.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/desync-extra-args.raucb")
