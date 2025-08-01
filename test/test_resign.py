import shutil

from conftest import have_faketime
from helper import run


def test_resign(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-bundle.raucb", in_bundle)

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_verity(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-verity-bundle.raucb", in_bundle)

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_crypt(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-crypt-bundle-unencrypted.raucb", in_bundle)

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/dev-only-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/rel-ca.pem"
    )

    assert exitcode == 0

    assert out_bundle.exists()

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-bundle.raucb", in_bundle)

    out_bundle = tmp_path / "out.raucb"
    out_bundle.touch(exist_ok=False)

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" resign {in_bundle} {out_bundle}"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert out_bundle.exists()


@have_faketime
def test_resign_extend_not_expired(tmp_path):
    out1_bundle = tmp_path / "out1.raucb"

    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {out1_bundle}"
    )
    assert exitcode == 0

    assert out1_bundle.exists()

    out2_bundle = tmp_path / "out2.raucb"

    out, err, exitcode = run(
        'faketime "2018-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {out1_bundle} {out2_bundle}"
    )
    assert exitcode == 0

    assert out2_bundle.exists()


@have_faketime
def test_resign_extend_expired_no_verify(tmp_path):
    out1_bundle = tmp_path / "out1.raucb"

    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {out1_bundle}"
    )
    assert exitcode == 0

    assert out1_bundle.exists()

    out2_bundle = tmp_path / "out2.raucb"

    out, err, exitcode = run(
        'faketime "2020-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --no-verify "
        f" resign {out1_bundle} {out2_bundle}"
    )
    assert exitcode == 0

    assert out2_bundle.exists()
