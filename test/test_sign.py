import os

from conftest import have_faketime
from helper import run


@have_faketime
def test_sign_bundle_expired_cert(tmp_path):
    out, err, exitcode = run(
        ' faketime "2019-07-02" '
        " rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f"bundle install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 1
    assert "certificate has expired" in err

    assert not os.path.exists(f"{tmp_path}/out.raucb")


@have_faketime
def test_sign_bundle_not_yet_valid_cert(tmp_path):
    out, err, exitcode = run(
        ' faketime "2017-01-01" '
        " rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f"bundle install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 1
    assert "certificate is not yet valid" in err

    assert not os.path.exists(f"{tmp_path}/out.raucb")


@have_faketime
def test_sign_bundle_almost_expired_cert(tmp_path):
    out, err, exitcode = run(
        ' faketime "2019-06-15" '
        " rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f"bundle install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")


@have_faketime
def test_sign_bundle_valid_cert(tmp_path):
    out, err, exitcode = run(
        ' faketime "2019-01-01" '
        " rauc "
        "--cert openssl-ca/rel/release-2018.cert.pem "
        "--key openssl-ca/rel/private/release-2018.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f"bundle install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")


@have_faketime
def test_sign_bundle_valid_cert_encrypted_key(tmp_path, monkeypatch):
    monkeypatch.setenv("RAUC_KEY_PASSPHRASE", "1111")
    out, err, exitcode = run(
        'faketime "2019-01-01" '
        "rauc "
        "--cert openssl-ca/rel/release-1.cert.pem "
        "--key openssl-ca/rel/private/release-1-encrypted.pem "
        "--keyring openssl-ca/rel-ca.pem "
        f"bundle install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/out.raucb")
