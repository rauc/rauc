import os

from helper import run


def test_encrypt_multi_single_cert_pem(tmp_path):
    out, err, exitcode = run(
        "rauc encrypt "
        "--to openssl-enc/keys/rsa-4096/cert-000.pem "
        "--to openssl-enc/keys/rsa-4096/cert-001.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"good-crypt-bundle-unencrypted.raucb {tmp_path}/encrypted.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/encrypted.raucb")


def test_encrypt_single_multi_cert_pem(tmp_path):
    out, err, exitcode = run(
        "rauc encrypt "
        "--to openssl-enc/keys/rsa-4096/certs.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"good-crypt-bundle-unencrypted.raucb {tmp_path}/encrypted.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/encrypted.raucb")


def test_encrypt_single_multi_cert_pem_rsa_ecc_mixed(tmp_path):
    out, err, exitcode = run(
        "rauc encrypt "
        "--to openssl-enc/keys/rsa-4096/certs.pem "
        "--to openssl-enc/keys/ecc/certs.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"good-crypt-bundle-unencrypted.raucb {tmp_path}/encrypted.raucb"
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/encrypted.raucb")


def test_encrypt_broken_multi_cert_pem(tmp_path):
    with open("openssl-enc/keys/rsa-4096/certs.pem") as infile:
        with open(f"{tmp_path}/certs.pem", "a") as outfile:
            outfile.writelines(infile.readlines()[:-5])

    out, err, exitcode = run(
        "rauc encrypt "
        f"--to {tmp_path}/certs.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"good-crypt-bundle-unencrypted.raucb {tmp_path}/encrypted.raucb"
    )

    assert exitcode == 1

    assert not os.path.exists(f"{tmp_path}/encrypted.raucb")


def test_encrypt_verity_bundle(tmp_path):
    out, err, exitcode = run(
        "rauc encrypt "
        "--to openssl-enc/keys/rsa-4096/cert-000.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"good-verity-bundle.raucb {tmp_path}/encrypted.raucb"
    )

    assert exitcode == 1
    assert "Refused to encrypt input bundle" in err

    assert not os.path.exists(f"{tmp_path}/encrypted.raucb")
