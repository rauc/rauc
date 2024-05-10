import os
import shutil

from conftest import have_openssl
from helper import run


@have_openssl
def test_extract_signature(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem"
        f" extract-signature {tmp_path}/good-bundle.raucb {tmp_path}/bundle.sig "
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0


@have_openssl
def test_extract_signature_crypt(tmp_path):
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem"
        " --key openssl-enc/keys/rsa-4096/private-key-000.pem"
        f" extract-signature good-crypt-bundle-encrypted.raucb {tmp_path}/bundle.sig "
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0


@have_openssl
def test_extract(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem" f" extract {tmp_path}/good-bundle.raucb {tmp_path}/bundle-extract "
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/bundle-extract/appfs.img")
    assert os.path.exists(f"{tmp_path}/bundle-extract/custom_handler.sh")
    assert os.path.exists(f"{tmp_path}/bundle-extract/hook.sh")
    assert os.path.exists(f"{tmp_path}/bundle-extract/manifest.raucm")
    assert os.path.exists(f"{tmp_path}/bundle-extract/rootfs.img")


@have_openssl
def test_extract_crypt(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem"
        " --key openssl-enc/keys/rsa-4096/private-key-000.pem"
        f" extract {tmp_path}/good-bundle.raucb {tmp_path}/bundle-extract "
    )

    assert exitcode == 0

    assert os.path.exists(f"{tmp_path}/bundle-extract/appfs.img")
    assert os.path.exists(f"{tmp_path}/bundle-extract/custom_handler.sh")
    assert os.path.exists(f"{tmp_path}/bundle-extract/hook.sh")
    assert os.path.exists(f"{tmp_path}/bundle-extract/manifest.raucm")
    assert os.path.exists(f"{tmp_path}/bundle-extract/rootfs.img")
