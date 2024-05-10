import os
import shutil

from helper import run


def test_bundle(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        "rauc bundle "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        f"{tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_args_compat(tmp_path):
    "test compatibiltiy for cert/key args before subcommand"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(f"rauc \
            --cert openssl-ca/dev/autobuilder-1.cert.pem \
            --key openssl-ca/dev/private/autobuilder-1.pem \
            bundle \
            {tmp_path}/install-content {tmp_path}/out.raucb")

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_mksquashfs_extra_args(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(f'rauc \
            --cert openssl-ca/dev/autobuilder-1.cert.pem \
            --key openssl-ca/dev/private/autobuilder-1.pem \
            bundle \
            --mksquashfs-args="-comp xz -info -progress" \
            {tmp_path}/install-content {tmp_path}/out.raucb')

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_pkcs11_key1(tmp_path, pkcs11):
    "A bundle signed with autobuilder-1 key must verify against keyring"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-1' \
            --key 'pkcs11:token=rauc;object=autobuilder-1' \
            {tmp_path}/install-content {tmp_path}/out.raucb")

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_pkcs11_key2_revoked(tmp_path, pkcs11):
    "A bundle signed with revoked autobuilder-2 key must NOT verify against keyring"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-2' \
            --key 'pkcs11:token=rauc;object=autobuilder-2' \
            {tmp_path}/install-content {tmp_path}/out.raucb")

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 1
    assert "certificate revoked" in err


def test_bundle_pkcs11_key_mismatch(tmp_path, pkcs11):
    "A bundle cannot be signed with mismatching key pair"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-1' \
            --key 'pkcs11:token=rauc;object=autobuilder-2' \
            {tmp_path}/install-content {tmp_path}/out.raucb")

    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert "key values mismatch" in err

    assert not os.path.exists(f"{tmp_path}/out.raucb")


def test_bundle_crypt(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")
    shutil.copy("install-content/manifest.raucm.crypt", tmp_path / "install-content/manifest.raucm")

    out, err, exitcode = run(
        "rauc bundle "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"{tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert "Creating 'crypt' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0
