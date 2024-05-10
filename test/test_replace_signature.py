import os
import shutil

from conftest import have_openssl
from helper import run


@have_openssl
def test_replace_signature_plain(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-bundle.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_verity(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-verity-bundle.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-verity-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_crypt(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-crypt-bundle-unencrypted.raucb", tmp_path / "good-crypt-bundle-unencrypted.raucb")

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-crypt-bundle-unencrypted.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-crypt-bundle-unencrypted.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    open(f"{tmp_path}/out2.raucb", "a").close()

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-bundle.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 1
    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_bad_keyring(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-bundle.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 1
    assert not os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_no_verify(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        "--keyring openssl-ca/dev-ca.pem "
        f"resign {tmp_path}/good-bundle.raucb {tmp_path}/out1.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )

    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out1.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        f"extract-signature {tmp_path}/out1.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-only-ca.pem "
        "--no-verify "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out2.raucb "
        "--signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/out2.raucb")


@have_openssl
def test_replace_signature_invalid_bundle_signature_output(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copy("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    open(f"{tmp_path}/invalid.raucb", "a").close()
    open(f"{tmp_path}/invalid.sig", "a").close()

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"extract-signature {tmp_path}/good-bundle.raucb {tmp_path}/bundle.sig"
    )
    assert exitcode == 0
    assert os.path.exists(f"{tmp_path}/bundle.sig")

    out, err, exitcode = run(f"openssl asn1parse -inform DER -in {tmp_path}/bundle.sig -noout")
    assert exitcode == 0

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/invalid.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/out.raucb "
        "--signing-keyring openssl-ca/dev-ca.pem"
    )
    assert exitcode == 1
    assert not os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/invalid.sig {tmp_path}/out.raucb "
        "--signing-keyring openssl-ca/dev-ca.pem"
    )
    assert exitcode == 1
    assert not os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/notexisting/out.raucb "
        "--signing-keyring openssl-ca/dev-ca.pem"
    )
    assert exitcode == 1
    assert not os.path.exists(f"{tmp_path}/notexisting/out.raucb")

    out, err, exitcode = run(
        "rauc "
        "--keyring openssl-ca/dev-ca.pem "
        f"replace-signature {tmp_path}/good-bundle.raucb "
        f"{tmp_path}/bundle.sig {tmp_path}/good-bundle.raucb "
        "--signing-keyring openssl-ca/dev-ca.pem"
    )
    assert exitcode == 1
    assert os.path.exists(f"{tmp_path}/good-bundle.raucb")
