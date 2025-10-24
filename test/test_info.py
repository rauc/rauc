import json
import shutil
import subprocess

from conftest import have_json, have_streaming
from helper import run


def test_info_plain(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  plain" in out


def test_info_verity():
    out, err, exitcode = run("rauc --keyring openssl-ca/dev-ca.pem info good-verity-bundle.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  verity" in out


def test_info_verity_adaptive_meta():
    out, err, exitcode = run("rauc --keyring openssl-ca/dev-ca.pem info good-adaptive-meta-bundle.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")


@have_streaming
def test_info_streaming():
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem info http://127.0.0.1/test/good-verity-bundle.raucb"
    )

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")


@have_streaming
def test_info_streaming_key_file():
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "info https://127.0.0.3/test/good-verity-bundle.raucb "
        "--tls-cert openssl-ca/web/client-1.cert.pem "
        "--tls-key openssl-ca/web/private/client-1.pem "
        "--tls-ca openssl-ca/web/ca.cert.pem"
    )

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")


@have_streaming
def test_info_streaming_key_pkcs11(pkcs11):
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "-C streaming:sandbox-user=root "  # softhsm DB is currently in /tmp/pytest-of-root, which is root-only
        "info https://127.0.0.3/test/good-verity-bundle.raucb "
        "--tls-cert openssl-ca/web/client-1.cert.pem "
        "--tls-key 'pkcs11:token=rauc;object=client-1?pin-value=1111' "
        "--tls-ca openssl-ca/web/ca.cert.pem"
    )

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")


def test_info_casync_plain(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-casync-bundle-1.5.1.raucb", tmp_path / "good-casync-bundle-1.5.1.raucb")

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info {tmp_path}/good-casync-bundle-1.5.1.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "rootfs.img.caibx" in out
    assert "appfs.img.caibx" in out


def test_info_casync_verity():
    out, err, exitcode = run("rauc --keyring openssl-ca/dev-ca.pem info good-casync-bundle-verity.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "rootfs.img.caibx" in out
    assert "appfs.img.caibx" in out


def test_info_crypt_unencrypted():
    out, err, exitcode = run("rauc --keyring openssl-ca/dev-ca.pem info good-crypt-bundle-unencrypted.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  crypt" in out


def test_info_crypt_encrypted_valid_key():
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "--key openssl-enc/keys/rsa-4096/private-key-000.pem "
        "info good-crypt-bundle-encrypted.raucb"
    )

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  crypt" in out


def test_info_crypt_encrypted_invalid_key():
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "--key openssl-enc/keys/rsa-4096/private-key-005.pem "
        "info good-crypt-bundle-encrypted.raucb"
    )

    assert exitcode == 1
    assert "Failed to decrypt CMS EnvelopedData" in err


def test_info_crypt_encrypted_pkcs11(pkcs11):
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "--key 'pkcs11:token=rauc;object=enc-rsa-000' "
        "info good-crypt-bundle-encrypted.raucb"
    )

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  crypt" in out


def test_info_dump_recipients_crypt_encrypted():
    out, err, exitcode = run(
        "rauc --keyring openssl-ca/dev-ca.pem "
        "--key openssl-enc/keys/rsa-4096/private-key-000.pem "
        "--dump-recipients "
        "info good-crypt-bundle-encrypted.raucb"
    )

    assert exitcode == 0
    assert "10 Recipients:" in out


def test_info_with_config(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc --conf=test.conf info {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  plain" in out


def test_info_verification_failure(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("invalid-sig-bundle.raucb", tmp_path / "invalid-sig-bundle.raucb")

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info {tmp_path}/invalid-sig-bundle.raucb")

    assert exitcode == 1
    assert "signature verification failed" in err


def test_info_dump_cert_unverified():
    out, err, exitcode = run("rauc --no-verify --dump-cert info good-bundle.raucb")

    assert exitcode == 0
    assert "Certificate:" in out


def test_info_valid_file_uri(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc info --keyring openssl-ca/dev-ca.pem file://{tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert out.startswith("Compatible:     'Test Config'")
    assert "Bundle Format:  plain" in out


def test_info_invalid_file_uri():
    out, err, exitcode = run("rauc info --keyring openssl-ca/dev-ca.pem file://good-bundle.raucb")

    assert exitcode == 1
    assert "Conversion error:" in err

    out, err, exitcode = run("rauc info --keyring openssl-ca/dev-ca.pem file:/good-bundle.raucb")

    assert exitcode == 1
    assert "No such file:" in err


def test_info_format_shell(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-adaptive-meta-bundle.raucb", tmp_path / "good-adaptive-meta-bundle.raucb")

    proc = subprocess.run(
        "rauc info --keyring openssl-ca/dev-ca.pem "
        f"--output-format=shell {tmp_path}/good-adaptive-meta-bundle.raucb | sh",
        shell=True,
    )
    assert proc.returncode == 0


@have_json
def test_info_format_json(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        f"rauc info --keyring openssl-ca/dev-ca.pem --output-format=json {tmp_path}/good-bundle.raucb"
    )

    assert exitcode == 0
    assert json.loads(out)


@have_json
def test_info_format_json_pretty(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        f"rauc info --keyring openssl-ca/dev-ca.pem --output-format=json-pretty {tmp_path}/good-bundle.raucb"
    )

    assert exitcode == 0
    assert json.loads(out)


@have_json
def test_info_format_json2(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        f"rauc info --keyring openssl-ca/dev-ca.pem --output-format=json-2 {tmp_path}/good-bundle.raucb"
    )

    assert exitcode == 0
    assert json.loads(out)


def test_info_format_invalid():
    out, err, exitcode = run("rauc info --keyring openssl-ca/dev-ca.pem --output-format=invalid good-bundle.raucb")

    assert exitcode == 1
    assert "Unknown output format: 'invalid'" in err


def test_info_configoverride(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc info -c test.conf -C system:bundle-formats=verity {tmp_path}/good-bundle.raucb")
    assert exitcode == 1
    assert "Bundle format 'plain' not allowed" in err

    out, err, exitcode = run("rauc info -C system:bundle-formats")
    assert exitcode == 1
    assert "Error in parsing override: Missing '='" in err

    out, err, exitcode = run("rauc info -C systembundle-formats=verity")
    assert exitcode == 1
    assert "Error in parsing override: Missing ':'" in err

    out, err, exitcode = run("rauc info -C")
    assert exitcode == 1
    assert "Error in parsing override: you must specify it in format SECTION:KEY=VALUE" in err
