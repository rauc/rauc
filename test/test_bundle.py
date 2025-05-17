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
    "test compatibility for cert/key args before subcommand"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        f"rauc \
            --cert openssl-ca/dev/autobuilder-1.cert.pem \
            --key openssl-ca/dev/private/autobuilder-1.pem \
            bundle \
            {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_mksquashfs_extra_args(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        f'rauc \
            --cert openssl-ca/dev/autobuilder-1.cert.pem \
            --key openssl-ca/dev/private/autobuilder-1.pem \
            bundle \
            --mksquashfs-args="-comp xz -info -progress" \
            {tmp_path}/install-content {tmp_path}/out.raucb'
    )

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_pkcs11_key1(tmp_path, pkcs11):
    "A bundle signed with autobuilder-1 key must verify against keyring"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-1' \
            --key 'pkcs11:token=rauc;object=autobuilder-1' \
            {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 0


def test_bundle_pkcs11_key2_revoked(tmp_path, pkcs11):
    "A bundle signed with revoked autobuilder-2 key must NOT verify against keyring"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-2' \
            --key 'pkcs11:token=rauc;object=autobuilder-2' \
            {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert os.path.exists(f"{tmp_path}/out.raucb")

    out, err, exitcode = run(f"rauc -c test.conf info {tmp_path}/out.raucb")
    assert exitcode == 1
    assert "certificate revoked" in err


def test_bundle_pkcs11_key_mismatch(tmp_path, pkcs11):
    "A bundle cannot be signed with mismatching key pair"

    shutil.copytree("install-content", tmp_path / "install-content")

    out, err, exitcode = run(
        f"rauc bundle \
            --cert 'pkcs11:token=rauc;object=autobuilder-1' \
            --key 'pkcs11:token=rauc;object=autobuilder-2' \
            {tmp_path}/install-content {tmp_path}/out.raucb"
    )

    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert "key values mismatch" in err

    assert not os.path.exists(f"{tmp_path}/out.raucb")


def test_bundle_crypt(tmp_path):
    shutil.copytree("install-content", tmp_path / "install-content")
    shutil.copyfile("install-content/manifest.raucm.crypt", tmp_path / "install-content/manifest.raucm")

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


def test_bundle_adaptive(tmp_path, bundle):
    bundle.manifest["image.rootfs"] = {
        "filename": "rootfs.img",
        "adaptive": "block-hash-index",
    }
    bundle.make_random_image("rootfs", 4097, "random rootfs")
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert "not a multiple of 4096 bytes" in err
    assert not bundle.output.is_file()


def test_bundle_content_checks(tmp_path, bundle):
    bundle.build()
    assert bundle.output.exists()
    bundle.output.unlink()

    # absolute symlinks are not allowed
    test_file = bundle.content / "abs-symlink"
    test_file.symlink_to("/dev/null")
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "absolute symlinks are not supported as bundle contents (abs-symlink)" in err
    assert not bundle.output.is_file()
    test_file.unlink()

    # relative symlinks are not allowed
    test_file = bundle.content / "rel-symlink"
    test_file.symlink_to("../foo")
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "symlinks containing slashes are not supported as bundle contents (rel-symlink)" in err
    assert not bundle.output.is_file()
    test_file.unlink()

    # local symlinks are allowed
    test_file = bundle.content / "local-symlink"
    test_file.symlink_to("foo")
    bundle.build()
    assert bundle.output.is_file()
    bundle.output.unlink()
    test_file.unlink()

    # directories are allowed
    test_dir = bundle.content / "subdir"
    test_dir.mkdir()
    bundle.build()
    assert bundle.output.is_file()
    bundle.output.unlink()
    test_dir.rmdir()

    # hidden directories are not allowed
    test_dir = bundle.content / ".hidden_subdir"
    test_dir.mkdir()
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "hidden directories are not supported as bundle contents (.hidden_subdir)"
    assert not bundle.output.is_file()
    test_dir.rmdir()

    # directories are not allowed
    test_fifo = bundle.content / "fifo"
    os.mkfifo(test_fifo)
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "only regular files are supported as bundle contents (fifo)"
    assert not bundle.output.is_file()
    test_fifo.unlink()


def test_bundle_min_rauc_version(bundle):
    bundle.manifest["update"]["min-rauc-version"] = "1.14-dev"
    bundle.build()
    bundle.output.unlink()

    bundle.manifest["update"]["min-rauc-version"] = "1000-rc.1+21000101"
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert "Minimum RAUC version in manifest (1000-rc.1+21000101) is newer than current version" in err
    assert not bundle.output.is_file()

    bundle.manifest["update"]["min-rauc-version"] = "bad_version"
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert (
        "Failed to parse 'min-rauc-version'. Expected 'Major[.Minor[.Patch]][-pre_release]]', got 'bad_version'" in err
    )
    assert not bundle.output.is_file()

    bundle.manifest["update"]["min-rauc-version"] = "1.13"
    out, err, exitcode = bundle.build_nocheck()
    assert exitcode == 1
    assert "Creating 'verity' format bundle" in out
    assert "Minimum RAUC version field in manifest is only supported since 1.14 (not '1.13')" in err
    assert not bundle.output.is_file()


def test_rollout_options(bundle):
    bundle.manifest["rollout"] = {
        "foo": "bar",
    }
    bundle.build()
