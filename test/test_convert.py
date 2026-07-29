import json
import shutil

from conftest import have_casync, have_desync, have_json
from helper import run


@have_casync
def test_convert(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "casync.raucb").exists()


@have_casync
def test_convert_ignore_image(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

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

    assert (tmp_path / "casync.raucb").exists()


@have_casync
def test_convert_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    (tmp_path / "casync.raucb").touch()

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert (tmp_path / "casync.raucb").exists()


@have_casync
def test_convert_error(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/casync.raucb"
    )

    assert exitcode == 1

    assert not (tmp_path / "casync.raucb").exists()


@have_casync
def test_convert_casync_extra_args(tmp_path):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

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

    assert (tmp_path / "casync-extra-args.raucb").exists()
    assert (tmp_path / "casync-extra-args.castr").is_dir()


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

    assert (tmp_path / "casync-verity.raucb").exists()
    assert (tmp_path / "casync-verity.castr").is_dir()


@have_casync
@have_json
def test_convert_archive(tmp_path, bundle):
    bundle.manifest["image.rootfs"] = {
        "filename": "rootfs.tar",
    }
    bundle.make_tar_image("rootfs", {"file": b"archive content"})
    bundle.build()

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {bundle.output} {tmp_path}/casync-archive.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "casync-archive.raucb").exists()
    assert (tmp_path / "casync-archive.castr").is_dir()

    out, err, exitcode = run(
        f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=json-2 {tmp_path}/casync-archive.raucb"
    )

    assert exitcode == 0

    info = json.loads(out)

    images = {image["slot-class"]: image for image in info["images"]}
    # archive images are converted to a casync directory tree index (.caidx),
    # not a blob index (.caibx)
    assert images["rootfs"]["filename"] == "rootfs.tar.caidx"


@have_desync
def test_convert_desync(tmp_path, system):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    system.config["casync"] = {
        "use-desync": "true",
    }
    system.write_config()

    out, err, exitcode = run(
        f"{system.prefix}"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "desync.raucb").exists()
    assert (tmp_path / "desync.castr").is_dir()


@have_desync
def test_convert_desync_output_exists(tmp_path, system):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    (tmp_path / "desync.raucb").touch()

    system.config["casync"] = {
        "use-desync": "true",
    }
    system.write_config()

    out, err, exitcode = run(
        f"{system.prefix}"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert (tmp_path / "desync.raucb").exists()


@have_desync
def test_convert_desync_error(tmp_path, system):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    system.config["casync"] = {
        "use-desync": "true",
    }
    system.write_config()

    out, err, exitcode = run(
        f"{system.prefix}"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" convert {tmp_path}/good-bundle.raucb {tmp_path}/desync.raucb"
    )

    assert exitcode == 1

    assert not (tmp_path / "desync.raucb").exists()


@have_desync
def test_convert_desync_extra_args(tmp_path, system):
    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    system.config["casync"] = {
        "use-desync": "true",
    }
    system.write_config()

    out, err, exitcode = run(
        f"{system.prefix}"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        " convert"
        ' --casync-args="--chunk-size=32:128:512"'
        f" {tmp_path}/good-bundle.raucb {tmp_path}/desync-extra-args.raucb"
    )

    assert exitcode == 0

    assert (tmp_path / "desync-extra-args.raucb").exists()
