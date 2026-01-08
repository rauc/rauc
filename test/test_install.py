import json
import os
import shutil
from textwrap import dedent

from conftest import have_casync, have_http, have_streaming, no_service, root
from helper import run
from helper import slot_data_from_json

# all tests require root privileges
pytestmark = root


def test_install(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.isdir("/run/rauc/slots/active")
    assert os.path.islink("/run/rauc/slots/active/rootfs")
    assert os.readlink("/run/rauc/slots/active/rootfs")

    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"
    assert status_data["boot_primary"] == "rootfs.0"

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc install {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0

    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "good"
    assert status_data["boot_primary"] == "rootfs.1"


def test_install_verity(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")

    out, err, exitcode = run(f"rauc install {tmp_path}/good-verity-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_crypt(rauc_dbus_service_with_system_crypt, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-crypt-bundle-encrypted.raucb", tmp_path / "good-crypt-bundle-encrypted.raucb")

    out, err, exitcode = run(f"rauc install {tmp_path}/good-crypt-bundle-encrypted.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_env(rauc_dbus_service_with_system_adaptive, tmp_path):
    assert (tmp_path / "images/rootfs-1").is_file()
    assert (tmp_path / "images/rootfs-1").stat().st_size == 0

    bundle_name = "good-adaptive-meta-bundle.raucb"

    # copy to tmp path for safe ownership check
    shutil.copyfile(bundle_name, tmp_path / bundle_name)

    out, err, exitcode = run(f"rauc install {tmp_path}/{bundle_name}")

    assert exitcode == 0
    assert (tmp_path / "images/rootfs-1").stat().st_size > 0

    with open(tmp_path / "preinstall-env") as f:
        pre_lines = f.readlines()
        assert "RAUC_CURRENT_BOOTNAME=A\n" in pre_lines
        assert "RAUC_TARGET_SLOTS=1 2\n" in pre_lines
        assert "RAUC_META_UPDATE_POLL=86400\n" in pre_lines
        assert "RAUC_META_VERSION_CHANNEL=beta\n" in pre_lines

    with open(tmp_path / "postinstall-env") as f:
        post_lines = f.readlines()

    assert post_lines == pre_lines


@have_casync
def test_install_plain_casync_local(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-casync-bundle-1.5.1.raucb", tmp_path / "good-casync-bundle-1.5.1.raucb")
    shutil.copytree("good-casync-bundle-1.5.1.castr", tmp_path / "good-casync-bundle-1.5.1.castr")

    out, err, exitcode = run(f"rauc install {tmp_path}/good-casync-bundle-1.5.1.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


@have_casync
@have_http
def test_install_verity_casync_http(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    out, err, exitcode = run("rauc install http://127.0.0.1/test/good-casync-bundle-verity.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


@have_streaming
def test_install_streaming(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    out, err, exitcode = run("rauc install http://127.0.0.1/test/good-verity-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


@have_streaming
def test_install_streaming_error(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    out, err, exitcode = run("rauc install http://127.0.0.1/test/missing-bundle.raucb")

    assert exitcode == 1
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_progress(rauc_dbus_service_with_system, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc install --progress {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_rauc_external(rauc_dbus_service_with_system_external, tmp_path):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    out, err, exitcode = run(f"rauc install {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.getsize(tmp_path / "images/rootfs-0") == 0

    out, err, exitcode = run(f"rauc install {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.getsize(tmp_path / "images/rootfs-0") > 0


def test_install_per_slot_status(tmp_path, create_system_files, system):
    """Tests that installation works with 'per-slot' status file"""
    system.prepare_minimal_config()
    del system.config["system"]["data-directory"]
    system.config["system"]["statusfile"] = "per-slot"
    system.write_config()

    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")

    with system.running_service("A"):
        out, err, exitcode = run(f"rauc install {tmp_path}/good-verity-bundle.raucb")

        assert exitcode == 0
        assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_abc(rauc_dbus_service_with_system_abc, tmp_path):
    """Tests that two consecutive calls of 'rauc install' update different slot groups"""
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.exists(tmp_path / "images/rootfs-2")
    assert not os.path.getsize(tmp_path / "images/rootfs-2") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")

    # First installation should update rootfs-1 (implementation-defined)
    out, err, exitcode = run(f"rauc install {tmp_path}/good-verity-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-0") == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.getsize(tmp_path / "images/rootfs-2") == 0

    # Second installation should update rootfs-2 (implementation-defined)
    out, err, exitcode = run(f"rauc install {tmp_path}/good-verity-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-0") == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0
    assert os.path.getsize(tmp_path / "images/rootfs-2") > 0


@no_service
def test_install_no_service(tmp_path, create_system_files, system):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    system.prepare_minimal_config()
    system.write_config()
    out, err, exitcode = run(f"{system.prefix} install --override-boot-slot=A {tmp_path}/good-bundle.raucb")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


@no_service
@have_streaming
def test_install_no_service_streaming(tmp_path, create_system_files, system):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    system.prepare_minimal_config()
    system.write_config()
    out, err, exitcode = run(
        f"{system.prefix} --override-boot-slot=A install http://127.0.0.1/test/good-verity-bundle.raucb"
    )

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0


@no_service
@have_streaming
def test_install_no_service_streaming_error(tmp_path, create_system_files, system):
    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    # copy to tmp path for safe ownership check
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    system.prepare_minimal_config()
    system.write_config()
    out, err, exitcode = run(
        f"{system.prefix} --override-boot-slot=A install http://127.0.0.1/test/missing-bundle.raucb"
    )

    assert exitcode == 1
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0


def test_install_hook_env(rauc_dbus_service_with_system, tmp_path, bundle):
    bundle.add_hook_script(
        dedent("""\
    #!/bin/bash
    set -e

    if [ -z "$RAUC_PYTEST_TMP" ]; then
        exit 1
    fi

    case "$1" in
        install-check)
            env | sort > "$RAUC_PYTEST_TMP/install-check-hook-env"
            ;;
        global-pre-install)
            env | sort > "$RAUC_PYTEST_TMP/global-pre-install-hook-env"
            ;;
        global-post-install)
            env | sort > "$RAUC_PYTEST_TMP/global-post-install-hook-env"
            ;;
        slot-pre-install)
            env | sort > "$RAUC_PYTEST_TMP/slot-pre-install-hook-env"
            ;;
        slot-install)
            env | sort > "$RAUC_PYTEST_TMP/slot-install-hook-env"
            ;;
        slot-post-install)
            env | sort > "$RAUC_PYTEST_TMP/slot-post-install-hook-env"
            ;;
        *)
            exit 1
            ;;
    esac
    """)
    )
    bundle.manifest["hooks"]["hooks"] = "install-check;global-pre-install;global-post-install"
    bundle.manifest["image.rootfs"] = {
        "filename": "rootfs.img",
        "hooks": "pre-install;post-install",
    }
    bundle.make_random_image("rootfs", 4096, "random rootfs")
    bundle.manifest["image.appfs"] = {
        "filename": "appfs.img",
        "hooks": "install",
    }
    bundle.make_random_image("appfs", 4096, "random appfs")
    bundle.manifest["meta.test"] = {
        "foo": "bar",
    }
    bundle.build()

    out, err, exitcode = run(f"rauc install {bundle.output}")

    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0

    with open(tmp_path / "install-check-hook-env") as f:
        check_lines = f.readlines()
        assert "RAUC_MF_VERSION=2011.03-2\n" in check_lines
        assert "RAUC_SYSTEM_COMPATIBLE=Test Config\n" in check_lines
        assert "RAUC_SYSTEM_VARIANT=Default Variant\n" in check_lines
        assert "RAUC_META_TEST_FOO=bar\n" in check_lines

    with open(tmp_path / "global-pre-install-hook-env") as f:
        global_pre_lines = f.readlines()
        assert check_lines == global_pre_lines

    with open(tmp_path / "global-post-install-hook-env") as f:
        global_post_lines = f.readlines()
        assert check_lines == global_post_lines

    with open(tmp_path / "slot-pre-install-hook-env") as f:
        pre_lines = f.readlines()
        assert "RAUC_IMAGE_CLASS=rootfs\n" in pre_lines
        assert "RAUC_IMAGE_SIZE=4096\n" in pre_lines
        assert "RAUC_SLOT_NAME=rootfs.1\n" in pre_lines
        assert "RAUC_SLOT_STATE=inactive\n" in pre_lines

    with open(tmp_path / "slot-post-install-hook-env") as f:
        post_lines = f.readlines()
        assert post_lines == pre_lines

    with open(tmp_path / "slot-install-hook-env") as f:
        install_lines = f.readlines()
        assert "RAUC_IMAGE_CLASS=appfs\n" in install_lines
        assert "RAUC_IMAGE_SIZE=4096\n" in install_lines
        assert "RAUC_SLOT_NAME=appfs.1\n" in install_lines
        assert "RAUC_SLOT_STATE=inactive\n" in install_lines


@have_streaming
def test_install_require_hash(rauc_dbus_service_with_system, tmp_path):
    GOOD_HASH = "2a7c9b2a31f11575deef280812e714fdb4542b55d308e39e85352ff996d79b8a"
    BAD_HASH = GOOD_HASH[:-1] + "0"

    assert os.path.exists(tmp_path / "images/rootfs-1")
    assert not os.path.getsize(tmp_path / "images/rootfs-1") > 0

    out, err, exitcode = run(
        f"rauc install http://127.0.0.1/test/good-verity-bundle.raucb --require-manifest-hash={BAD_HASH}"
    )
    assert exitcode == 1
    assert os.path.getsize(tmp_path / "images/rootfs-1") == 0

    out, err, exitcode = run(
        f"rauc install http://127.0.0.1/test/good-verity-bundle.raucb --require-manifest-hash={GOOD_HASH}"
    )
    assert exitcode == 0
    assert os.path.getsize(tmp_path / "images/rootfs-1") > 0
