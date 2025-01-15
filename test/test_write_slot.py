import os
from subprocess import check_call

from helper import run
from conftest import needs_emmc


def test_write_slot_invalid_local_paths():
    out, err, exitcode = run("rauc -c test.conf write-slot rootfs.0 foo")
    assert exitcode == 1
    assert "No such file or directory" in err

    out, err, exitcode = run("rauc -c test.conf write-slot rootfs.0 foo.raucb")
    assert exitcode == 1
    assert "No such file or directory" in err

    out, err, exitcode = run("rauc -c test.conf write-slot rootfs.0 /path/to/foo.raucb")
    assert exitcode == 1
    assert "No such file or directory" in err


def test_write_slot_invalid_slot():
    out, err, exitcode = run("rauc -c test.conf write-slot dummy install-content/rootfs.img")
    assert exitcode == 1
    assert "No matching slot found for given slot name" in err


def test_write_slot_readonly():
    out, err, exitcode = run("rauc -c test.conf write-slot rescue.0 install-content/appfs.img")
    assert exitcode == 1
    assert "Reject writing to readonly slot" in err


def test_write_slot(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} write-slot rootfs.0 install-content/appfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out


def test_write_slot_no_handler(tmp_path, rauc_no_service):
    open(tmp_path / "image.xyz", mode="w").close()

    out, err, exitcode = run(f"{rauc_no_service} write-slot rootfs.0 {tmp_path}/image.xyz")
    assert exitcode == 1
    assert f"Unsupported image {tmp_path}/image.xyz for slot type ext4" in err


@needs_emmc
def test_write_boot_emmc(system):
    device = os.environ["RAUC_TEST_EMMC"]

    # disable boot partition to have a fixed setup
    check_call(["mmc", "bootpart", "enable", "0", "0", device])

    system.config["slot.bootloader.0"] = {
        "device": device,
        "type": "boot-emmc",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert "eMMC device was not enabled for booting, yet. Ignoring." in err
    assert f"Boot partition {device}boot0 is now active" in err

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert "Found active eMMC boot partition /dev/mmcblk0boot0" in err
    assert f"Boot partition {device}boot1 is now active" in err
