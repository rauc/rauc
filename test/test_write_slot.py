import os
from subprocess import check_call
from textwrap import dedent

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


def test_write_slot_image_type(tmp_path, rauc_no_service):
    """
    Tests writing image with non-standard '.bin' extension to an 'ext4' slot:
    - First run without explicit '--image-type' option set (should fail).
    - Second run *with* this option set (should succeed).
    """
    open(tmp_path / "image.bin", mode="w").close()

    out, err, exitcode = run(f"{rauc_no_service} write-slot rootfs.0 {tmp_path}/image.bin")
    assert exitcode == 1
    assert f"Unable to map extension of file '{tmp_path}/image.bin' to known image type" in err

    out, err, exitcode = run(f"{rauc_no_service} write-slot --image-type=raw rootfs.0 install-content/appfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out


def test_write_slot_no_handler(tmp_path, rauc_no_service):
    open(tmp_path / "image.vfat", mode="w").close()

    out, err, exitcode = run(f"{rauc_no_service} write-slot rootfs.0 {tmp_path}/image.vfat")
    assert exitcode == 1
    assert "Unsupported image type 'vfat' for slot type 'ext4'" in err


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


@needs_emmc
def test_write_boot_emmc_size_limit(system):
    """
    Sets 'size-limit' option for boot-emmc slot and checks that after writing,
    the data above the size-limit remains untouched.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    bootdevice = f"{device}boot0"
    size = 1024 * 1024  # full size of eMMC boot partition
    half_size = size // 2

    # disable boot partition to have a fixed setup
    check_call(["mmc", "bootpart", "enable", "0", "0", device])

    system.config["slot.bootloader.0"] = {
        "device": device,
        "type": "boot-emmc",
        "size-limit": f"{half_size}",
    }
    system.write_config()

    # Prepare known data
    original_data = os.urandom(size)
    with open(f"/sys/block/{bootdevice[4:]}/force_ro", "w") as f:
        f.write("0")
    with open(bootdevice, "wb") as f:
        f.write(original_data)
    with open(f"/sys/block/{bootdevice[4:]}/force_ro", "w") as f:
        f.write("1")

    # write image
    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert "eMMC device was not enabled for booting, yet. Ignoring." in err
    assert f"Boot partition {device}boot0 is now active" in err

    assert f"Cleared first {half_size} bytes on /dev/mmcblk0boot0" in err

    # Read back from device
    with open(bootdevice, "rb") as f:
        result_data = f.read(1024 * 1024)

    # Check first 16 bytes below 512 KiB are zeroed
    assert result_data[half_size - 0x10 : half_size] == b"\x00" * 0x10, "First 512 KiB is not zeroed"

    # Check first 16 bytes above 512 KiB are intact
    assert result_data[half_size : half_size + 0x10] == original_data[half_size : half_size + 0x10], (
        "Second 512 KiB is not intact"
    )


@needs_emmc
def test_write_boot_emmc_size_limit_too_large(system):
    """
    Sets 'size-limit' option for boot-emmc slot to a value larger then the
    actual size of the partition and ensures RAUC prints a warning.
    """
    device = os.environ["RAUC_TEST_EMMC"]

    # disable boot partition to have a fixed setup
    check_call(["mmc", "bootpart", "enable", "0", "0", device])

    system.config["slot.bootloader.0"] = {
        "device": device,
        "type": "boot-emmc",
        "size-limit": "10M",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert "eMMC device was not enabled for booting, yet. Ignoring." in err
    assert f"Boot partition {device}boot0 is now active" in err

    assert "The size-limit (10485760 bytes) exceeds actual device size" in err


@needs_emmc
def test_write_boot_emmc_hook(tmp_path, create_system_files, system, bundle):
    """
    Tests that pre/post-install slot hooks work correctly with boot-emmc slots.
    Regression test for https://github.com/rauc/rauc/issues/1893
    """
    device = os.environ["RAUC_TEST_EMMC"]

    # disable boot partition for a fixed setup
    check_call(["mmc", "bootpart", "enable", "0", "0", device])

    system.prepare_minimal_config()
    system.config["slot.bootloader.0"] = {
        "device": device,
        "type": "boot-emmc",
    }
    system.write_config()

    bundle.add_hook_script(
        dedent("""\
        #!/bin/bash
        set -e
        case "$1" in
            slot-pre-install)
                env | sort > "$RAUC_PYTEST_TMP/pre-install-hook-env"
                ;;
            slot-post-install)
                env | sort > "$RAUC_PYTEST_TMP/post-install-hook-env"
                ;;
            *)
                exit 1
                ;;
        esac
        """)
    )
    bundle.manifest["image.bootloader"] = {
        "filename": "bootloader.img",
        "hooks": "pre-install;post-install",
    }
    bundle.make_random_image("bootloader", 4096, "random bootloader")
    bundle.build()

    with system.running_service("A"):
        out, err, exitcode = run(f"rauc install {bundle.output}")

    assert exitcode == 0

    with open(tmp_path / "pre-install-hook-env") as f:
        pre_lines = f.readlines()
        assert "RAUC_SLOT_NAME=bootloader.0\n" in pre_lines
        assert "RAUC_SLOT_CLASS=bootloader\n" in pre_lines
        assert "RAUC_SLOT_TYPE=boot-emmc\n" in pre_lines

    with open(tmp_path / "post-install-hook-env") as f:
        post_lines = f.readlines()
        assert "RAUC_SLOT_NAME=bootloader.0\n" in post_lines
        assert "RAUC_SLOT_CLASS=bootloader\n" in post_lines
        assert "RAUC_SLOT_TYPE=boot-emmc\n" in post_lines
