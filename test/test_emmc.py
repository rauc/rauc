import os
from subprocess import check_call

from conftest import needs_emmc
from helper import run


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