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


@needs_emmc
def test_write_emmc_boot_linked_no_active_boot(system):
    """
    Test emmc-boot-linked handler when no boot partition is active yet.
    Should fail with appropriate error message.
    """

    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "0", "0", emmc.base_dev])

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert f"Device '{emmc.base_dev}' is not boot enabled" in err


@needs_emmc
def test_write_emmc_boot_linked_with_active_boot0_with_migrate(system):
    """
    Test emmc-boot-linked handler when boot0 is active.
    Should migrate content from boot0 to boot1, then write new image to boot0.
    """

    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()
    size = 1024 * 1024  # full size of eMMC boot partition

    check_call(["mmc", "bootpart", "enable", "1", "0", emmc.base_dev])

    system.write_config()

    # Prepare known data
    original_data = os.urandom(size)

    with open(f"/sys/block/{emmc.boot0[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(emmc.boot0, "wb") as f:
        f.write(original_data)
    with open(f"/sys/block/{emmc.boot0[5:]}/force_ro", "w") as f:
        f.write("1")

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {emmc.boot0}: boot0" in err
    assert f"Preserving boot partition content by copying from {emmc.boot0} to {emmc.boot1}" in err

    # Read back migrated data from boot1
    with open(emmc.boot1, "rb") as f:
        migrated_data = f.read(size)

    # Check that the original data was migrated correctly
    assert migrated_data[:1024] == original_data[:1024], "Migration did not preserve original data correctly"


@needs_emmc
def test_write_emmc_boot_linked_with_active_boot1_no_migrate(system):
    """
    Test emmc-boot-linked handler when boot1 is active.
    Should write new image to boot0 without migrating content from boot1.
    Also writes test data and verifies that no migration occurred.
    """

    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "2", "0", emmc.base_dev])

    # Prepare test data to verify that no migration occurred
    test_data = b"BOOT1_BOOTLOADER_DATA" + b"\x00" * (1024 - 21)
    with open(f"/sys/block/{emmc.boot1[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(emmc.boot1, "wb") as f:
        f.write(test_data)
    with open(f"/sys/block/{emmc.boot1[5:]}/force_ro", "w") as f:
        f.write("1")

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {emmc.boot0}: boot1" in err
    assert "writing data to device" in err

    # Check that boot1 data is unchanged
    with open(emmc.boot1, "rb") as f:
        boot1_data_after = f.read(1024)
    assert boot1_data_after == test_data, "Boot1 data should remain unchanged when targeting inactive partition"

    # Check that boot0 contains new data
    with open(emmc.boot0, "rb") as f:
        boot0_data_after = f.read(1024)
    assert boot0_data_after != test_data, "Boot0 should contain new image data"


@needs_emmc
def test_write_emmc_boot_linked_with_active_boot0_no_migrate(system):
    """
    Test emmc-boot-linked handler when boot0 is active and targeting boot1.
    Should skip migration and directly write to the inactive partition (boot1).
    """
    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "1", "0", emmc.base_dev])

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.1 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {emmc.boot1}: boot0" in err
    assert f"Preserving boot partition content by copying from {emmc.boot0} to {emmc.boot1}" not in err


@needs_emmc
def test_write_emmc_boot_linked_point_to_same_boot_dev(system):
    emmc = system.prepare_emmc_boot_linked_config()
    system.config["slot.bootloader.1"]["device"] = emmc.boot0
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "1", "0", emmc.base_dev])

    test_data = b"EXISTING_BOOTLOADER_DATA" + b"\x00" * (1024 - 24)
    with open(f"/sys/block/{emmc.boot0[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(emmc.boot0, "wb") as f:
        f.write(test_data)
    with open(f"/sys/block/{emmc.boot0[5:]}/force_ro", "w") as f:
        f.write("1")

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "No data directory or status file set, falling back to per-slot status."
    assert "Consider setting 'data-directory=<path>' or 'statusfile=<path>/per-slot' explicitly."
    assert "Using per-slot statusfile. System status information not supported!"
    assert (
        f"emmc-boot-linked slots 'bootloader.1' and 'bootloader.0' cannot use the same boot device '{emmc.boot0}'"
        in err
    )


@needs_emmc
def test_write_emmc_boot_linked_force_rw_failure(system):
    """
    Test emmc-boot-linked handler when forcing read-write mode fails.
    """

    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "1", "0", emmc.base_dev])

    # Remove write permissions to simulate failure
    force_ro_path = f"/sys/block/{emmc.boot0[5:]}/force_ro"
    assert os.path.exists(force_ro_path)

    # Make the force_ro file read-only to simulate permission failure
    os.chmod(force_ro_path, 0o444)

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")

    # Restore permissions
    os.chmod(force_ro_path, 0o644)

    assert exitcode != 0
    assert (
        f"Failed to write slot: failed forcing rw: Could not open device attribute {force_ro_path}: Permission denied"
        in err
    )


@needs_emmc
def test_write_emmc_boot_linked_multiple_writes(system):
    """
    Test multiple consecutive writes with emmc-boot-linked handler.
    First write: boot0 active -> migrate boot0→boot1, write to boot0, switch to boot1
    Second write: boot1 active -> write directly to boot0 (inactive), switch to boot0
    """
    emmc = system.prepare_emmc_boot_linked_config()
    system.write_config()

    check_call(["mmc", "bootpart", "enable", "1", "0", emmc.base_dev])

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {emmc.boot0}: boot0" in err
    assert f"Preserving boot partition content by copying from {emmc.boot0} to {emmc.boot1}" in err

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {emmc.boot0}: boot1" in err
    assert f"Preserving boot partition content by copying from {emmc.boot0} to {emmc.boot1}" not in err


@needs_emmc
def test_write_emmc_boot_linked_single_slot_error(system):
    """
    Test emmc-boot-linked handler when only one slot is configured.
    Should fail with appropriate error message since emmc-boot-linked requires both slots.
    """
    device = os.environ["RAUC_TEST_EMMC"]

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    # Configure only one slot - this should cause an error
    system.config["slot.rootfs.0"] = {
        "device": f"{device}p1",
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": f"{device}boot0",
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "Need exactly 2 emmc-boot-linked slots, but found 1" in err
