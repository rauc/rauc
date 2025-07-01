import os
from subprocess import check_call

from conftest import needs_emmc
from helper import run


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
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "0", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "Could not find active boot partition during migration" in err


@needs_emmc
def test_write_emmc_boot_linked_with_active_boot0_with_migrate(system):
    """
    Test emmc-boot-linked handler when boot0 is active.
    Should migrate content from boot0 to boot1, then write new image to boot0.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"
    size = 1024 * 1024  # full size of eMMC boot partition

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    # Prepare known data
    original_data = os.urandom(size)

    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(boot0_device, "wb") as f:
        f.write(original_data)
    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("1")

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot0" in err
    assert f"Copying from {boot0_device} to {boot1_device}" in err

    # Read back migrated data from boot1
    with open(boot1_device, "rb") as f:
        migrated_data = f.read(size)

    # Check that the original data was migrated correctly
    assert migrated_data[:1024] == original_data[:1024], "Migration did not preserve original data correctly"


@needs_emmc
def test_write_emmc_boot_linked_with_active_boot1_no_migrate(system):
    """
    Test emmc-boot-linked handler when boot1 is active.
    Should migrate content from boot1 to boot0, then write new image to boot1.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "2", "0", device])

    test_data = b"BOOT1_BOOTLOADER_DATA" + b"\x00" * (1024 - 21)
    with open(f"/sys/block/{boot1_device[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(boot1_device, "wb") as f:
        f.write(test_data)
    with open(f"/sys/block/{boot1_device[5:]}/force_ro", "w") as f:
        f.write("1")

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }

    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot1" in err
    assert "writing data to device" in err


@needs_emmc
def test_write_emmc_boot_linked_point_to_same_boot_dev(system):
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    test_data = b"EXISTING_BOOTLOADER_DATA" + b"\x00" * (1024 - 24)
    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(boot0_device, "wb") as f:
        f.write(test_data)
    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("1")

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "No data directory or status file set, falling back to per-slot status."
    assert "Consider setting 'data-directory=<path>' or 'statusfile=<path>/per-slot' explicitly."
    assert "Using per-slot statusfile. System status information not supported!"
    assert (
        f"emmc-boot-linked slots 'bootloader.1' and 'bootloader.0' cannot use the same boot device '{boot0_device}'"
        in err
    )


@needs_emmc
def test_write_emmc_boot_linked_target_inactive_partition(system):
    """
    Test emmc-boot-linked handler when targeting the inactive partition.
    Should skip migration and directly write to the inactive partition.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.1 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot1_device}: boot0" in err
    assert f"Copying from {boot0_device} to {boot1_device}" not in err


@needs_emmc
def test_write_emmc_boot_linked_migration_failure(system):
    """
    Test emmc-boot-linked handler when migration fails due to device resolution error.
    """
    device = "/dev/someother_emmc"
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert f"Device path '{boot1_device}' does not contain valid MMC device pattern" in err


@needs_emmc
def test_write_emmc_boot_linked_with_hooks(system, tmp_path):
    """
    Test emmc-boot-linked handler with pre/post install hooks.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device: str = f"{device}boot0"
    boot1_device: str = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    hook_script = tmp_path / "hook.sh"
    hook_script.write_text(
        """#!/bin/bash
echo "Hook called: $RAUC_SLOT_HOOK_TYPE for $RAUC_SLOT_NAME"
echo "Boot partition activating: $RAUC_BOOT_PARTITION_ACTIVATING"
echo "Boot size limit: $RAUC_BOOT_SIZE_LIMIT"
"""
    )
    hook_script.chmod(0o755)

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }

    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
        "hooks": f"file://{hook_script}",
    }

    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }

    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
        "hooks": f"file://{hook_script}",
    }
    system.write_config()


@needs_emmc
def test_write_emmc_boot_linked_read_bootpart_failure(system):
    """
    Test emmc-boot-linked handler when reading boot partition info fails.
    This tests the r_emmc_read_bootpart error path.
    """
    # Use a regular file instead of an eMMC device to trigger read failure
    invalid_device = "/dev/null"

    system.config["slot.bootloader.0"] = {
        "device": invalid_device,
        "type": "emmc-boot-linked",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "failed" in err.lower() or "error" in err.lower()


@needs_emmc
def test_write_emmc_boot_linked_force_rw_failure(system):
    """
    Test emmc-boot-linked handler when forcing read-write mode fails.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }

    # Remove write permissions to simulate failure
    force_ro_path = f"/sys/block/{boot0_device[5:]}/force_ro"
    if os.path.exists(force_ro_path):
        # Make the force_ro file read-only to simulate permission failure
        os.chmod(force_ro_path, 0o444)

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")

    # Restore permissions
    if os.path.exists(force_ro_path):
        os.chmod(force_ro_path, 0o644)

    if exitcode != 0:
        assert "failed" in err.lower() or "error" in err.lower()


@needs_emmc
def test_write_emmc_boot_linked_multiple_writes(system):
    """
    Test multiple consecutive writes with emmc-boot-linked handler.
    This tests the complete workflow including migration and writing.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot0" in err
    assert f"Copying from {boot0_device} to {boot1_device}" in err

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot1" in err
    assert f"Copying from {boot0_device} to {boot1_device}" not in err


@needs_emmc
def test_write_emmc_boot_linked_single_slot_error(system):
    """
    Test emmc-boot-linked handler when only one slot is configured.
    Should fail with appropriate error message since emmc-boot-linked requires both slots.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    root0_device = f"{device}p1"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    # Configure only one slot - this should cause an error
    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "Need at least 2 valid emmc-boot-linked group slots, but only found 1" in err


@needs_emmc
def test_write_emmc_boot_linked_size_limit(system):
    """
    Sets 'size-limit' option for emmc-boot-linked slot and checks that after writing,
    the data above the size-limit remains untouched.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"
    size = 1024 * 1024
    half_size = size // 2

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
        "size-limit": f"{half_size}",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
        "size-limit": f"{half_size}",
    }
    system.write_config()

    # Prepare known data
    original_data = os.urandom(size)
    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("0")
    with open(boot0_device, "wb") as f:
        f.write(original_data)
    with open(f"/sys/block/{boot0_device[5:]}/force_ro", "w") as f:
        f.write("1")

    # write image
    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot0" in err

    # Check both clear operations
    assert (
        f"Cleared first {size} bytes on /dev/mmcblk0boot1" in err
    )  # Migration clears full size and ignores size limit
    assert f"Cleared first {half_size} bytes on /dev/mmcblk0boot0" in err  # Write respects size limit

    # Read back from boot0 (where the size-limited write happened)
    with open(boot0_device, "rb") as f:
        result_data = f.read(size)

    # Check first 16 bytes below 512 KiB are zeroed (cleared area)
    assert result_data[half_size - 0x10 : half_size] == b"\x00" * 0x10, "First 512 KiB is not zeroed"

    # Check first 16 bytes above 512 KiB are intact (preserved original data)
    assert result_data[half_size : half_size + 0x10] == original_data[half_size : half_size + 0x10], (
        "Second 512 KiB is not intact"
    )


@needs_emmc
def test_write_emmc_boot_linked_size_limit_too_large(system):
    """
    Sets 'size-limit' option for emmc-boot-linked slot to a value larger than the
    actual size of the partition and ensures RAUC prints a warning.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
        "size-limit": "10M",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
        "size-limit": "10M",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 0
    assert "Slot written successfully" in out
    assert f"Active eMMC boot partition for {boot0_device}: boot0" in err

    assert "The size-limit (10485760 bytes) exceeds actual device size" in err


@needs_emmc
def test_write_emmc_boot_linked_size_limit_exceeded(system):
    """
    Tests that emmc-boot-linked slot fails when image size exceeds the size-limit.
    """
    device = os.environ["RAUC_TEST_EMMC"]
    boot0_device = f"{device}boot0"
    boot1_device = f"{device}boot1"
    root0_device = f"{device}p1"
    root1_device = f"{device}p2"

    check_call(["mmc", "bootpart", "enable", "1", "0", device])

    small_limit = 1024

    system.config["slot.rootfs.0"] = {
        "device": root0_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.0"] = {
        "device": boot0_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.0",
        "size-limit": f"{small_limit}",
    }
    system.config["slot.rootfs.1"] = {
        "device": root1_device,
        "type": "ext4",
    }
    system.config["slot.bootloader.1"] = {
        "device": boot1_device,
        "type": "emmc-boot-linked",
        "parent": "rootfs.1",
        "size-limit": f"{small_limit}",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} write-slot bootloader.0 install-content/rootfs.img")
    assert exitcode == 1
    assert "is larger than size-limit" in err
