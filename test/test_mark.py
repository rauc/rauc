import copy
import json
import os

import pytest

from conftest import have_grub, have_qemu, no_service
from helper import run
from helper import slot_data_from_json


@no_service
@have_grub
def test_status_mark_good_internally(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-good")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_bad_internally(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-bad")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_active_internally(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-active")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_good_booted(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-good booted")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_good_other(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-good other")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_good_any_bootslot(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-good rescue.0")

    assert exitcode == 0


@no_service
@have_grub
def test_status_mark_good_non_bootslot(rauc_no_service):
    out, err, exitcode = run(f"{rauc_no_service} --override-boot-slot=A status mark-good bootloader.0")

    assert exitcode == 1


@have_grub
def test_status_mark_bad_other(rauc_dbus_service_with_system_abc):
    out, err, exitcode = run("rauc status --output-format=json")
    assert exitcode == 0
    status = json.loads(out)

    for slotname, property in status["slots"][0].items():
        if property["state"] != "booted" and property["class"] == "rootfs":
            assert property["boot_status"] == "good"

    out, err, exitcode = run("rauc status mark-bad other")
    assert exitcode == 0

    out, err, exitcode = run("rauc status --output-format=json")
    assert exitcode == 0
    status = json.loads(out)

    for slotname, property in status["slots"][0].items():
        if property["state"] != "booted" and property["class"] == "rootfs":
            assert property["boot_status"] == "bad"


@have_grub
def test_status_mark_prevent_late_fallback(tmp_path, create_system_files, system):
    system.prepare_abc_config()
    system.config["system"]["prevent-late-fallback"] = "true"
    system.write_config()
    with system.running_service("A"):
        out, err, exitcode = run("rauc status --output-format=json")
        assert exitcode == 0
        status = json.loads(out)

        for slotname, property in status["slots"][0].items():
            if property["state"] != "booted" and property["class"] == "rootfs":
                assert property["boot_status"] == "good"

        out, err, exitcode = run("rauc status mark-good")
        assert exitcode == 0

        out, err, exitcode = run("rauc status --output-format=json")
        assert exitcode == 0
        status = json.loads(out)

        for slotname, property in status["slots"][0].items():
            if property["state"] != "booted" and property["class"] == "rootfs":
                assert property["boot_status"] == "bad"


@have_grub
def test_status_mark_good_dbus(rauc_dbus_service_with_system):
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"

    out, err, exitcode = run("rauc status mark-good")

    assert exitcode == 0
    assert "marked slot(s) rootfs.0 as good" in out

    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"


@have_grub
def test_status_mark_bad_dbus(rauc_dbus_service_with_system):
    # check pre-condition
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"

    # mark bad
    out, err, exitcode = run("rauc status mark-bad")

    assert exitcode == 0
    assert "marked slot(s) rootfs.0 as bad" in out

    # check post-condition
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "bad"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"


@have_grub
def test_status_mark_active_dbus(rauc_dbus_service_with_system):
    # check pre-condition
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "bad"
    assert status_data["boot_primary"] == "rootfs.0"

    # mark active other
    out, err, exitcode = run("rauc status mark-active other")

    assert exitcode == 0
    assert "rootfs.1 as active" in out

    # check post-condition
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0
    status_data = json.loads(out)

    assert slot_data_from_json(status_data, "rootfs.0")["boot_status"] == "good"
    assert slot_data_from_json(status_data, "rootfs.1")["boot_status"] == "good"
    assert status_data["boot_primary"] == "rootfs.1"


@have_qemu
def test_status_mark_bad_barebox(tmp_path, create_system_files, system):
    """
    Tests that 'mark-bad' call for barebox alters the barebox state
    variables appropriately.

    Leverages the 'barebox-state' dummy with variables pre-set from env.
    """

    system.prepare_minimal_config()
    system.config["system"]["bootloader"] = "barebox"
    del system.config["system"]["grubenv"]
    system.write_config()
    os.environ["BAREBOX_STATE_VARS_PRE"] = """
bootstate.A.priority=20
bootstate.B.priority=21
bootstate.A.remaining_attempts=3
bootstate.B.remaining_attempts=3
"""
    os.environ["BAREBOX_STATE_VARS_POST"] = """
bootstate.A.priority=20
bootstate.B.priority=0
bootstate.A.remaining_attempts=3
bootstate.B.remaining_attempts=0
"""
    with system.running_service("A"):
        # mark rootfs.1 (B) bad
        out, err, exitcode = run("rauc status mark-bad rootfs.1")
        assert not err
        assert exitcode == 0


@have_qemu
def test_status_mark_active_barebox(tmp_path, create_system_files, system):
    """
    Tests that 'mark-primary' call for barebox alters the barebox state
    variables appropriately.

    Leverages the 'barebox-state' dummy with variables pre-set from env.
    """

    system.prepare_minimal_config()
    system.config["system"]["bootloader"] = "barebox"
    del system.config["system"]["grubenv"]
    system.write_config()
    os.environ["BAREBOX_STATE_VARS_PRE"] = """
bootstate.A.priority=21
bootstate.B.priority=20
bootstate.A.remaining_attempts=3
bootstate.B.remaining_attempts=0
"""
    os.environ["BAREBOX_STATE_VARS_POST"] = """
bootstate.A.priority=10
bootstate.B.priority=20
bootstate.A.remaining_attempts=3
bootstate.B.remaining_attempts=3
"""
    with system.running_service("A"):
        # mark rootfs.1 (B) active/primary
        out, err, exitcode = run("rauc status mark-active rootfs.1")
        assert not err
        assert exitcode == 0


EFI_INITIAL_STATE = {
    "boot_current": "0000",
    "timeout": 0,
    "boot_order": ["0000", "0001"],
    "boot_next": None,
    "boot_entries": {"0000": {"label": "A"}, "0001": {"label": "B"}},
}


@pytest.fixture
def efi_mock(monkeypatch):
    monkeypatch.setenv("PATH", os.path.abspath("bin"), prepend=os.pathsep)


def create_efi_system_config(system, blk_dev_partitions, *, configure_efi_entry=False):
    system.prepare_minimal_config()
    system.config["system"]["bootloader"] = "efi"
    del system.config["system"]["grubenv"]

    system.config["slot.rootfs.0"]["device"] = next(blk_dev_partitions)
    system.config["slot.rootfs.1"]["device"] = next(blk_dev_partitions)

    if configure_efi_entry:
        system.config["slot.rootfs.0"]["efi-loader"] = r"\\EFI\\BOOT\\BOOTX64.EFI"
        system.config["slot.rootfs.0"]["efi-cmdline"] = "@1"
        system.config["slot.rootfs.1"]["efi-loader"] = r"\\EFI\\BOOT\\BOOTX64.EFI"
        system.config["slot.rootfs.1"]["efi-cmdline"] = "@2"

    system.write_config()


@have_qemu
@pytest.mark.parametrize("efi_entry_missing", [False, True], ids=["efi_entry_exists", "efi_entry_missing"])
def test_status_mark_good_efi(tmp_path, create_system_files, system, efi_mock, blk_dev_partitions, efi_entry_missing):
    """
    Tests that 'mark-good' call for EFI does not alter boot order and a missing matching EFI boot
    entry (efi-loader/efi-cmdline configured) is recreated.

    Leverages the mock efibootmgr with JSON storage mode.
    """
    create_efi_system_config(system, blk_dev_partitions, configure_efi_entry=efi_entry_missing)

    # Create JSON file with initial EFI boot state
    efi_state = copy.deepcopy(EFI_INITIAL_STATE)
    if efi_entry_missing:
        # Delete boot entry 0000 for system A
        del efi_state["boot_entries"]["0000"]
        efi_state["boot_order"].remove("0000")

    efi_vars_file = tmp_path / "efi_vars.json"
    efi_vars_file.write_text(json.dumps(efi_state))
    os.environ["EFIBOOTMGR_VAR_FILE"] = str(efi_vars_file)

    with system.running_service("A"):
        # mark rootfs.0 (A) good
        _, err, exitcode = run("rauc status mark-good rootfs.0")
        assert not err
        assert exitcode == 0

        # Verify EFI state is unchanged:
        # efi_entry_missing=False: mark-good doesn't modify boot order,
        # efi_entry_missing=True: boot entry is created with the same number as before and
        #                         mark-good puts it back in boot order
        result_state = json.loads(efi_vars_file.read_text())
        assert result_state == EFI_INITIAL_STATE


@have_qemu
@pytest.mark.parametrize("efi_entry_missing", [False, True], ids=["efi_entry_exists", "efi_entry_missing"])
def test_status_mark_bad_efi(tmp_path, create_system_files, system, efi_mock, blk_dev_partitions, efi_entry_missing):
    """
    Tests that 'mark-bad' call for EFI removes slot from boot order and a missing matching EFI boot
    entry (efi-loader/efi-cmdline configured) is recreated.

    Leverages the mock efibootmgr with JSON storage mode.
    """
    create_efi_system_config(system, blk_dev_partitions, configure_efi_entry=efi_entry_missing)

    # Create JSON file with initial EFI boot state
    efi_state = copy.deepcopy(EFI_INITIAL_STATE)
    if efi_entry_missing:
        # Delete boot entry 0001 for system B
        del efi_state["boot_entries"]["0001"]
        efi_state["boot_order"].remove("0001")

    efi_vars_file = tmp_path / "efi_vars.json"
    efi_vars_file.write_text(json.dumps(efi_state))
    os.environ["EFIBOOTMGR_VAR_FILE"] = str(efi_vars_file)

    with system.running_service("A"):
        # mark rootfs.1 (B) bad
        _, err, exitcode = run("rauc status mark-bad rootfs.1")
        assert not err
        assert exitcode == 0

        result_state = json.loads(efi_vars_file.read_text())
        # Verify system B (0001) was removed from boot order
        assert result_state["boot_order"] == ["0000"]
        # Everything else should be unchanged
        assert result_state["boot_entries"] == EFI_INITIAL_STATE["boot_entries"]
        assert result_state["boot_next"] == EFI_INITIAL_STATE["boot_next"]


@have_qemu
@pytest.mark.parametrize("efi_entry_missing", [False, True], ids=["efi_entry_exists", "efi_entry_missing"])
def test_status_mark_active_efi(
    tmp_path, create_system_files, system, efi_mock, blk_dev_partitions, efi_entry_missing
):
    """
    Tests that 'mark-active' call for EFI moves slot to primary position in boot order and a
    missing matching EFI boot entry (efi-loader/efi-cmdline configured) is recreated.

    Leverages the mock efibootmgr with JSON storage mode.
    """
    create_efi_system_config(system, blk_dev_partitions, configure_efi_entry=efi_entry_missing)

    # Create JSON file with initial EFI boot state
    efi_state = copy.deepcopy(EFI_INITIAL_STATE)
    if efi_entry_missing:
        # Delete boot entry 0001 for system B
        del efi_state["boot_entries"]["0001"]
        efi_state["boot_order"].remove("0001")

    efi_vars_file = tmp_path / "efi_vars.json"
    efi_vars_file.write_text(json.dumps(efi_state))
    os.environ["EFIBOOTMGR_VAR_FILE"] = str(efi_vars_file)

    with system.running_service("A"):
        # mark rootfs.1 (B) active/primary
        _, err, exitcode = run("rauc status mark-active rootfs.1")
        assert not err
        assert exitcode == 0

        result_state = json.loads(efi_vars_file.read_text())
        # Verify system B (0001) set as BootNext
        assert result_state["boot_next"] == "0001"
        # Everything else should be unchanged
        assert result_state["boot_order"] == EFI_INITIAL_STATE["boot_order"]
        assert result_state["boot_entries"] == EFI_INITIAL_STATE["boot_entries"]


@have_qemu
def test_status_mark_efi_missing_unconfigured_boot_entry(
    tmp_path, create_system_files, system, blk_dev_partitions, efi_mock
):
    """
    Tests that mark calls for a slot without corresponding EFI boot entry and without
    efi-loader/efi-cmdline fail as expected and the EFI boot entries are untouched.

    Leverages the mock efibootmgr with JSON storage mode.
    """
    create_efi_system_config(system, blk_dev_partitions, configure_efi_entry=False)

    # create JSON file with initial EFI boot state
    efi_state = copy.deepcopy(EFI_INITIAL_STATE)
    # Delete boot entry 0000 for system A
    del efi_state["boot_entries"]["0000"]
    efi_state["boot_order"].remove("0000")

    efi_vars_file = tmp_path / "efi_vars.json"
    efi_vars_file.write_text(json.dumps(efi_state))
    os.environ["EFIBOOTMGR_VAR_FILE"] = str(efi_vars_file)

    with system.running_service("A"):
        # mark rootfs.0 (A) good without a corresponding boot entry
        _, err, exitcode = run("rauc status mark-good rootfs.0")
        assert (
            err.strip()
            == "rauc mark: Failed marking slot rootfs.0 as good:  efi backend: Did not find efi entry for bootname 'A'!"
        )
        assert exitcode == 1

        result_state = json.loads(efi_vars_file.read_text())
        # EFI state should be unchanged
        assert result_state == efi_state

        # mark rootfs.0 (A) bad without a corresponding boot entry
        _, err, exitcode = run("rauc status mark-bad rootfs.0")
        assert (
            err.strip()
            == "rauc mark: Failed marking slot rootfs.0 as bad:  efi backend: Did not find efi entry for bootname 'A'!"
        )
        assert exitcode == 1

        result_state = json.loads(efi_vars_file.read_text())
        # EFI state should be unchanged
        assert result_state == efi_state

        # mark rootfs.0 (A) active without a corresponding boot entry
        _, err, exitcode = run("rauc status mark-active rootfs.0")
        assert (
            err.strip()
            == "rauc mark: failed to activate slot rootfs.0: efi backend: Did not find efi entry for bootname 'A'!"
        )
        assert exitcode == 1

        result_state = json.loads(efi_vars_file.read_text())
        # EFI state should be unchanged
        assert result_state == efi_state
