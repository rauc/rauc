import json
import os

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
