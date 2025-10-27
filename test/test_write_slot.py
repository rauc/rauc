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
