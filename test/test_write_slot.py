from helper import run


def test_write_slot_invalid_local_paths():
    out, err, exitcode = run("rauc -c test.conf write-slot system0 foo")
    assert exitcode == 1
    assert "No such file or directory" in err

    out, err, exitcode = run("rauc -c test.conf write-slot system0 foo.raucb")
    assert exitcode == 1
    assert "No such file or directory" in err

    out, err, exitcode = run("rauc -c test.conf write-slot system0 /path/to/foo.raucb")
    assert exitcode == 1
    assert "No such file or directory" in err


def test_write_slot_invalid_slot():
    out, err, exitcode = run("rauc -c test.conf write-slot systemx install-content/rootfs.img")
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
