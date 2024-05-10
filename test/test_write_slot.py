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
