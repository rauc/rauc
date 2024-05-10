from helper import run


def test_service_double_init(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc --conf=test.conf --override-boot-slot=system0 service")

    assert exitcode == 1
    assert "Failed to obtain name de.pengutronix.rauc on session bus" in err
