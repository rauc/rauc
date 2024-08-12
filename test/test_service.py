from helper import run


def test_service_double_init(rauc_dbus_service, tmp_path):
    out, err, exitcode = run(f"rauc --conf={tmp_path / 'system.conf'} --override-boot-slot=system0 service")

    assert exitcode == 1
    assert "Failed to obtain name de.pengutronix.rauc on session bus" in err
