import json

from conftest import have_json, no_service
from helper import run


@no_service
def test_status_no_service():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status")

    assert exitcode == 0
    assert "=== System Info ===" in out


@no_service
def test_status_no_service_output_readable():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status " "--output-format=readable")

    assert exitcode == 0
    assert "=== System Info ===" in out


@no_service
def test_status_no_service_output_shell():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status " "--output-format=shell")

    assert exitcode == 0
    assert "RAUC_SYSTEM_COMPATIBLE='Test Config'" in out


@no_service
@have_json
def test_status_no_service_output_json():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status " "--output-format=json")

    assert exitcode == 0
    assert '"compatible":"Test Config"' in out


@no_service
@have_json
def test_status_no_service_output_json_pretty():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status " "--output-format=json-pretty")

    assert exitcode == 0
    assert '"compatible" : "Test Config"' in out


@no_service
@have_json
def test_status_no_service_output_nvalid():
    out, err, exitcode = run("rauc -c test.conf --override-boot-slot=system0 status " "--output-format=invalid")

    assert exitcode == 1
    assert "Unknown output format: 'invalid'" in err


def test_status(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status")

    assert exitcode == 0
    assert out.startswith("=== System Info ===")


def test_status_readable(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status --detailed --output-format=readable")

    assert exitcode == 0
    assert out.startswith("=== System Info ===")


def test_status_shell(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status --detailed --output-format=shell")

    assert exitcode == 0
    assert out.startswith("RAUC_SYSTEM_COMPATIBLE='Test Config'")


def test_status_json(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status --detailed --output-format=json")

    assert exitcode == 0
    assert json.loads(out)


def test_status_json_pretty(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status --detailed --output-format=json-pretty")

    assert exitcode == 0
    assert json.loads(out)


def test_status_invalid(rauc_service, rauc_dbus_service):
    out, err, exitcode = run("rauc status --detailed --output-format=invalid")

    assert exitcode == 1
    assert "Unknown output format" in err
