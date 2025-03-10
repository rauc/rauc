import json
import uuid

import pytest
from dasbus.typing import get_native, get_variant

from conftest import have_json, have_service
from helper import run


def test_backend_range(http_server):
    """Test if the backend returns the range parameters correctly."""
    http_server.setup(
        file_path="test/good-verity-bundle.raucb",
    )

    resp = http_server.get(headers={"Range": "bytes=0-3"})
    resp.raise_for_status()
    assert resp.status_code == 206
    assert resp.content == b"hsqs"

    summary = http_server.get_summary()
    assert summary["requests"] == 1
    assert summary["range_requests"] == ["0:4"]


def test_backend_headers(http_server):
    """Test if the backend returns the request headers correctly."""
    http_server.setup(
        file_path="test/good-verity-bundle.raucb",
    )

    resp = http_server.head(headers={"RAUC-Test": "value"})
    resp.raise_for_status()
    assert resp.status_code == 200

    summary = http_server.get_summary()
    assert summary["requests"] == 1
    assert summary["first_request_headers"].get("RAUC-Test") == "value"


def prune_standard_headers(headers):
    for k in ["Host", "X-Forwarded-For", "Connection", "Accept", "User-Agent"]:
        try:
            del headers[k]
        except KeyError:
            pass


def is_uuid(value):
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def is_uptime(value):
    try:
        float(value)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("api", ["cli", "dbus"])
@have_json
def test_info_headers(create_system_files, system, http_server, api):
    """Test if the info command sends custom headers correctly."""
    if api == "dbus" and not have_service():
        pytest.skip("Missing service")

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "boot-id;machine-id;system-version;serial;variant;transaction-id;uptime",
    }
    system.write_config()
    http_server.setup(
        file_path="test/good-verity-bundle.raucb",
    )

    if api == "cli":
        out, err, exitcode = run(
            f"{system.prefix} info {http_server.url} --output-format=json -H 'Test-Header: Test-Value'"
        )
        assert exitcode == 0
        info = json.loads(out)
        assert info["compatible"] == "Test Config"
    elif api == "dbus":
        with system.running_service("A"):
            info = system.proxy.InspectBundle(
                http_server.url,
                {
                    "http-headers": get_variant("as", ["Test-Header: Test-Value"]),
                },
            )
        info = get_native(info)
        assert info["update"]["compatible"] == "Test Config"

    summary = http_server.get_summary()
    assert summary["requests"] == 3

    first_headers = summary["first_request_headers"]
    assert first_headers.pop("User-Agent").startswith("rauc/")
    assert is_uuid(first_headers.pop("RAUC-Boot-ID"))
    assert is_uuid(first_headers.pop("RAUC-Machine-ID"))
    assert is_uptime(first_headers.pop("RAUC-Uptime"))
    prune_standard_headers(first_headers)
    assert first_headers == {
        "Range": "bytes=0-3",
        "Test-Header": "Test-Value",
        "RAUC-Serial": "1234",
        "RAUC-System-Version": "1.0.0",
        "RAUC-Variant": "test-variant-x",
    }

    second_headers = summary["second_request_headers"]
    prune_standard_headers(second_headers)
    assert second_headers == {
        "Range": "bytes=26498-26505",
        "Test-Header": "Test-Value",
    }

    assert summary["range_requests"] == [
        "0:4",  # magic
        "26498:26506",  # CMS size
        "24576:26498",  # CMS data
    ]
