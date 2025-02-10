import json

from conftest import have_json
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


@have_json
def test_info_headers(create_system_files, system, http_server):
    """Test if the info command sends custom headers correctly."""
    system.prepare_minimal_config()
    system.write_config()
    http_server.setup(
        file_path="test/good-verity-bundle.raucb",
    )

    out, err, exitcode = run(
        f"{system.prefix} info {http_server.url} --output-format=json -H 'Test-Header: Test-Value'"
    )
    assert exitcode == 0
    info = json.loads(out)
    assert info["compatible"] == "Test Config"

    summary = http_server.get_summary()
    assert summary["requests"] == 3

    headers = summary["first_request_headers"]
    assert headers["User-Agent"].startswith("rauc/")
    for k in ["Host", "X-Forwarded-For", "Connection", "Accept", "User-Agent"]:
        del headers[k]
    assert headers == {
        "Range": "bytes=0-3",
        "Test-Header": "Test-Value",
    }

    assert summary["range_requests"] == [
        "0:4",  # magic
        "26498:26506",  # CMS size
        "24576:26498",  # CMS data
    ]
