import time

import pytest
from dasbus.typing import get_native

from conftest import needs_nbd, needs_service
from helper import run

pytestmark = [needs_nbd, needs_service]


def wait_one_poll(system, *, timeout=15.0):
    start = time.monotonic()
    old = system.proxy.NextPoll
    while old == system.proxy.NextPoll:
        time.sleep(0.1)
        assert time.monotonic() < (start + timeout)
    return time.monotonic() - start


def test_no_system_version(create_system_files, system, http_server):
    """Test if polling startup correctly fails because of the missing system version."""
    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
    }
    system.write_config()

    out, err, exitcode = run(f"{system.prefix} service --override-boot-slot=A")

    assert exitcode != 0
    assert "failed to set up polling: system version not provided via system-info handler" in err


def test_polling_only(create_system_files, system, http_server):
    """Test polling without automatic installation."""
    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        slots_initial = get_native(system.proxy.GetSlotStatus())
        status_1 = get_native(system.proxy.Status)

        wait_time_1 = wait_one_poll(system)
        status_2 = get_native(system.proxy.Status)

        wait_time_2 = wait_one_poll(system)

        system.proxy.Poll()
        wait_time_3 = wait_one_poll(system)
        status_3 = get_native(system.proxy.Status)

        slots_final = get_native(system.proxy.GetSlotStatus())

    assert "manifest" not in status_1
    assert wait_time_1 < 60 / 10  # initial delay
    assert status_2["manifest"]["update"]["version"] == "2011.03-2"
    assert status_2["recent-error-count"] == 0
    assert status_2["attempt-count"] == 1
    assert wait_time_2 == pytest.approx(60 / 10, abs=1.5)  # normal poll
    assert wait_time_3 == pytest.approx(30 / 10, abs=1.5)  # poll now
    assert status_3["manifest"] == status_2["manifest"]
    assert status_3["recent-error-count"] == 0
    assert status_3["attempt-count"] == 3
    assert status_3["summary"] == "update candidate found: higher semantic version"

    assert slots_initial == slots_final


def test_no_content(create_system_files, system, http_server):
    """Test if we handle HTTP code 204 correctly."""
    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        wait_one_poll(system)
        status_1 = get_native(system.proxy.Status)
        summary_1 = http_server.get_summary()

        wait_one_poll(system)
        http_server.setup(
            http_code=204,
        )

        wait_one_poll(system)
        status_2 = get_native(system.proxy.Status)
        summary_2 = http_server.get_summary()

    assert status_1["manifest"]["update"]["version"] == "2011.03-2"
    assert status_1["recent-error-count"] == 0
    assert status_1["attempt-count"] == 1
    assert summary_1["requests"] == 3  # initial manifest fetch

    assert status_2["summary"] == "no update bundle available"
    assert not status_2["update-available"]
    assert "manifest" not in status_2
    assert summary_2["requests"] == 1  # only HTTP 204


def test_inhibit(create_system_files, system, http_server, tmp_path):
    """Test if inhibiting via files works correctly."""
    inhibit_1 = tmp_path / "inhibit-1"
    inhibit_2 = tmp_path / "inhibit-2"

    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "inhibit-files": f"{inhibit_1};{inhibit_2}",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        wait_time_1 = wait_one_poll(system)
        inhibit_1.touch()
        summary_1 = http_server.get_summary()

        wait_one_poll(system)
        wait_one_poll(system)
        wait_one_poll(system)

        summary_2 = http_server.get_summary()

        wait_one_poll(system)
        inhibit_1.unlink()
        wait_time_2 = wait_one_poll(system)
        summary_3 = http_server.get_summary()

    assert wait_time_1 < 60 / 10  # initial delay
    assert summary_1["requests"] == 3  # initial request
    assert summary_2["requests"] == 0  # inhibited
    assert summary_3["requests"] == 1  # not modified
    assert wait_time_2 < 15  # short delay


@pytest.mark.parametrize(
    "sys_ver,criteria,result",
    [
        pytest.param("0.1", "different-version", "update candidate found: different version", id="version different"),
        pytest.param("2011.03-2", "different-version", "no update candidate available", id="version unchanged"),
        pytest.param("0.1", "higher-semver", "update candidate found: higher semantic version", id="semver newer"),
        pytest.param("2011.03-2", "higher-semver", "no update candidate available", id="semver unchanged"),
        pytest.param("9999.1", "higher-semver", "no update candidate available", id="semver older"),
    ],
)
def test_candidate_criteria(create_system_files, system, http_server, sys_ver, criteria, result):
    """Test if the different candidate criteria work."""
    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "candidate-criteria": criteria,
    }
    system.write_config()

    env = {"RAUC_TEST_SYSTEM_VERSION": sys_ver}

    with system.running_service("A", polling_speedup=10, extra_env=env):
        system.proxy.Mark("good", "booted")

        slots_initial = get_native(system.proxy.GetSlotStatus())
        wait_one_poll(system)
        status = get_native(system.proxy.Status)
        slots_final = get_native(system.proxy.GetSlotStatus())

    assert status["manifest"]["update"]["version"] == "2011.03-2"
    assert status["recent-error-count"] == 0
    assert status["attempt-count"] == 1
    assert status["summary"] == result

    assert slots_initial == slots_final


@pytest.mark.parametrize(
    "sys_ver,criteria,result",
    [
        pytest.param(
            "2010.01-1",
            ("different-version", "higher-semver"),
            ("update candidate found: different version", True),
            id="semver newer",
        ),
        pytest.param(
            "2022.12-3",
            ("different-version", "different-version"),
            ("update candidate found: different version", True),
            id="version different",
        ),
        pytest.param(
            "2022.12-3",
            ("different-version", "higher-semver"),
            ("update candidate found: different version", False),
            id="semver older",
        ),
        pytest.param(
            "2022.12-3",
            ("different-version", "always"),
            ("update candidate found: different version", True),
            id="always",
        ),
    ],
)
def test_install_criteria(create_system_files, system, http_server, sys_ver, criteria, result):
    """Test if the different install criteria work."""
    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "candidate-criteria": criteria[0],
        "install-criteria": criteria[1],
    }
    system.write_config()

    env = {"RAUC_TEST_SYSTEM_VERSION": sys_ver}

    with system.running_service("A", polling_speedup=10, extra_env=env):
        system.proxy.Mark("good", "booted")

        slots_initial = get_native(system.proxy.GetSlotStatus())
        wait_one_poll(system)
        status = get_native(system.proxy.Status)
        slots_final = get_native(system.proxy.GetSlotStatus())

    assert status["manifest"]["update"]["version"] == "2011.03-2"
    assert status["recent-error-count"] == 0
    assert status["attempt-count"] == 1
    assert status["summary"] == result[0]

    slots_initial = dict(slots_initial)
    slots_final = dict(slots_final)
    assert slots_initial["rootfs.1"].get("installed.count", 0) == 0
    if result[1]:  # installation should have happened
        assert slots_final["rootfs.1"].get("installed.count", 0) == 1
    else:
        assert slots_initial == slots_final


@pytest.mark.parametrize(
    "remove_appfs,criteria,result",
    [
        pytest.param(False, "updated-slots", (True, True), id="updated slots"),
        pytest.param(True, "updated-slots", (False, False), id="updated slots with error"),
        pytest.param(False, "updated-artifacts", (True, False), id="no updated artifacts"),
        pytest.param(True, "failed-update", (False, True), id="bad config"),
    ],
)
def test_reboot_criteria(create_system_files, system, http_server, tmp_path, remove_appfs, criteria, result):
    """Test if the different reboot criteria work."""
    reboot_flag = tmp_path / "reboot-flag"
    assert not reboot_flag.exists()

    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "install-criteria": "always",
        "reboot-criteria": criteria,
        "reboot-cmd": f"touch {reboot_flag}",
    }
    if remove_appfs:
        del system.config["slot.appfs.0"]
        del system.config["slot.appfs.1"]
    system.write_config()

    env = {"RAUC_TEST_SYSTEM_VERSION": "2010.01-1"}

    with system.running_service("A", polling_speedup=10, extra_env=env):
        system.proxy.Mark("good", "booted")

        slots_initial = get_native(system.proxy.GetSlotStatus())
        wait_one_poll(system)
        status = get_native(system.proxy.Status)
        slots_final = get_native(system.proxy.GetSlotStatus())
        time.sleep(5)

    assert status["manifest"]["update"]["version"] == "2011.03-2"
    assert status["recent-error-count"] == 0
    assert status["attempt-count"] == 1

    slots_initial = dict(slots_initial)
    slots_final = dict(slots_final)
    assert slots_initial["rootfs.1"].get("installed.count", 0) == 0
    if result[0]:  # installation should have happened
        assert slots_final["rootfs.1"].get("installed.count", 0) == 1
    else:
        assert slots_initial == slots_final

    assert reboot_flag.exists() == result[1]
