import os
import signal
import subprocess
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


def wait_until(condition, *, timeout=15.0):
    start = time.monotonic()
    while True:
        result = condition()
        if result:
            return result
        time.sleep(0.1)
        assert time.monotonic() < (start + timeout)


def status_without_manifest(system):
    status = get_native(system.proxy.Status)
    return status if "manifest" not in status else None


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


def test_sighup_reload_accepted(create_system_files, system, http_server):
    """Test if SIGHUP accepts polling-only changes and clears stale status."""
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
        "candidate-criteria": "higher-semver",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        wait_one_poll(system)
        status_1 = get_native(system.proxy.Status)
        assert status_1["summary"] == "update candidate found: higher semantic version"
        assert "manifest" in status_1

        system.config["polling"]["candidate-criteria"] = "different-version"
        system.write_config()
        os.kill(system.service.pid, signal.SIGHUP)

        status_2 = wait_until(lambda: status_without_manifest(system))
        assert "summary" not in status_2
        assert status_2["recent-error-count"] == 0

        system.proxy.Poll()
        wait_one_poll(system)
        status_3 = get_native(system.proxy.Status)
        last_error = system.proxy.LastError

    assert status_3["summary"] == "update candidate found: different version"
    assert "manifest" in status_3
    assert last_error == ""


def test_sighup_reload_rejected(create_system_files, system, http_server):
    """Test if SIGHUP rejects non-polling changes and leaves old polling active."""
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
        "candidate-criteria": "higher-semver",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        wait_one_poll(system)
        status_1 = get_native(system.proxy.Status)
        assert status_1["summary"] == "update candidate found: higher semantic version"

        system.config["system"]["compatible"] = "Changed Config"
        system.config["polling"]["candidate-criteria"] = "different-version"
        system.write_config()
        os.kill(system.service.pid, signal.SIGHUP)

        wait_until(lambda: "non-polling" in system.proxy.LastError)
        system.proxy.Poll()
        wait_one_poll(system)
        status_2 = get_native(system.proxy.Status)

    assert status_2["summary"] == "update candidate found: higher semantic version"


def test_sighup_reload_deferred(create_system_files, system, http_server, tmp_path):
    """Test if SIGHUP during polling installation is deferred until idle."""
    marker = tmp_path / "preinstall-started"
    preinstall = tmp_path / "sleep-preinstall.sh"
    preinstall.write_text(f"#!/bin/sh\ntouch {marker}\nsleep 3\n")
    preinstall.chmod(0o755)

    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
        "pre-install": str(preinstall),
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "candidate-criteria": "higher-semver",
        "install-criteria": "always",
    }
    system.write_config()

    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        wait_until(marker.exists, timeout=20.0)
        assert system.proxy.Operation == "installing"

        system.config["polling"] = {
            "url": http_server.url,
            "interval-sec": "60",
            "candidate-criteria": "different-version",
        }
        system.write_config()
        os.kill(system.service.pid, signal.SIGHUP)

        wait_until(lambda: system.proxy.Operation == "idle", timeout=20.0)
        status_1 = wait_until(lambda: status_without_manifest(system))

        system.proxy.Poll()
        wait_one_poll(system)
        status_2 = get_native(system.proxy.Status)

    assert "summary" not in status_1
    assert status_2["summary"] == "update candidate found: different version"


def test_sighup_reload_preserves_pending_reboot(create_system_files, system, http_server, tmp_path):
    """Test if accepted SIGHUP reloads keep a pending polling reboot."""
    marker = tmp_path / "preinstall-started"
    preinstall = tmp_path / "sleep-preinstall.sh"
    preinstall.write_text(f"#!/bin/sh\ntouch {marker}\nsleep 1\n")
    preinstall.chmod(0o755)
    reboot_flag = tmp_path / "reboot-flag"

    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
        "pre-install": str(preinstall),
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "install-criteria": "always",
        "reboot-criteria": "updated-slots",
        "reboot-cmd": f"touch {reboot_flag}",
    }
    system.write_config()

    env = {"RAUC_TEST_SYSTEM_VERSION": "2010.01-1"}

    with system.running_service("A", polling_speedup=5, extra_env=env):
        system.proxy.Mark("good", "booted")

        wait_until(marker.exists, timeout=20.0)
        wait_until(lambda: system.proxy.Operation == "idle", timeout=20.0)
        assert not reboot_flag.exists()

        system.config["polling"]["candidate-criteria"] = "different-version"
        system.write_config()
        os.kill(system.service.pid, signal.SIGHUP)

        status_after_reload = wait_until(lambda: status_without_manifest(system), timeout=10.0)
        wait_until(reboot_flag.exists, timeout=20.0)
        last_error = system.proxy.LastError

    assert "summary" not in status_after_reload
    assert last_error == ""


def test_sighup_reload_deferred_dbus_install(create_system_files, system, http_server, tmp_path):
    """Test if SIGHUP during a D-Bus-triggered install is drained when idle."""
    marker = tmp_path / "preinstall-started"
    preinstall = tmp_path / "sleep-preinstall.sh"
    preinstall.write_text(f"#!/bin/sh\ntouch {marker}\nsleep 3\n")
    preinstall.chmod(0o755)

    http_server.setup(
        file_path="good-verity-bundle.raucb",
    )

    system.prepare_minimal_config()
    system.config["handlers"] = {
        "system-info": "bin/systeminfo.sh",
        "pre-install": str(preinstall),
    }
    system.config["streaming"] = {
        "send-headers": "system-version;transaction-id",
    }
    system.config["polling"] = {
        "url": http_server.url,
        "interval-sec": "60",
        "candidate-criteria": "higher-semver",
    }
    system.write_config()

    install = None
    with system.running_service("A", polling_speedup=10):
        system.proxy.Mark("good", "booted")

        system.proxy.Poll()
        wait_one_poll(system)
        status_1 = get_native(system.proxy.Status)
        assert status_1["summary"] == "update candidate found: higher semantic version"

        install_env = os.environ.copy()
        install_env["RAUC_PYTEST_TMP"] = str(system.tmp_path)
        install = subprocess.Popen(
            ["rauc", "-c", str(system.output), "install", os.path.abspath("good-verity-bundle.raucb")],
            env=install_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_until(marker.exists, timeout=20.0)
            assert system.proxy.Operation == "installing"

            system.config["polling"]["candidate-criteria"] = "different-version"
            system.write_config()
            os.kill(system.service.pid, signal.SIGHUP)

            wait_until(lambda: system.proxy.Operation == "idle", timeout=20.0)
            out, err = install.communicate(timeout=10.0)
            assert install.returncode == 0, f"{out}\n{err}"
            status_2 = wait_until(lambda: status_without_manifest(system), timeout=20.0)

            system.proxy.Poll()
            wait_one_poll(system)
            status_3 = get_native(system.proxy.Status)
        finally:
            if install.poll() is None:
                install.terminate()
                install.wait(timeout=10.0)

    assert "summary" not in status_2
    assert status_3["summary"] == "update candidate found: different version"


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
