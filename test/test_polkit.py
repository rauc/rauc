import os
import shutil
import signal
import subprocess
import threading
import time
from contextlib import contextmanager

import pytest
from dasbus.connection import SessionMessageBus
from dasbus.error import DBusError
from dasbus.typing import Bool, List, Str, get_native, get_variant

from conftest import UNPRIVILEGED_ID, have_streaming, needs_polkit, root, unprivileged_bus

pytestmark = needs_polkit

# Arguments that choose how a bundle is downloaded
ACCESS_ARGS = [
    pytest.param("tls-no-verify", get_variant(Bool, True), id="tls-no-verify"),
    pytest.param("tls-cert", get_variant(Str, "/etc/shadow"), id="tls-cert"),
    pytest.param("tls-key", get_variant(Str, "pkcs11:token=any"), id="tls-key"),
    pytest.param("tls-ca", get_variant(Str, "/tmp/ca.pem"), id="tls-ca"),
    pytest.param("http-headers", get_variant(List[Str], ["X-Any: value"]), id="http-headers"),
]

# Arguments that need the install-override action
INSTALL_OVERRIDES = [
    pytest.param("ignore-compatible", get_variant(Bool, True), id="ignore-compatible"),
    pytest.param("ignore-version-limit", get_variant(Bool, True), id="ignore-version-limit"),
    pytest.param("transaction-id", get_variant(Str, "x\r\nX-Injected: 1"), id="transaction-id"),
    *ACCESS_ARGS,
]


@pytest.fixture(autouse=True)
def unprivileged_caller(system):
    """Call the service as an unprivileged user, as root is allowed without asking polkit."""
    system.unprivileged = True


@pytest.fixture
def bundle_path(tmp_path):
    shutil.copyfile("good-verity-bundle.raucb", tmp_path / "good-verity-bundle.raucb")
    return str(tmp_path / "good-verity-bundle.raucb")


def slot_written(path):
    return path.exists() and path.stat().st_size > 0


def wait_idle(proxy):
    """Wait for an install the service accepted to end, and return its error."""
    timeout = time.monotonic() + 30.0
    while proxy.Operation != "idle":
        assert time.monotonic() < timeout, "install did not finish"
        time.sleep(0.1)
    return proxy.LastError


def slot_status(status, version, bundle="b1"):
    return {"status": status, "bundle.version": version, "bundle.hash": bundle}


def group_status(status, version, bundle="b1"):
    return {"rootfs.1": slot_status(status, version, bundle), "appfs.1": slot_status(status, version, bundle)}


def write_central_status(tmp_path, status):
    """Write the central status file of the minimal config, as {slot name: {key: value}}."""
    os.makedirs(tmp_path / "data-dir", exist_ok=True)
    with open(tmp_path / "data-dir/central.raucs", "w") as f:
        for name, keys in status.items():
            f.write(f"[slot.{name}]\n")
            f.writelines(f"{k}={v}\n" for k, v in keys.items())


@contextmanager
def polkitd_stopped(polkitd):
    os.kill(polkitd.pid, signal.SIGSTOP)
    try:
        yield
    finally:
        os.kill(polkitd.pid, signal.SIGCONT)


def call_in_order(polkitd, *calls):
    """
    Start each (method, args) call while polkitd is stopped, one second apart,
    so the service asks polkit in that order, and return their results.
    """
    # connected first, as dropping privileges changes every thread
    proxies = [unprivileged_bus().get_proxy("de.pengutronix.rauc", "/") for _ in calls]
    results = [None] * len(calls)

    def call(i, method, args):
        try:
            results[i] = getattr(proxies[i], method)(*args)
        except DBusError as e:
            results[i] = e

    threads = [threading.Thread(target=call, args=(i, *c)) for i, c in enumerate(calls)]
    with polkitd_stopped(polkitd):
        for thread in threads:
            thread.start()
            time.sleep(1)
    for thread in threads:
        thread.join(timeout=30)

    return results


def test_install_refused(rauc_dbus_service_with_system, polkit_allow, bundle_path, tmp_path):
    polkit_allow()

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle_path, {})

    assert not slot_written(tmp_path / "images/rootfs-1")


def test_install_allowed(rauc_dbus_service_with_system, polkit_allow, bundle_path, tmp_path):
    polkit_allow("de.pengutronix.rauc.install")

    rauc_dbus_service_with_system.InstallBundle(bundle_path, {})

    assert wait_idle(rauc_dbus_service_with_system) == ""
    assert slot_written(tmp_path / "images/rootfs-1")


@pytest.mark.parametrize("key, value", INSTALL_OVERRIDES)
def test_install_needs_override(rauc_dbus_service_with_system, polkit_allow, bundle_path, tmp_path, key, value):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(bundle_path, {key: value})

    assert not slot_written(tmp_path / "images/rootfs-1")


def test_install_override_allowed(rauc_dbus_service_with_system, polkit_allow, bundle_path, tmp_path):
    polkit_allow("de.pengutronix.rauc.install-override")

    rauc_dbus_service_with_system.InstallBundle(bundle_path, {"ignore-compatible": get_variant(Bool, True)})

    assert wait_idle(rauc_dbus_service_with_system) == ""
    assert slot_written(tmp_path / "images/rootfs-1")


def test_mark_refused(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Mark("good", "booted")


def test_mark_allowed(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.mark")

    slot, _ = rauc_dbus_service_with_system.Mark("good", "booted")

    assert slot == "rootfs.0"


def test_inspect_refused(rauc_dbus_service_with_system, polkit_allow, bundle_path):
    polkit_allow("de.pengutronix.rauc.install")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InspectBundle(bundle_path, {})
    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Info(bundle_path)


def test_inspect_allowed(rauc_dbus_service_with_system, polkit_allow, bundle_path):
    polkit_allow("de.pengutronix.rauc.inspect")

    rauc_dbus_service_with_system.InspectBundle(bundle_path, {})
    compatible, version = rauc_dbus_service_with_system.Info(bundle_path)

    assert (compatible, version) == ("Test Config", "2011.03-2")


@pytest.mark.parametrize("key, value", ACCESS_ARGS)
def test_inspect_needs_override(rauc_dbus_service_with_system, polkit_allow, bundle_path, key, value):
    polkit_allow("de.pengutronix.rauc.inspect")

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InspectBundle(bundle_path, {key: value})


def test_inspect_override_allowed(rauc_dbus_service_with_system, polkit_allow, bundle_path):
    polkit_allow("de.pengutronix.rauc.inspect-override")

    manifest = get_native(
        rauc_dbus_service_with_system.InspectBundle(bundle_path, {"tls-no-verify": get_variant(Bool, True)})
    )

    assert manifest["update"]["compatible"] == "Test Config"


@root
def test_root_not_checked(rauc_dbus_service_with_system, polkit_allow):
    """Root is allowed without asking polkit, so the rauc command line tool works unchanged."""
    polkit_allow()

    SessionMessageBus().get_proxy("de.pengutronix.rauc", "/").Mark("good", "booted")

    assert polkit_allow.calls() == []
    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Mark("good", "booted")


def test_subject_is_the_caller(rauc_dbus_service_with_system, polkit_allow):
    """polkit is asked about the caller's name on the bus, which it resolves itself."""
    polkit_allow()
    bus = unprivileged_bus()

    with pytest.raises(DBusError, match="not authorized"):
        bus.get_proxy("de.pengutronix.rauc", "/").Mark("good", "booted")

    ((subject, action, _),) = polkit_allow.checks()
    assert action == "de.pengutronix.rauc.mark"
    assert subject == ("system-bus-name", {"name": bus.connection.get_unique_name()})


def test_read_only_methods_not_checked(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow()

    rauc_dbus_service_with_system.GetSlotStatus()
    rauc_dbus_service_with_system.GetPrimary()


@have_streaming
def test_poll(create_system_files, system, http_server, polkit_allow):
    http_server.setup(file_path="good-verity-bundle.raucb")
    system.prepare_minimal_config()
    system.config["handlers"] = {"system-info": "bin/systeminfo.sh"}
    system.config["polling"] = {"url": http_server.url, "interval-sec": "60"}
    system.write_config()

    with system.running_service("A"):
        polkit_allow("de.pengutronix.rauc.install")
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Poll()

        polkit_allow("de.pengutronix.rauc.poll")
        system.proxy.Poll()


def test_details_hide_tls_values(rauc_dbus_service_with_system, polkit_allow, bundle_path):
    polkit_allow()

    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.InstallBundle(
            bundle_path,
            {
                "tls-key": get_variant(Str, "pkcs11:token=t;object=k?pin-value=SECRET"),
                "tls-cert": get_variant(Str, "pkcs11:token=t;object=c?pin-value=SECRET"),
            },
        )
    with pytest.raises(DBusError, match="not authorized"):
        rauc_dbus_service_with_system.Mark("good", "booted")

    (install_action, install), (mark_action, mark) = polkit_allow.calls()
    assert install_action == "de.pengutronix.rauc.install-override"
    assert install["source"] == bundle_path
    assert install["tls-key"] == "true"
    assert install["tls-cert"] == "true"
    assert install["tls-ca"] == "false"
    assert not any("SECRET" in v for v in install.values())
    assert mark_action == "de.pengutronix.rauc.mark"
    assert mark == {"state": "good", "slot": "booted"}


@pytest.mark.parametrize(
    "limit, status, slot, complete, meets",
    [
        ("2.0.0", {}, "other", "false", "false"),
        ("2.0.0", group_status("ok", "2.0.0"), "other", "true", "true"),
        ("2.0.0", group_status("ok", "2.1.0"), "rootfs.1", "true", "true"),
        ("2.0.0", group_status("ok", "1.9.0"), "other", "true", "false"),
        ("2.0.0", group_status("pending", "2.0.0"), "other", "false", "true"),
        ("2.0.0", {"rootfs.1": slot_status("ok", "2.0.0")}, "other", "false", "false"),
        (
            "2.0.0",
            {"rootfs.1": slot_status("ok", "2.0.0"), "appfs.1": slot_status("pending", "2.0.0")},
            "other",
            "false",
            "true",
        ),
        (
            "2.0.0",
            {"rootfs.1": slot_status("ok", "2.0.0"), "appfs.1": slot_status("ok", "1.0.0")},
            "other",
            "true",
            "false",
        ),
        (
            "2.0.0",
            {"rootfs.1": slot_status("ok", "2.0.0", "b2"), "appfs.1": slot_status("ok", "2.0.0", "b1")},
            "other",
            "false",
            "true",
        ),
        (None, group_status("ok", "1.0.0"), "other", "true", "true"),
    ],
)
def test_mark_active_details(
    tmp_path, create_system_files, system, polkit_allow, limit, status, slot, complete, meets
):
    """Activating a slot passes whether it holds a complete install at or above the version limit."""
    system.prepare_minimal_config()
    if limit:
        system.config["system"]["min-bundle-version"] = limit
    system.write_config()
    write_central_status(tmp_path, status)

    with system.running_service("A"):
        polkit_allow()
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Mark("active", slot)
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Mark("good", "booted")

        assert polkit_allow.calls() == [
            (
                "de.pengutronix.rauc.mark",
                {
                    "state": "active",
                    "slot": slot,
                    "install-complete": complete,
                    "meets-version-limit": meets,
                    "activated-since-install": "false",
                    "booted-slot-good": "false",
                },
            ),
            ("de.pengutronix.rauc.mark", {"state": "good", "slot": "booted"}),
        ]


@pytest.mark.parametrize("activated, expected", [(None, "false"), ("2026-01-01T11:00:00Z", "true")])
def test_mark_active_details_activated(tmp_path, create_system_files, system, polkit_allow, activated, expected):
    """Activating a slot passes whether it was activated since its last install."""
    system.prepare_minimal_config()
    system.write_config()
    status = group_status("ok", "1.0.0")
    status["rootfs.1"]["installed.timestamp"] = "2026-01-01T10:00:00Z"
    if activated:
        status["rootfs.1"]["activated.timestamp"] = activated
    write_central_status(tmp_path, status)

    with system.running_service("A"):
        polkit_allow()
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Mark("active", "other")

        ((_, details),) = polkit_allow.calls()

    assert details["activated-since-install"] == expected


@pytest.mark.parametrize("name", ["booted", "rootfs.0"])
def test_booted_slot_good_follows_the_booted_slot(rauc_dbus_service_with_system, polkit_allow, bundle_path, name):
    """Marking the booted slot good or bad, by any name, is reflected in booted-slot-good."""
    polkit_allow("de.pengutronix.rauc.mark")

    def booted_slot_good():
        with pytest.raises(DBusError, match="not authorized"):
            rauc_dbus_service_with_system.InstallBundle(bundle_path, {})
        return polkit_allow.calls()[-1][1]["booted-slot-good"]

    assert booted_slot_good() == "false"
    rauc_dbus_service_with_system.Mark("good", name)
    assert booted_slot_good() == "true"
    rauc_dbus_service_with_system.Mark("good", "rootfs.1")
    assert booted_slot_good() == "true"
    rauc_dbus_service_with_system.Mark("bad", name)
    assert booted_slot_good() == "false"


@pytest.mark.parametrize("method", ["InstallBundle", "Mark"])
def test_refused_when_booted_slot_good_changes_during_check(
    rauc_dbus_service_with_system, polkit_allow, bundle_path, tmp_path, method
):
    """A call checked while the booted slot was not yet marked good is refused once it is."""
    polkit_allow("de.pengutronix.rauc.install", "de.pengutronix.rauc.mark")
    args = (bundle_path, {}) if method == "InstallBundle" else ("active", "other")

    good, later = call_in_order(polkit_allow, ("Mark", ("good", "booted")), (method, args))

    assert not isinstance(good, DBusError)
    assert isinstance(later, DBusError)
    assert "changed during authorization" in str(later)
    assert not slot_written(tmp_path / "images/rootfs-1")


@pytest.mark.parametrize("cut_off", [False, True])
def test_mark_active_details_after_install(tmp_path, create_system_files, system, polkit_allow, bundle_path, cut_off):
    """After a restart, an install cut off at its second image is not complete, a full one is."""
    system.prepare_minimal_config()
    system.write_config()
    if cut_off:
        os.unlink(tmp_path / "images/appfs-1")
        os.mkdir(tmp_path / "images/appfs-1")

    with system.running_service("A"):
        polkit_allow("de.pengutronix.rauc.install")
        system.proxy.InstallBundle(bundle_path, {})
        assert (wait_idle(system.proxy) != "") == cut_off

    assert slot_written(tmp_path / "images/rootfs-1")

    with system.running_service("A"):
        polkit_allow()
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Mark("active", "other")

        ((action, details),) = polkit_allow.calls()

    assert action == "de.pengutronix.rauc.mark"
    assert details["install-complete"] == ("false" if cut_off else "true")


def test_mark_active_details_after_activation(tmp_path, create_system_files, system, polkit_allow, bundle_path):
    """Once the installed slot was activated, activating it again passes activated-since-install."""
    system.prepare_minimal_config()
    system.config["system"]["activate-installed"] = "false"
    system.write_config()

    with system.running_service("A"):
        polkit_allow("de.pengutronix.rauc.install", "de.pengutronix.rauc.mark")
        system.proxy.InstallBundle(bundle_path, {})
        assert wait_idle(system.proxy) == ""
        polkit_allow.calls()
        system.proxy.Mark("active", "other")
        polkit_allow.proxy.SetAllowed([])
        with pytest.raises(DBusError, match="not authorized"):
            system.proxy.Mark("active", "other")

        first, second = polkit_allow.calls()

    assert first[1]["install-complete"] == "true"
    assert first[1]["activated-since-install"] == "false"
    assert second[1]["activated-since-install"] == "true"


def test_refused_when_polkit_does_not_answer(rauc_dbus_service_with_system, polkit_allow):
    polkit_allow("de.pengutronix.rauc.mark")

    with polkitd_stopped(polkit_allow):
        start = time.monotonic()
        with pytest.raises(DBusError, match="polkit did not answer in time"):
            rauc_dbus_service_with_system.Mark("good", "booted")
        assert 15 < time.monotonic() - start < 25

    # and works again once polkit answers
    rauc_dbus_service_with_system.Mark("good", "booted")


@root
def test_refused_when_caller_leaves(rauc_dbus_service_with_system, polkit_allow):
    """A call whose caller leaves the bus while polkit is asked is not carried out."""
    polkit_allow("de.pengutronix.rauc.mark")
    primary = rauc_dbus_service_with_system.GetPrimary()

    with polkitd_stopped(polkit_allow):
        caller = subprocess.Popen(
            [
                "setpriv",
                f"--reuid={UNPRIVILEGED_ID}",
                f"--regid={UNPRIVILEGED_ID}",
                "--clear-groups",
                "gdbus",
                "call",
                "--session",
                "--dest=de.pengutronix.rauc",
                "--object-path=/",
                "--method=de.pengutronix.rauc.Installer.Mark",
                "active",
                "other",
            ]
        )
        time.sleep(1)
        caller.kill()
        caller.wait()
        time.sleep(1)
    time.sleep(1)

    assert rauc_dbus_service_with_system.GetPrimary() == primary


def test_mark_refused_when_install_starts_during_check(rauc_dbus_service_with_system, polkit_allow, bundle_path):
    """An install authorized while a Mark() check is pending makes the Mark() busy."""
    polkit_allow("de.pengutronix.rauc.install", "de.pengutronix.rauc.mark")

    install, mark = call_in_order(polkit_allow, ("InstallBundle", (bundle_path, {})), ("Mark", ("good", "booted")))

    assert not isinstance(install, DBusError)
    assert isinstance(mark, DBusError)
    assert "already processing a different method" in str(mark)
    assert wait_idle(rauc_dbus_service_with_system) == ""
