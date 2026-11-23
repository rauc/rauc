import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
import pytest


def _run_syslog_test(tmp_path, syslog_arg, expect_success=True):
    """Helper function to run syslog test with given syslog argument"""
    log_path = "/dev/log"
    messages = []

    def listener(sock):
        while True:
            try:
                data = sock.recv(1024)
                if data:
                    messages.append(data.decode("utf-8", errors="ignore"))
                else:
                    break
            except OSError:
                break

    if Path(log_path).exists():
        pytest.skip("/dev/log already exists, is a syslog daemon running?")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(log_path)
    except (PermissionError, OSError):
        pytest.skip("Cannot bind to /dev/log, likely in cross env.")

    threading.Thread(target=listener, args=(sock,), daemon=True).start()

    try:
        env = os.environ.copy()
        env["RAUC_PYTEST_TMP"] = str(tmp_path)

        cmd = [
            "rauc",
            "service",
            f"--conf={tmp_path / 'system.conf'}",
            f"--mount={tmp_path}/mnt",
            "--override-boot-slot=A",
            syslog_arg,
        ]

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(2)
        proc.terminate()
        exit_code = proc.wait(timeout=5)

        if expect_success:
            assert len(messages) > 0, "No syslog messages logged to /dev/log"

            pat = r"<\d+>.*\s+rauc\[\d+\]:"
            rauc_messages = [msg for msg in messages if re.search(pat, msg)]
            assert len(rauc_messages) > 0, "No valid syslog messages from rauc found"

            pat = r"<\d+>.*rauc\[\d+\]:.*service start"
            assert any(re.search(pat, msg) for msg in rauc_messages), "No 'service start' syslog message found"
        else:
            assert exit_code != 0, "Expected rauc service to fail with invalid syslog facility"

    finally:
        sock.close()
        if Path(log_path).exists():
            os.unlink(log_path)


@pytest.mark.parametrize("syslog_arg", ["--syslog", "--syslog=local0"])
def test_syslog(rauc_dbus_service_with_system, tmp_path, syslog_arg):
    """Check syslog messages from rauc with different syslog options"""
    _run_syslog_test(tmp_path, syslog_arg, expect_success=True)


def test_syslog_invalid(rauc_dbus_service_with_system, tmp_path):
    """Check that invalid syslog facility causes rauc service to fail"""
    _run_syslog_test(tmp_path, "--syslog=undefined", expect_success=False)
