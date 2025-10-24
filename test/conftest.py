import json
import os
import shutil
import subprocess
import time
from functools import cache
from configparser import ConfigParser
from pathlib import Path
from random import Random
from contextlib import contextmanager

import pytest
from dasbus.connection import SessionMessageBus
from dasbus.error import DBusError
import requests

from helper import run

# Avoid fastcopy via sendfile() which seems to cause troubles with the 9pfs and
# the current kernel used in our qemu-test:
#
# | WARNING: CPU: 1 PID: 6623 at lib/iov_iter.c:1201 iov_iter_pipe+0x31/0x40
#
# Manually override _USE_CP_SENDFILE as suggested here:
# https://github.com/python/cpython/issues/87909#issuecomment-1093909363
# and originally defined here:
# https://github.com/python/cpython/blob/3.12/Lib/shutil.py#L51
shutil._USE_CP_SENDFILE = False


meson_build = os.environ.get("MESON_BUILD_DIR")
if not meson_build:
    raise Exception("Please set MESON_BUILD_DIR to point to the meson build directory.")
if not os.path.isabs(meson_build):
    meson_build = os.path.abspath(meson_build)


@pytest.fixture(scope="session")
def monkeysession():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope="session", autouse=True)
def env_setup(monkeysession):
    monkeysession.setenv("PATH", meson_build, prepend=os.pathsep)
    monkeysession.setenv("LC_ALL", "C")
    monkeysession.setenv("TZ", "UTC")
    monkeysession.setenv("DBUS_STARTER_BUS_TYPE", "session")

    os.chdir(f"{os.path.dirname(os.path.abspath(__file__))}")


@cache
def meson_buildoptions():
    with open(os.path.join(meson_build, "meson-info/intro-buildoptions.json")) as f:
        data = json.loads(f.read())

    return {o["name"]: o for o in data}


@cache
def string_in_config_h(findstring):
    with open(os.path.join(meson_build, "config.h")) as f:
        if findstring in f.read():
            return True
    return False


have_json = pytest.mark.skipif(not string_in_config_h("ENABLE_JSON 1"), reason="No json")


root = pytest.mark.skipif(os.geteuid() != 0, reason="Not root")


def _have_grub():
    out, err, exitcode = run("grub-editenv -V")
    return exitcode == 0


have_grub = pytest.mark.skipif(not _have_grub(), reason="Have no grub-editenv")


def _have_openssl():
    out, err, exitcode = run("openssl version")
    return exitcode == 0


have_openssl = pytest.mark.skipif(not _have_openssl(), reason="Have no OPENSSL")


def _have_casync():
    try:
        out, err, exitcode = run("casync --version")
        return exitcode == 0
    except Exception:
        return False


have_casync = pytest.mark.skipif(not _have_casync(), reason="Have no casync")


def _have_desync():
    try:
        out, err, exitcode = run("desync --help")
        return exitcode == 0
    except Exception:
        return False


have_desync = pytest.mark.skipif(not _have_desync(), reason="Have no desync")


def _have_faketime():
    # faketime is not compatible with sanitizers:
    # https://github.com/wolfcw/libfaketime/issues/412#issuecomment-1293686539
    b_sanitize = meson_buildoptions().get("b_sanitize", {})
    if b_sanitize.get("value", "none") != "none":
        print("faketime not compatible with sanitizers")
        return False

    try:
        out, err, exitcode = run('faketime "2018-01-01" date')
        if exitcode != 0:
            return False

        # On some platforms faketime is broken, see e.g. https://github.com/wolfcw/libfaketime/issues/418
        out, err, exitcode = run('faketime "2018-01-01" date -R')
        if "Jan 2018" not in out:
            return False

        return exitcode == 0
    except Exception:
        return False


have_faketime = pytest.mark.skipif(not _have_faketime(), reason="Have no faketime")


have_http = pytest.mark.skipif("RAUC_TEST_HTTP_SERVER" not in os.environ, reason="Have no HTTP")


have_streaming = pytest.mark.skipif(
    "RAUC_TEST_HTTP_SERVER" not in os.environ or not string_in_config_h("ENABLE_STREAMING 1"),
    reason="Have no streaming",
)


def _have_qemu():
    out, err, exitcode = run("grep -q qemu-test-init /proc/cmdline")
    return exitcode == 0


have_qemu = pytest.mark.skipif(not _have_qemu(), reason="Not in qemu-test")

no_service = pytest.mark.skipif(string_in_config_h("ENABLE_SERVICE 1"), reason="Have service")


def have_service():
    return string_in_config_h("ENABLE_SERVICE 1")


needs_emmc = pytest.mark.skipif("RAUC_TEST_EMMC" not in os.environ, reason="Missing eMMC")


needs_composefs = pytest.mark.skipif(not string_in_config_h("ENABLE_COMPOSEFS 1"), reason="Missing composefs support")


def softhsm2_load_key_pair(cert, privkey, label, id_, softhsm2_mod, tmp_path):
    proc = subprocess.run(
        f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 -y cert -w {cert} --label {label} --id {id_}",
        shell=True,
    )
    assert proc.returncode == 0

    pubkey_file = tmp_path / f"pubkey_{label}.pem"

    proc = subprocess.run(
        f"openssl rsa -in {privkey} -inform pem -pubout -outform pem -out {pubkey_file}",
        shell=True,
    )
    assert proc.returncode == 0

    proc = subprocess.run(
        f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 -y pubkey -w {pubkey_file} --label {label} --id {id_}",
        shell=True,
    )
    assert proc.returncode == 0

    proc = subprocess.run(
        f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 -y privkey -w {privkey} --label {label} --id {id_}",
        shell=True,
    )
    assert proc.returncode == 0


def softhsm2_test_signature(tmp_path, cert, label, ca):
    test_tmp = tmp_path / "softhsm2_test" / label
    test_tmp.mkdir(parents=True)
    (test_tmp / "message.txt").write_text("test message\n")

    subprocess.check_call(
        "openssl cms -engine pkcs11 -keyform engine -sign "
        f"-in {test_tmp}/message.txt -out {test_tmp}/message.sig -binary "
        f"-inkey 'pkcs11:token=rauc;object={label}&pin-value=1111' "
        f"-signer {cert}",
        shell=True,
    )
    subprocess.check_call(
        f"openssl cms -verify -in {test_tmp}/message.sig -out {test_tmp}/message.out -binary -CAfile {ca}",
        shell=True,
    )

    assert (test_tmp / "message.out").read_text() == "test message\n"


def softhsm2_test_encryption(tmp_path, cert, label):
    test_tmp = tmp_path / "softhsm2_test" / label
    test_tmp.mkdir(parents=True)
    (test_tmp / "message.txt").write_text("test message\n")

    subprocess.check_call(
        f"openssl cms -encrypt -in {test_tmp}/message.txt -out {test_tmp}/message.enc -binary {cert}",
        shell=True,
    )
    subprocess.check_call(
        "openssl cms -engine pkcs11 -keyform engine -decrypt "
        f"-in {test_tmp}/message.enc -out {test_tmp}/message.out -binary "
        f"-recip {cert} -inkey 'pkcs11:token=rauc;object={label}&pin-value=1111'",
        shell=True,
    )

    assert (test_tmp / "message.out").read_text() == "test message\n"


def prepare_softhsm2(tmp_path, softhsm2_mod):
    ca_dev = Path("openssl-ca/dev")
    ca_cert = Path("openssl-ca/dev-ca.pem")
    enc_keys = Path("openssl-enc/keys")
    web_ca = Path("openssl-ca/web")

    softhsm2_conf = tmp_path / "softhsm2.conf"
    softhsm2_dir = tmp_path / "softhsm2.tokens"

    os.environ["SOFTHSM2_CONF"] = str(softhsm2_conf)
    os.environ["SOFTHSM2_DIR"] = str(softhsm2_dir)

    with open(softhsm2_conf, mode="w") as f:
        f.write(f"directories.tokendir = {softhsm2_dir}")

    os.mkdir(softhsm2_dir)

    out, err, exitcode = run(f"pkcs11-tool --module {softhsm2_mod} --init-token --label rauc --so-pin 0000")
    assert exitcode == 0
    out, err, exitcode = run(f"pkcs11-tool --module {softhsm2_mod} -l --so-pin 0000 --new-pin 1111 --init-pin")
    assert exitcode == 0

    out, err, exitcode = run("p11-kit list-modules")
    assert exitcode == 0

    out, err, exitcode = run("openssl engine pkcs11 -tt -vvvv")
    assert exitcode == 0

    # load signing key pairs
    softhsm2_load_key_pair(
        ca_dev / "autobuilder-1.cert.pem",
        ca_dev / "private/autobuilder-1.pem",
        "autobuilder-1",
        "01",
        softhsm2_mod,
        tmp_path,
    )
    softhsm2_load_key_pair(
        ca_dev / "autobuilder-2.cert.pem",
        ca_dev / "private/autobuilder-2.pem",
        "autobuilder-2",
        "02",
        softhsm2_mod,
        tmp_path,
    )

    subprocess.check_call(
        f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 --sign --mechanism RSA-PKCS --label autobuilder-1 --input-file /dev/null --output-file=/dev/null ",
        shell=True,
    )
    subprocess.check_call(
        f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 --sign --mechanism RSA-PKCS --label autobuilder-2 --input-file /dev/null --output-file=/dev/null ",
        shell=True,
    )

    softhsm2_test_signature(tmp_path, ca_dev / "autobuilder-1.cert.pem", "autobuilder-1", ca_cert)
    softhsm2_test_signature(tmp_path, ca_dev / "autobuilder-2.cert.pem", "autobuilder-2", ca_cert)

    # load encryption key pair
    softhsm2_load_key_pair(
        enc_keys / "rsa-4096/cert-000.pem",
        enc_keys / "rsa-4096/private-key-000.pem",
        "enc-rsa-000",
        "11",
        softhsm2_mod,
        tmp_path,
    )

    softhsm2_test_encryption(tmp_path, enc_keys / "rsa-4096/cert-000.pem", "enc-rsa-000")

    # load web client key pair
    softhsm2_load_key_pair(
        web_ca / "client-1.cert.pem",
        web_ca / "private/client-1.pem",
        "client-1",
        "21",
        softhsm2_mod,
        tmp_path,
    )

    subprocess.check_call(f"pkcs11-tool --module {softhsm2_mod} -l --pin 1111 --list-objects", shell=True)

    os.environ["RAUC_PKCS11_PIN"] = "1111"
    # setting the module is needed only if p11-kit doesn't work
    os.environ["RAUC_PKCS11_MODULE"] = softhsm2_mod


@pytest.fixture(scope="session")
def pkcs11(tmp_path_factory):
    if os.path.exists("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"):
        softhsm2_mod = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    else:
        softhsm2_mod = "/usr/lib/softhsm/libsofthsm2.so"
    if not os.path.exists(softhsm2_mod):
        pytest.skip("libsofthsm2.so not available on system")

    prepare_softhsm2(tmp_path_factory.mktemp("blub"), softhsm2_mod)


@pytest.fixture(scope="session")
def dbus_session_bus(tmp_path_factory):
    addr_r_fd, addr_w_fd = os.pipe()

    try:
        # Start the dbus-daemon
        dbus = subprocess.Popen(
            [
                "dbus-daemon",
                "--session",
                f"--address=unix:path={tmp_path_factory.mktemp('dbus')}/socket",
                f"--print-address={addr_w_fd}",
            ],
            pass_fds=(addr_w_fd,),
        )
        # Wait until readiness is signaled by writing the address
        addr = os.read(addr_r_fd, 4096).decode()
    finally:
        os.close(addr_r_fd)
        os.close(addr_w_fd)

    print(f"DBUS_SESSION_BUS_ADDRESS: {addr}")

    # Set the address in the current process's environment
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = addr

    yield

    dbus.terminate()
    try:
        dbus.wait(timeout=10)
    except subprocess.TimeoutExpired:
        dbus.kill()
        dbus.wait()


@pytest.fixture
def create_system_files(env_setup, tmp_path):
    os.mkdir(tmp_path / "images")
    open(tmp_path / "images/rootfs-0", mode="w").close()
    open(tmp_path / "images/rootfs-1", mode="w").close()
    open(tmp_path / "images/appfs-0", mode="w").close()
    open(tmp_path / "images/appfs-1", mode="w").close()
    os.mkdir(tmp_path / "repos")
    os.mkdir(tmp_path / "repos/files")
    os.mkdir(tmp_path / "repos/trees")
    os.mkdir(tmp_path / "repos/composefs")
    os.symlink(os.path.abspath("bin"), tmp_path / "bin")
    os.symlink(os.path.abspath("openssl-ca"), tmp_path / "openssl-ca")
    os.symlink(os.path.abspath("openssl-enc"), tmp_path / "openssl-enc")

    run(f'grub-editenv {tmp_path}/grubenv.test set ORDER="A B" A_TRY="0" B_TRY="0" A_OK="1" B_OK="0"')


@pytest.fixture
def rauc_no_service(create_system_files, tmp_path):
    tmp_conf_file = tmp_path / "system.conf"
    shutil.copy("test.conf", tmp_conf_file)

    return f"rauc -c {tmp_conf_file}"


@pytest.fixture
def rauc_dbus_service_with_system(tmp_path, create_system_files, system):
    system.prepare_minimal_config()
    system.write_config()
    with system.running_service("A"):
        yield system.proxy


@pytest.fixture
def rauc_dbus_service_with_system_crypt(tmp_path, create_system_files, system):
    system.prepare_crypt_config()
    system.write_config()
    with system.running_service("A"):
        yield system.proxy


@pytest.fixture
def rauc_dbus_service_with_system_external(tmp_path, create_system_files, system):
    system.prepare_minimal_config()
    system.write_config()
    with system.running_service("_external_"):
        yield system.proxy


@pytest.fixture
def rauc_dbus_service_with_system_adaptive(tmp_path, create_system_files, system):
    system.prepare_adaptive_config()
    system.write_config()
    with system.running_service("A"):
        yield system.proxy


@pytest.fixture
def rauc_dbus_service_with_system_abc(tmp_path, create_system_files, system):
    system.prepare_abc_config()
    system.write_config()
    with system.running_service("A"):
        yield system.proxy


@pytest.fixture
def rauc_dbus_service_with_system_composefs(tmp_path, create_system_files, system):
    system.prepare_composefs_config()
    system.write_config()
    with system.running_service("A"):
        yield system.proxy


class Bundle:
    def __init__(self, tmp_path, name=None):
        if name is None:
            name = "test"

        self.tmp_path = tmp_path
        self.output = tmp_path / f"{name}.raucb"
        self.content = tmp_path / f"{name}-install-content"

        assert not self.output.exists()
        assert not self.content.exists()
        self.content.mkdir()

        # default manifest
        self.manifest = ConfigParser()
        self.manifest["update"] = {
            "compatible": "Test Config",
            "version": "2011.03-2",
        }
        self.manifest["bundle"] = {
            "format": "verity",
        }

        # some padding
        self._make_random_file(self.content / "padding", 4096, "fixed padding")

    def _make_random_file(self, path, size, seed):
        rand = Random(seed)

        with open(path, "wb") as f:
            f.write(bytes(rand.getrandbits(8) for _ in range(size)))

    def make_random_image(self, image_name, size, seed):
        path = self.content / self.manifest[f"image.{image_name}"]["filename"]
        self._make_random_file(path, size, seed)

    def add_hook_script(self, hook_script):
        path = self.content / "hook.sh"
        with open(path, "w") as f:
            f.write(hook_script)
        path.chmod(0o755)

        self.manifest["hooks"] = {
            "filename": "hook.sh",
        }

    def build_nocheck(self):
        with open(self.content / "manifest.raucm", "w") as f:
            self.manifest.write(f, space_around_delimiters=False)

        return run(
            "rauc bundle "
            "--cert openssl-ca/dev/autobuilder-1.cert.pem "
            "--key openssl-ca/dev/private/autobuilder-1.pem "
            f"{self.content} {self.output}"
        )

    def build(self):
        out, err, exitcode = self.build_nocheck()
        assert exitcode == 0
        assert "Creating 'verity' format bundle" in out
        assert self.output.is_file()


@pytest.fixture
def bundle(tmp_path):
    bundle = Bundle(tmp_path)

    yield bundle


class System:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.output = tmp_path / "system.conf"
        self.data_dir = tmp_path / "data_dir"

        self.config = ConfigParser()
        self.config["system"] = {
            "compatible": "Test Config",
            "bootloader": "noop",
        }

        self.prefix = f"rauc -c {self.output}"

        self.service = None
        self.proxy = None

    def prepare_minimal_config(self):
        self.config["system"] = {
            "compatible": "Test Config",
            "bootloader": "grub",
            "grubenv": "grubenv.test",
            "variant-name": "Default Variant",
            "data-directory": "data-dir",
        }
        self.config["keyring"] = {
            "path": "openssl-ca/dev-ca.pem",
            "check-crl": "true",
        }
        self.config["slot.rootfs.0"] = {
            "device": "images/rootfs-0",
            "type": "raw",
            "bootname": "A",
        }
        self.config["slot.rootfs.1"] = {
            "device": "images/rootfs-1",
            "type": "raw",
            "bootname": "B",
        }
        self.config["slot.appfs.0"] = {
            "device": "images/appfs-0",
            "type": "raw",
            "parent": "rootfs.0",
        }
        self.config["slot.appfs.1"] = {
            "device": "images/appfs-1",
            "type": "raw",
            "parent": "rootfs.1",
        }
        self.config["artifacts.files"] = {
            "path": "repos/files",
            "type": "files",
        }
        self.config["artifacts.trees"] = {
            "path": "repos/trees",
            "type": "trees",
        }

    def prepare_crypt_config(self):
        self.prepare_minimal_config()
        self.config["encryption"] = {
            "key": "openssl-enc/keys/rsa-4096/private-key-000.pem",
            "cert": "openssl-enc/keys/rsa-4096/cert-000.pem",
        }

    def prepare_adaptive_config(self):
        self.prepare_minimal_config()
        self.config["handlers"] = {
            "system-info": "bin/systeminfo.sh",
            "pre-install": "bin/preinstall.sh",
            "post-install": "bin/postinstall.sh",
        }

    def prepare_abc_config(self):
        self.prepare_minimal_config()
        # add third slot group
        self.config["slot.rootfs.2"] = {
            "device": "images/rootfs-2",
            "type": "raw",
            "bootname": "C",
        }
        self.config["slot.appfs.2"] = {
            "device": "images/appfs-2",
            "type": "raw",
            "parent": "rootfs.2",
        }
        # create target devices for third slot group
        open(self.tmp_path / "images/rootfs-2", mode="w").close()
        open(self.tmp_path / "images/appfs-2", mode="w").close()
        # prepare grub env for 3 slots
        run(
            f'grub-editenv {self.tmp_path}/grubenv.test set ORDER="A B C" A_TRY="0" B_TRY="0" C_TRY="0" A_OK="1" B_OK="1" C_OK="1"'
        )

    def prepare_composefs_config(self):
        self.prepare_minimal_config()
        self.config["artifacts.composefs"] = {
            "path": "repos/composefs",
            "type": "composefs",
        }

    def write_config(self):
        with open(self.output, "w") as f:
            self.config.write(f, space_around_delimiters=False)

    @contextmanager
    def running_service(self, bootslot):
        if not have_service():
            # TODO avoid unnescesary setup by moving using a pytest mark for all service/noservice cases
            pytest.skip("No service")

        assert self.service is None
        assert self.proxy is None

        env = os.environ.copy()
        env["RAUC_PYTEST_TMP"] = str(self.tmp_path)

        self.service = subprocess.Popen(
            f"rauc service --conf={self.output} --mount={self.tmp_path}/mnt --override-boot-slot={bootslot}".split(),
            env=env,
        )

        bus = SessionMessageBus()

        # Wait for de.pengutronix.rauc to appear on the bus
        timeout = time.monotonic() + 5.0
        while True:
            time.sleep(0.1)
            try:
                self.proxy = bus.get_proxy("de.pengutronix.rauc", "/")
                self.proxy.Operation  # try to access the service
                break
            except DBusError:
                if time.monotonic() > timeout:
                    raise

        yield

        self.service.terminate()
        try:
            self.service.wait(timeout=10)
            assert self.service.returncode == 0
        except subprocess.TimeoutExpired:
            self.service.kill()
            self.service.wait()


@pytest.fixture
def system(tmp_path, dbus_session_bus):
    system = System(tmp_path)

    yield system


class HTTPServer:
    def __init__(self):
        self.server = None
        # in the qemu test environment, the server is already running
        if "RAUC_TEST_HTTP_BACKEND" in os.environ:
            self.base = "http://127.0.0.1/backend"
        else:
            self.base = "http://127.0.0.1:8080"
            self.start()
        self.url = f"{self.base}/get"

    def start(self):
        if "RAUC_TEST_HTTP_BACKEND" in os.environ:
            return
        assert self.server is None

        self.server = subprocess.Popen(["python3", "nginx_backend.py"])
        timeout = time.monotonic() + 5.0
        while True:
            time.sleep(0.1)
            try:
                resp = requests.get(f"{self.base}/")
                resp.raise_for_status()
                break
            except requests.exceptions.ConnectionError:
                if time.monotonic() > timeout:
                    raise

    def stop(self):
        if "RAUC_TEST_HTTP_SERVER" in os.environ:
            return
        assert self.server is not None

        self.server.terminate()
        try:
            self.server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait()

    def setup(self, *, file_path):
        resp = requests.post(
            f"{self.base}/setup",
            timeout=5,
            json={
                "file_path": os.path.abspath(file_path),
            },
        )
        resp.raise_for_status()

    def get(self, **kwargs):
        kwargs.setdefault("timeout", 15)
        return requests.get(self.url, **kwargs)

    def head(self, **kwargs):
        kwargs.setdefault("timeout", 5)
        return requests.head(self.url, **kwargs)

    def get_summary(self):
        resp = requests.get(f"{self.base}/summary", timeout=15)
        resp.raise_for_status()
        return resp.json()


@pytest.fixture(scope="session")
def http_server(env_setup):
    server = HTTPServer()
    yield server
    server.stop()
