import shutil
from pathlib import Path

from conftest import root
from helper import run


@root
def test_mount(tmp_path):
    shutil.copyfile("good-bundle.raucb", tmp_path / "good-bundle.raucb")

    try:
        out, err, exitcode = run(f"rauc --conf=test.conf mount {tmp_path}/good-bundle.raucb")

        assert exitcode == 0
        assert "Mounted bundle at /mnt/rauc/bundle" in out

        assert Path("/mnt/rauc/bundle/manifest.raucm").exists()
        assert Path("/mnt/rauc/bundle/rootfs.img").exists()

    finally:
        out, err, exitcode = run("umount /mnt/rauc/bundle")
        assert exitcode == 0
