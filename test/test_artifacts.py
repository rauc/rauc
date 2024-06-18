import shutil
import tarfile
import json
from configparser import ConfigParser
from io import BytesIO
from random import Random
from pprint import pprint
from pathlib import Path
from contextlib import contextmanager

from conftest import root, have_json
from helper import run


pytestmark = [root, have_json]


def make_random_file(path, size, seed):
    r = Random(seed)

    with open(path, "wb") as f:
        f.write(bytes(r.getrandbits(8) for _ in range(size)))


def make_manifest(tmp_path, contents):
    mf = ConfigParser()
    mf["update"] = {
        "compatible": "Test Config",
        "version": "2011.03-2",
    }
    mf["bundle"] = {
        "format": "verity",
    }
    mf.update(contents)

    path = tmp_path / "install-content"
    if path.is_dir():
        shutil.rmtree(path)
    path.mkdir()
    with open(path / "manifest.raucm", "w") as f:
        mf.write(f, space_around_delimiters=False)

    # some padding
    make_random_file(path / "padding", 4096, "fixed padding")


def make_tarfile(path, contents):
    with tarfile.open(name=path, mode="w") as t:
        for filename, content in contents.items():
            f = tarfile.TarInfo(name=filename)
            c = BytesIO(content)
            f.size = len(content)
            t.addfile(f, c)


def make_bundle(tmp_path, name):
    out_path = tmp_path / name
    out_path.unlink(missing_ok=True)

    out, err, exitcode = run(
        "rauc bundle "
        "--cert openssl-ca/dev/autobuilder-1.cert.pem "
        "--key openssl-ca/dev/private/autobuilder-1.pem "
        f"{tmp_path}/install-content {out_path}"
    )
    assert exitcode == 0
    assert "Creating 'verity' format bundle" in out

    assert out_path.is_file()

    return out_path


def get_info(path):
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=json-2 {path}")
    assert exitcode == 0

    info = json.loads(out)

    assert info
    assert info.get("bundle", {}).get("format") == "verity"

    return info


class RepoStatus(dict):
    @property
    def artifacts(self):
        result = {}

        for artifact in self.get("artifacts", []):
            result[artifact["name"]] = artifact

        return result

    @property
    def referenced_artifacts(self):
        result = {}

        for artifact in self.get("artifacts", []):
            if len(artifact["references"]) == 0:
                continue

            result[artifact["name"]] = artifact

        return result

    @property
    def path(self):
        return Path(self["path"])


class Status(dict):
    @property
    def repos(self):
        result = {}

        for repo in self.get("artifact-repositories", []):
            result[repo["name"]] = RepoStatus(repo)

        return result


def get_status():
    out, err, exitcode = run("rauc status --output-format=json-pretty")
    assert exitcode == 0

    status = json.loads(out)

    assert status
    assert status.get("compatible") == "Test Config"

    return Status(status)


@contextmanager
def extracted_bundle(tmp_path, bundle_path):
    path = tmp_path / "extracted"
    assert not path.exists()

    try:
        out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem extract {bundle_path} {path}")
        assert exitcode == 0
        yield path
    finally:
        shutil.rmtree(path)


def test_bundle(tmp_path):
    """Create a bundle with artifacts and check the resulting information."""
    bundle_path = tmp_path / "install-content"

    make_manifest(
        tmp_path,
        {
            "image.files/artifact-1": {
                "filename": "file-a.raw",
            },
            "image.trees/artifact-1": {
                "filename": "tree-a.tar",
            },
        },
    )
    with open(bundle_path / "file-a.raw", "wb") as f:
        data_a = b"content-a"
        f.write(data_a)
    make_tarfile(bundle_path / "tree-a.tar", {"file": data_a})
    bundle_a = make_bundle(tmp_path, "bundle-a.raucb")

    info = get_info(bundle_a)
    assert info["images"][0]["filename"] == "file-a.raw"
    assert info["images"][0]["slot-class"] == "files"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][1]["filename"] == "tree-a.tar"
    assert info["images"][1]["slot-class"] == "trees"
    assert info["images"][1]["artifact"] == "artifact-1"

    with extracted_bundle(tmp_path, bundle_a) as extracted:
        assert (extracted / "file-a.raw").is_file()
        assert (extracted / "tree-a.tar").is_file()


def test_bundle_convert_tree(tmp_path):
    """Create a bundle by extracting a tar file."""
    bundle_path = tmp_path / "install-content"

    make_manifest(
        tmp_path,
        {
            "image.trees/artifact-1": {
                "filename": "tree-a.tar",
                "convert": "tar-extract",
            },
        },
    )
    data_a = b"content-a"
    make_tarfile(bundle_path / "tree-a.tar", {"file": data_a})
    bundle_a = make_bundle(tmp_path, "bundle-a.raucb")

    info = get_info(bundle_a)
    pprint(info)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["tar-extract"]
    assert info["images"][0]["converted"] == ["tree-a.tar.extracted"]

    with extracted_bundle(tmp_path, bundle_a) as extracted:
        run(f"tree {extracted}")
        assert not (extracted / "tree-a.tar").exists()
        assert (extracted / "tree-a.tar.extracted").is_dir()
        assert (extracted / "tree-a.tar.extracted/file").is_file()
        with open(extracted / "tree-a.tar.extracted/file", "rb") as f:
            assert f.read() == data_a


def test_bundle_convert_tree_keep(tmp_path):
    """Create a bundle by extracting a tar file while keeping the original."""
    bundle_path = tmp_path / "install-content"

    make_manifest(
        tmp_path,
        {
            "image.trees/artifact-1": {
                "filename": "tree-a.tar",
                "convert": "tar-extract;keep",
            },
        },
    )
    make_tarfile(bundle_path / "tree-a.tar", {"file": b"contents-a"})
    bundle_a = make_bundle(tmp_path, "bundle-a.raucb")

    info = get_info(bundle_a)
    pprint(info)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["tar-extract", "keep"]
    assert info["images"][0]["converted"] == ["tree-a.tar.extracted", "tree-a.tar"]

    with extracted_bundle(tmp_path, bundle_a) as extracted:
        assert (extracted / "tree-a.tar").exists()
        assert (extracted / "tree-a.tar.extracted").is_dir()
        assert (extracted / "tree-a.tar.extracted/file").is_file()
        with open(extracted / "tree-a.tar.extracted/file", "rb") as f:
            assert f.read() == b"contents-a"


def do_install_file(tmp_path, repo_name, artifact_name, artifact_data):
    bundle_path = tmp_path / "install-content"

    make_manifest(
        tmp_path,
        {
            f"image.{repo_name}/{artifact_name}": {
                "filename": "file.raw",
            },
        },
    )
    with open(bundle_path / "file.raw", "wb") as f:
        f.write(artifact_data)
    bundle = make_bundle(tmp_path, "bundle.raucb")

    out, err, exitcode = run(f"rauc install {bundle}")
    assert exitcode == 0


def do_install_tree(tmp_path, repo_name, artifact_name, artifact_contents):
    bundle_path = tmp_path / "install-content"

    make_manifest(
        tmp_path,
        {
            f"image.{repo_name}/{artifact_name}": {
                "filename": "tree.tar",
            },
        },
    )
    make_tarfile(bundle_path / "tree.tar", artifact_contents)
    bundle = make_bundle(tmp_path, "bundle.raucb")

    out, err, exitcode = run(f"rauc install {bundle}")
    assert exitcode == 0


def test_file_install(rauc_dbus_service_with_system, tmp_path):
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one file artifact and check result
    data_a = b"content-a"
    do_install_file(tmp_path, "files", "artifact-1", data_a)

    status = get_status()
    assert "files" in status.repos
    repo = status.repos["files"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path, "rb") as f:
        assert f.read() == data_a
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-1"))

    # update one file artifact and check result
    data_b = b"content-b"
    do_install_file(tmp_path, "files", "artifact-1", data_b)

    status = get_status()
    assert "files" in status.repos
    repo = status.repos["files"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path, "rb") as f:
        assert f.read() == data_b
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-1"))

    # install a different file artifact and check result
    data_c = b"content-c"
    do_install_file(tmp_path, "files", "artifact-2", data_c)

    status = get_status()
    assert "files" in status.repos
    repo = status.repos["files"]
    assert "artifact-2" in repo.referenced_artifacts
    assert "artifact-1" not in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-2"
    assert artifact_path.is_symlink()
    with open(artifact_path, "rb") as f:
        assert f.read() == data_c
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-2"))
    artifact_path = repo.path / "artifact-1"
    assert not artifact_path.exists()
    assert not Path("/run/rauc/artifacts/trees/artifact-1").exists()


def test_tree_install(rauc_dbus_service_with_system, tmp_path):
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one tree artifact and check result
    data_a = b"content-a"
    do_install_tree(tmp_path, "trees", "artifact-1", {"file-a": data_a})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-a", "rb") as f:
        assert f.read() == data_a
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-1"))

    # update one tree artifact and check result
    data_b = b"content-b"
    do_install_tree(tmp_path, "trees", "artifact-1", {"file-b": data_b})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-b", "rb") as f:
        assert f.read() == data_b
    # old file must be gone
    assert not (artifact_path / "file-a").exists()
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-1"))

    # install a different tree artifact and check result
    data_c = b"content-c"
    do_install_tree(tmp_path, "trees", "artifact-2", {"file-a": data_c})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-2" in repo.referenced_artifacts
    assert "artifact-1" not in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-2"
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-a", "rb") as f:
        assert f.read() == data_c
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-2"))
    artifact_path = repo.path / "artifact-1"
    assert not artifact_path.exists()
    assert not Path("/run/rauc/artifacts/trees/artifact-1").exists()


def test_install_keep_other(rauc_dbus_service_with_system, tmp_path):
    """
    When we install to one repo, artifacts in other repos should not be
    removed.
    """
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one file artifact and check result
    data_a = b"content-a"
    do_install_file(tmp_path, "files", "artifact-1", data_a)

    status = get_status()
    assert "files" in status.repos
    repo = status.repos["files"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path, "rb") as f:
        assert f.read() == data_a
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-1"))

    # install one tree artifact and check result
    data_b = b"content-b"
    do_install_tree(tmp_path, "trees", "artifact-1", {"file-a": data_b})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-a", "rb") as f:
        assert f.read() == data_b
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-1"))

    # the file artifact should not be removed
    repo = status.repos["files"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-1"))
