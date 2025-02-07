import shutil
import tarfile
import json
from io import BytesIO
from pprint import pprint
from pathlib import Path
from contextlib import contextmanager

from conftest import root, have_json, needs_composefs, Bundle
from helper import run, run_tree


pytestmark = [root, have_json]


def make_tarfile(path, contents):
    with tarfile.open(name=path, mode="w") as t:
        for filename, content in contents.items():
            f = tarfile.TarInfo(name=filename)
            c = BytesIO(content)
            f.size = len(content)
            t.addfile(f, c)


def get_info(path):
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=json-2 {path}")
    assert exitcode == 0

    info = json.loads(out)

    assert info
    assert info.get("bundle", {}).get("format") == "verity"

    return info


def get_composefs_info(image):
    out, err, exitcode = run(f"composefs-info ls {image}")
    assert exitcode == 0
    assert err == ""

    result = {}
    for line in out.splitlines():
        name, obj = line.split("@", 1)
        result[name.rstrip("\t")] = obj.strip()

    return result


class RepoStatus(dict):
    @property
    def artifacts(self):
        result = {}

        for artifact in self.get("artifacts", []):
            for instance in artifact["instances"]:
                result.setdefault(artifact["name"], {})[instance["checksum"]] = instance

        return result

    @property
    def referenced_artifacts(self):
        result = {}

        for artifact in self.get("artifacts", []):
            for instance in artifact["instances"]:
                if len(instance["references"]) == 0:
                    continue

                result.setdefault(artifact["name"], {})[instance["checksum"]] = instance

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
def extracted_bundle(tmp_path, bundle_path, remove=True):
    path = tmp_path / "extracted"
    assert not path.exists()

    try:
        out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem extract {bundle_path} {path}")
        assert exitcode == 0
        yield path
    finally:
        if remove:
            shutil.rmtree(path)


@contextmanager
def mounted_composefs(tmp_path, image_path, store_path):
    mount_path = tmp_path / "mounted-composefs"
    mount_path.mkdir(exist_ok=True)

    run(f"mount.composefs -o basedir={store_path} {image_path} {mount_path}")
    try:
        yield mount_path
    finally:
        run(f"umount {mount_path}")


def test_bundle(tmp_path, bundle):
    """Create a bundle with artifacts and check the resulting information."""
    bundle.manifest["image.files/artifact-1"] = {
        "filename": "file-a.raw",
    }
    bundle.manifest["image.trees/artifact-1"] = {
        "filename": "tree-a.tar",
    }
    with open(bundle.content / "file-a.raw", "wb") as f:
        data_a = b"content-a"
        f.write(data_a)
    make_tarfile(bundle.content / "tree-a.tar", {"file": data_a})
    bundle.build()

    info = get_info(bundle.output)
    assert info["images"][0]["filename"] == "file-a.raw"
    assert info["images"][0]["slot-class"] == "files"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][1]["filename"] == "tree-a.tar"
    assert info["images"][1]["slot-class"] == "trees"
    assert info["images"][1]["artifact"] == "artifact-1"

    with extracted_bundle(tmp_path, bundle.output) as extracted:
        assert (extracted / "file-a.raw").is_file()
        assert (extracted / "tree-a.tar").is_file()


def test_convert_info(tmp_path, bundle):
    """Create a bundle by extracting a tar file."""
    bundle.manifest["image.trees/artifact-1"] = {
        "filename": "tree-a.tar",
        "convert": "tar-extract",
    }
    data_a = b"content-a"
    make_tarfile(bundle.content / "tree-a.tar", {"file": data_a})
    bundle.build()

    info = get_info(bundle.output)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["tar-extract"]
    assert info["images"][0]["converted"] == ["tree-a.tar.extracted"]

    # test old json output
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=json {bundle.output}")
    assert exitcode == 0
    info = json.loads(out)
    assert info["images"][0]["trees"]["artifact"] == "artifact-1"
    assert info["images"][0]["trees"]["filename"] == "tree-a.tar"
    assert info["images"][0]["trees"]["convert"] == ["tar-extract"]
    assert info["images"][0]["trees"]["converted"] == ["tree-a.tar.extracted"]

    # test readable output
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=readable {bundle.output}")
    assert exitcode == 0
    out = out.splitlines()
    assert "    Convert:   tar-extract" in out
    assert "    Converted: 'tree-a.tar.extracted'" in out

    # test shell output
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info --output-format=shell {bundle.output}")
    assert exitcode == 0
    assert out
    out = out.splitlines()
    assert "RAUC_IMAGE_CONVERT_0='tar-extract'" in out
    assert "RAUC_IMAGE_CONVERTED_0='tree-a.tar.extracted'" in out


def test_bundle_convert_tree(tmp_path, bundle):
    """Create a bundle by extracting a tar file."""
    bundle.manifest["image.trees/artifact-1"] = {
        "filename": "tree-a.tar",
        "convert": "tar-extract",
    }
    data_a = b"content-a"
    make_tarfile(bundle.content / "tree-a.tar", {"file": data_a})
    bundle.build()

    info = get_info(bundle.output)
    pprint(info)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["tar-extract"]
    assert info["images"][0]["converted"] == ["tree-a.tar.extracted"]

    with extracted_bundle(tmp_path, bundle.output) as extracted:
        run_tree(extracted)
        assert not (extracted / "tree-a.tar").exists()
        assert (extracted / "tree-a.tar.extracted").is_dir()
        assert (extracted / "tree-a.tar.extracted/file").is_file()
        with open(extracted / "tree-a.tar.extracted/file", "rb") as f:
            assert f.read() == data_a


def test_bundle_convert_tree_keep(tmp_path, bundle):
    """Create a bundle by extracting a tar file while keeping the original."""
    bundle.manifest["image.trees/artifact-1"] = {
        "filename": "tree-a.tar",
        "convert": "tar-extract;keep",
    }
    make_tarfile(bundle.content / "tree-a.tar", {"file": b"contents-a"})
    bundle.build()

    info = get_info(bundle.output)
    pprint(info)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["tar-extract", "keep"]
    assert info["images"][0]["converted"] == ["tree-a.tar.extracted", "tree-a.tar"]

    with extracted_bundle(tmp_path, bundle.output) as extracted:
        assert (extracted / "tree-a.tar").exists()
        assert (extracted / "tree-a.tar.extracted").is_dir()
        assert (extracted / "tree-a.tar.extracted/file").is_file()
        with open(extracted / "tree-a.tar.extracted/file", "rb") as f:
            assert f.read() == b"contents-a"


@needs_composefs
def test_bundle_convert_composefs(tmp_path, bundle):
    """Create a bundle by converting a tar file to a composfs image and objects."""
    bundle.manifest["image.trees/artifact-1"] = {
        "filename": "tree-a.tar",
        "convert": "composefs",
    }
    data_a = b"content-a" * 1024
    data_b = b"content-b" * 1024
    make_tarfile(
        bundle.content / "tree-a.tar",
        {
            "file-a-1": data_a,
            "file-a-2": data_a,
            "file-b": data_b,
        },
    )
    bundle.build()

    info = get_info(bundle.output)
    pprint(info)
    assert info["images"][0]["filename"] == "tree-a.tar"
    assert info["images"][0]["slot-class"] == "trees"
    assert info["images"][0]["artifact"] == "artifact-1"
    assert info["images"][0]["convert"] == ["composefs"]
    assert info["images"][0]["converted"] == ["tree-a.tar.cfs"]

    with extracted_bundle(tmp_path, bundle.output, remove=False) as extracted:
        run_tree(extracted)

        image_path = extracted / "tree-a.tar.cfs" / "image.cfs"
        store_path = extracted / ".rauc-cfs-store"

        assert not (extracted / "tree-a.tar").exists()
        assert image_path.is_file()
        assert store_path.is_dir()

        composefs_info = get_composefs_info(extracted / "tree-a.tar.cfs/image.cfs")
        assert set(composefs_info.keys()) == {
            "/file-a-1",
            "/file-a-2",
            "/file-b",
        }
        # both files should share one object
        assert composefs_info["/file-a-1"] == composefs_info["/file-a-2"]

        with mounted_composefs(tmp_path, image_path, store_path) as mount_path:
            with open(mount_path / "file-a-1", "rb") as f:
                assert f.read() == data_a
            with open(mount_path / "file-a-2", "rb") as f:
                assert f.read() == data_a
            with open(mount_path / "file-b", "rb") as f:
                assert f.read() == data_b


def do_install_file(tmp_path, name, repo_name, artifact_name, artifact_data):
    bundle = Bundle(tmp_path, name)
    bundle.manifest[f"image.{repo_name}/{artifact_name}"] = {
        "filename": "file.raw",
    }
    with open(bundle.content / "file.raw", "wb") as f:
        f.write(artifact_data)
    bundle.build()

    out, err, exitcode = run(f"rauc install {bundle.output}")
    assert exitcode == 0

    bundle.output.unlink()


def do_install_tree(tmp_path, name, repo_name, artifact_name, artifact_contents):
    bundle = Bundle(tmp_path, name)
    bundle.manifest[f"image.{repo_name}/{artifact_name}"] = {
        "filename": "tree.tar",
    }
    make_tarfile(bundle.content / "tree.tar", artifact_contents)
    bundle.build()

    out, err, exitcode = run(f"rauc install {bundle.output}")
    assert exitcode == 0

    bundle.output.unlink()


def do_install_composefs(tmp_path, name, repo_name, artifact_name, artifact_contents):
    bundle = Bundle(tmp_path, name)
    bundle.manifest[f"image.{repo_name}/{artifact_name}"] = {
        "filename": "tree.tar",
        "convert": "composefs",
    }
    make_tarfile(bundle.content / "tree.tar", artifact_contents)
    bundle.build()

    out, err, exitcode = run(f"rauc install {bundle.output}")
    assert exitcode == 0

    bundle.output.unlink()


def test_file_install(rauc_dbus_service_with_system, tmp_path):
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one file artifact and check result
    data_a = b"content-a"
    do_install_file(tmp_path, "a", "files", "artifact-1", data_a)

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
    do_install_file(tmp_path, "b", "files", "artifact-1", data_b)

    status = get_status()
    assert "files" in status.repos
    repo = status.repos["files"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with open(artifact_path, "rb") as f:
        assert f.read() == data_b
    assert artifact_path.samefile(Path("/run/rauc/artifacts/files/artifact-1"))

    # install a different file artifact and check result
    data_c = b"content-c"
    do_install_file(tmp_path, "c", "files", "artifact-2", data_c)

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

    # test status output in shell format
    out, err, exitcode = run("rauc status --output-format=shell")
    assert exitcode == 0
    out = out.splitlines()
    assert "RAUC_REPOS='1 2'" in out
    assert "RAUC_REPO_ARTIFACTS_2='1'" in out
    assert "RAUC_REPO_ARTIFACT_NAME_2_1='artifact-2'" in out
    assert "RAUC_REPO_ARTIFACT_INSTANCES_2_1='1'" in out
    assert "RAUC_REPO_ARTIFACT_INSTANCE_ACTIVE_2_1_1='1'" in out

    # test status output in readable format
    out, err, exitcode = run("rauc status --output-format=readable")
    assert exitcode == 0
    assert "[artifact-2]" in out
    out = out.splitlines()
    assert "  type: trees" in out
    assert "  type: files" in out


def test_tree_install(rauc_dbus_service_with_system, tmp_path):
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one tree artifact and check result
    data_a = b"content-a"
    do_install_tree(tmp_path, "a", "trees", "artifact-1", {"file-a": data_a})
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
    do_install_tree(tmp_path, "b", "trees", "artifact-1", {"file-b": data_b})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-b", "rb") as f:
        assert f.read() == data_b
    # old file must be gone
    assert not (artifact_path / "file-a").exists()
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-1"))

    # install a different tree artifact and check result
    data_c = b"content-c"
    do_install_tree(tmp_path, "c", "trees", "artifact-2", {"file-a": data_c})
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
    do_install_file(tmp_path, "a", "files", "artifact-1", data_a)

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
    do_install_tree(tmp_path, "b", "trees", "artifact-1", {"file-a": data_b})
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


def test_tree_in_use(rauc_dbus_service_with_system, tmp_path):
    status = get_status()
    assert set(status.repos.keys()) == {"files", "trees"}
    assert set(status.repos["files"].artifacts) == set()
    assert set(status.repos["trees"].artifacts) == set()

    # install one tree artifact and check result
    data_a = b"content-a"
    do_install_tree(tmp_path, "a", "trees", "artifact-1", {"file-a": data_a})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-a", "rb") as f:
        assert f.read() == data_a
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-1"))

    # open a file from this artifact and remember the full path
    active_file_path = (artifact_path / "file-a").resolve()
    active_file = open(active_file_path, "rb")

    # install another tree artifact and check result
    data_b = b"content-b"
    do_install_tree(tmp_path, "b", "trees", "artifact-2", {"file-b": data_b})
    status = get_status()
    assert "trees" in status.repos
    repo = status.repos["trees"]
    assert "artifact-1" not in repo.referenced_artifacts
    assert "artifact-2" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-2"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with open(artifact_path / "file-b", "rb") as f:
        assert f.read() == data_b
    # old file must be gone
    assert not (artifact_path / "file-a").exists()
    assert artifact_path.samefile(Path("/run/rauc/artifacts/trees/artifact-2"))

    active_file.close()
    with open(active_file_path, "rb") as f:
        assert f.read() == data_a


@needs_composefs
def test_composefs_install(rauc_dbus_service_with_system_composefs, tmp_path):
    status = get_status()
    assert "composefs" in status.repos
    assert set(status.repos["composefs"].artifacts) == set()

    # install one composefs artifact and check result
    data_a = b"content-a" * 1024
    do_install_composefs(tmp_path, "a", "composefs", "artifact-1", {"file-a": data_a})
    status = get_status()
    assert "composefs" in status.repos
    repo = status.repos["composefs"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with mounted_composefs(tmp_path, artifact_path / "image.cfs", repo.path / ".rauc-cfs-store") as mount_path:
        run_tree(mount_path)
        with open(mount_path / "file-a", "rb") as f:
            assert f.read() == data_a
    assert artifact_path.samefile(Path("/run/rauc/artifacts/composefs/artifact-1"))

    # update one composefs artifact and check result
    data_b = b"content-b" * 1024
    do_install_composefs(tmp_path, "b", "composefs", "artifact-1", {"file-b": data_b})
    status = get_status()
    assert "composefs" in status.repos
    repo = status.repos["composefs"]
    assert "artifact-1" in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-1"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with mounted_composefs(tmp_path, artifact_path / "image.cfs", repo.path / ".rauc-cfs-store") as mount_path:
        run_tree(mount_path)
        with open(mount_path / "file-b", "rb") as f:
            assert f.read() == data_b
    # old file must be gone
    assert not (artifact_path / "file-a").exists()
    assert artifact_path.samefile(Path("/run/rauc/artifacts/composefs/artifact-1"))

    # install a different composefs artifact and check result
    data_c = b"content-c" * 1024
    data_d = b"content-d" * 1024  # fetch multiple objects to exercise sorting
    do_install_composefs(
        tmp_path,
        "c",
        "composefs",
        "artifact-2",
        {
            "file-a": data_c,
            "file-b": data_b,
            "file-d": data_d,
        },
    )
    status = get_status()
    assert "composefs" in status.repos
    repo = status.repos["composefs"]
    assert "artifact-2" in repo.referenced_artifacts
    assert "artifact-1" not in repo.referenced_artifacts

    artifact_path = repo.path / "artifact-2"
    run_tree(repo.path)
    assert artifact_path.is_symlink()
    with mounted_composefs(tmp_path, artifact_path / "image.cfs", repo.path / ".rauc-cfs-store") as mount_path:
        run_tree(mount_path)
        with open(mount_path / "file-a", "rb") as f:
            assert f.read() == data_c
    assert artifact_path.samefile(Path("/run/rauc/artifacts/composefs/artifact-2"))
    artifact_path = repo.path / "artifact-1"
    assert not artifact_path.exists()
    assert not Path("/run/rauc/artifacts/composefs/artifact-1").exists()
