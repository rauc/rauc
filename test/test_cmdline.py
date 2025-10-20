import re

import pytest

from helper import run


def test_noargs():
    out, err, exitcode = run("rauc")

    assert exitcode == 1
    assert re.match(r"Usage:\s+rauc \[OPTION.\] <COMMAND>\s+Options:", out)
    assert err == ""


def test_invalid_arg():
    out, err, exitcode = run("rauc info --foobar")

    assert exitcode == 1
    assert re.match(r"Usage:\s+rauc \[OPTION.\] info <BUNDLE>\s+Print bundle info\s+Info options:", out)
    assert err == "Unknown option --foobar\n"


def test_invalid_cmd():
    out, err, exitcode = run("rauc dothis")

    assert exitcode == 1
    assert out.startswith("Invalid command 'dothis' given")
    assert err == ""


test_cmd_array_missing = [
    "rauc install",
    "rauc write-slot",
    "rauc install",
    "rauc write-slot",
    "rauc write-slot slot",
    "rauc info",
    "rauc bundle",
    "rauc bundle input",
    "rauc resign",
    "rauc resign input",
    "rauc replace-signature",
    "rauc replace-signature input",
    "rauc replace-signature input output",
]


@pytest.mark.parametrize("test_cmd", test_cmd_array_missing)
def test_missing_arg(test_cmd):
    out, err, exitcode = run(test_cmd)

    assert exitcode == 1


test_cmd_array_excess = [
    "rauc install bundle excess",
    "rauc write-slot source target excess",
    "rauc info bundle excess",
    "rauc bundle indir outbundle excess",
    "rauc resign inbundle outbundle excess",
    "rauc replace-signature inbundle insig outbundle excess",
]


@pytest.mark.parametrize("test_cmd", test_cmd_array_excess)
def test_excess_args(test_cmd):
    out, err, exitcode = run(test_cmd)

    assert exitcode == 1


def test_version():
    out, err, exitcode = run("rauc --version")

    assert exitcode == 0
    assert out.startswith("rauc ")
    assert err == ""


test_cmd_array_help = [
    "rauc",
    "rauc install",
    "rauc write-slot",
    "rauc info",
    "rauc bundle",
    "rauc resign",
    "rauc replace-signature",
]


@pytest.mark.parametrize("test_cmd", test_cmd_array_help)
def test_help(test_cmd):
    out, err, exitcode = run(test_cmd + " --help")

    assert exitcode == 0
    assert out.startswith("Usage:")
    assert err == ""


def test_install_invalid_local_paths():
    out, err, exitcode = run("rauc install foo")

    assert exitcode == 1
    assert "No such file" in err

    out, err, exitcode = run("rauc install foo.raucb")

    assert exitcode == 1
    assert "No such file" in err

    out, err, exitcode = run("rauc install /path/to/foo.raucb")

    assert exitcode == 1
    assert "No such file" in err
