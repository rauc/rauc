import pytest

from helper import run


def test_noargs():
    out, err, exitcode = run("rauc")

    assert exitcode == 1
    assert out.startswith("Usage:\n  rauc [OPTION?] <COMMAND>\n\nOptions:")
    assert err == ""


def test_invalid_arg():
    out, err, exitcode = run("rauc info --foobar")

    assert exitcode == 1
    assert out.startswith("Usage:\n  rauc [OPTION?] info <BUNDLE>\n\nPrint bundle info\n\nInfo options:")
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
