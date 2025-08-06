import shutil

from conftest import have_faketime
from helper import run
from decode_cms import decode_cms


# each signer cert's issuer + serial
SIGNERS = {
    "release-1": ("O=Test Org, CN=Test Org Provisioning CA Release", 1),
    "release-2018": ("O=Test Org, CN=Test Org Provisioning CA Release", 2),
    "autobuilder-1": ("O=Test Org, CN=Test Org Provisioning CA Development", 1),
    "autobuilder-2": ("O=Test Org, CN=Test Org Provisioning CA Development", 2),
}


def get_cms(bundle_path):
    with open(bundle_path, "rb") as bundle_file:
        # read CMS/signature size from bundle (8 bytes)
        bundle_file.seek(-8, 2)
        cms_length_bytes = bundle_file.read(8)
        # calculate CMS offset and length
        cms_length = int.from_bytes(cms_length_bytes, "big")
        cms_start = bundle_file.tell() - cms_length - 8
        # read CMS data from bundle file
        bundle_file.seek(cms_start)
        cms_data = bundle_file.read(cms_length)

    return decode_cms(cms_data)


# for convenience, support both a bytes object or a file path
def get_signers(cms_or_path):
    if isinstance(cms_or_path, dict):
        cms = cms_or_path
    else:
        cms = get_cms(cms_or_path)
    assert cms["contentType"] == "signedData"

    # support multiple signers by collecting into a set
    cms_signers = {(si["issuer"], si["serial"]) for si in cms["signerInfos"]}

    return cms_signers


def get_cert_subjects(cms_or_path):
    if isinstance(cms_or_path, dict):
        cms = cms_or_path
    else:
        cms = get_cms(cms_or_path)
    assert cms["contentType"] == "signedData"

    cms_subjects = {cert["subject"] for cert in cms["certs"]}

    return cms_subjects


def test_resign(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-bundle.raucb", in_bundle)
    assert get_signers(in_bundle) == {SIGNERS["release-1"]}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    assert get_signers(out_bundle) == {SIGNERS["autobuilder-1"]}

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_verity(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-verity-bundle.raucb", in_bundle)
    assert get_signers(in_bundle) == {SIGNERS["release-1"]}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    assert get_signers(out_bundle) == {SIGNERS["autobuilder-1"]}

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_append(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-bundle.raucb", in_bundle)
    assert get_signers(in_bundle) == {SIGNERS["release-1"]}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --append"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    assert get_signers(out_bundle) == {SIGNERS["release-1"], SIGNERS["autobuilder-1"]}

    # no path for the signature by Autobuilder-1
    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1
    assert "unable to get local issuer certificate" in err

    # no path for the signature by Release-1
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 1
    assert "unable to get local issuer certificate" in err

    # dev-ca also allows release signatures
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info {out_bundle}")
    assert exitcode == 0
    assert (
        "Verified detached signature by 'O = Test Org, CN = Test Org Autobuilder-1', 'O = Test Org, CN = Test Org Release-1'"
        in err
    )


def test_resign_verity_append(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-verity-bundle.raucb", in_bundle)
    assert get_signers(in_bundle) == {SIGNERS["release-1"]}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --append"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    assert get_signers(out_bundle) == {SIGNERS["release-1"], SIGNERS["autobuilder-1"]}

    # no path for the signautre by Autobuilder-1
    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 1
    assert "unable to get local issuer certificate" in err

    # no path for the signature by Release-1
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 1
    assert "unable to get local issuer certificate" in err

    # dev-ca also allows release signatures
    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-ca.pem info {out_bundle}")
    assert exitcode == 0
    assert (
        "Verified inline signature by 'O = Test Org, CN = Test Org Autobuilder-1', 'O = Test Org, CN = Test Org Release-1'"
        in err
    )


def test_resign_crypt(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-crypt-bundle-unencrypted.raucb", in_bundle)
    assert get_signers(in_bundle) == {SIGNERS["autobuilder-1"]}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/dev-only-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --signing-keyring openssl-ca/rel-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    assert get_signers(out_bundle) == {SIGNERS["release-1"]}

    out, err, exitcode = run(f"rauc --keyring openssl-ca/dev-only-ca.pem info {out_bundle}")
    assert exitcode == 1

    out, err, exitcode = run(f"rauc --keyring openssl-ca/rel-ca.pem info {out_bundle}")
    assert exitcode == 0


def test_resign_output_exists(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-bundle.raucb", in_bundle)

    out_bundle = tmp_path / "out.raucb"
    out_bundle.touch(exist_ok=False)

    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/dev-ca.pem"
        f" resign {in_bundle} {out_bundle}"
    )

    assert exitcode == 1
    assert "already exists" in err

    assert out_bundle.exists()


@have_faketime
def test_resign_extend_not_expired(tmp_path):
    out1_bundle = tmp_path / "out1.raucb"

    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {out1_bundle}"
    )
    assert exitcode == 0

    assert out1_bundle.exists()

    out2_bundle = tmp_path / "out2.raucb"

    out, err, exitcode = run(
        'faketime "2018-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {out1_bundle} {out2_bundle}"
    )
    assert exitcode == 0

    assert out2_bundle.exists()


@have_faketime
def test_resign_extend_expired_no_verify(tmp_path):
    out1_bundle = tmp_path / "out1.raucb"

    out, err, exitcode = run(
        'faketime "2018-01-01"'
        " rauc"
        " --cert openssl-ca/rel/release-2018.cert.pem"
        " --key openssl-ca/rel/private/release-2018.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" bundle install-content {out1_bundle}"
    )
    assert exitcode == 0
    assert out1_bundle.exists()

    cms = get_cms(out1_bundle)
    assert len(cms["signerInfos"]) == 1
    assert cms["signerInfos"][0]["issuer"] == SIGNERS["release-2018"][0]
    assert cms["signerInfos"][0]["serial"] == SIGNERS["release-2018"][1]
    signing_time = cms["signerInfos"][0]["signedAttrs"]["signingTime"]
    assert signing_time[0] == "utcTime"
    assert signing_time[1].year == 2018
    assert signing_time[1].month == 1
    assert signing_time[1].day == 1

    out2_bundle = tmp_path / "out2.raucb"

    out, err, exitcode = run(
        'faketime "2020-10-01"'
        " rauc"
        " --cert openssl-ca/rel/release-1.cert.pem"
        " --key openssl-ca/rel/private/release-1.pem"
        " --no-verify "
        f" resign {out1_bundle} {out2_bundle}"
    )
    assert exitcode == 0

    assert out2_bundle.exists()

    cms = get_cms(out2_bundle)
    assert len(cms["signerInfos"]) == 1
    assert cms["signerInfos"][0]["issuer"] == SIGNERS["release-1"][0]
    assert cms["signerInfos"][0]["serial"] == SIGNERS["release-1"][1]
    signing_time = cms["signerInfos"][0]["signedAttrs"]["signingTime"]
    assert signing_time[0] == "utcTime"
    assert signing_time[1].year == 2020
    assert signing_time[1].month == 10
    assert signing_time[1].day == 1


def test_resign_append_intermediate(tmp_path):
    # copy to tmp path for safe ownership check
    in_bundle = tmp_path / "in.raucb"
    shutil.copyfile("good-verity-bundle.raucb", in_bundle)
    cms = get_cms(in_bundle)
    assert get_signers(cms) == {SIGNERS["release-1"]}
    assert get_cert_subjects(cms) == {"O=Test Org, CN=Test Org Release-1"}

    out_bundle = tmp_path / "out.raucb"
    out, err, exitcode = run(
        "rauc"
        " --cert openssl-ca/dev/autobuilder-1.cert.pem"
        " --key openssl-ca/dev/private/autobuilder-1.pem"
        " --keyring openssl-ca/rel-ca.pem"
        f" resign {in_bundle} {out_bundle}"
        " --intermediate openssl-ca/dev/ca.cert.pem"
        " --append"
        " --signing-keyring openssl-ca/dev-only-ca.pem"
    )
    assert exitcode == 0
    assert out_bundle.exists()
    cms = get_cms(out_bundle)
    assert get_signers(cms) == {SIGNERS["release-1"], SIGNERS["autobuilder-1"]}
    assert get_cert_subjects(cms) == {
        "O=Test Org, CN=Test Org Release-1",
        "O=Test Org, CN=Test Org Autobuilder-1",
        "O=Test Org, CN=Test Org Provisioning CA Development",
    }

    # no path for the signature by Release-1
    out, err, exitcode = run(f"rauc --keyring openssl-ca/root-ca.pem info {out_bundle}")
    assert exitcode == 1
    assert "unable to get local issuer certificate" in err
