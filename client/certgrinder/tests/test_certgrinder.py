# type: ignore
"""certgrinder.py tests.

Runs with pytest and Tox.
"""
import base64
import hashlib
import logging
import os
import pathlib
import ssl
import urllib.request

import pytest
from certgrinder.certgrinder import Certgrinder, main, parse_args
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID


# INTEGRATION TESTS
def test_get_certificate(
    pebble_server,
    certgrinderd_configfile,
    tmp_path_factory,
    certgrinderd_env,
    caplog,
    tmpdir_factory,
):
    """Get a couple of certificates and check that they look right."""
    # caplog.set_level(logging.DEBUG)
    mockargs = [
        "--path",
        str(tmpdir_factory.mktemp("certificates")),
        "--domain-list",
        "example.com,www.example.com",
        "--domain-list",
        "example.net",
        "--certgrinderd",
        f"server/certgrinderd/certgrinderd.py --config-file {certgrinderd_configfile}",
        # "--debug",
        "get",
        "certificate",
    ]
    with pytest.raises(SystemExit) as E:
        main(mockargs)
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"

    # initialise a TLS context with the pebble minica.pem to download certs
    tls_context = ssl.create_default_context(
        cafile=str(
            pathlib.Path.home()
            / "go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem"
        )
    )

    # download intermediate cert
    with urllib.request.urlopen(
        "https://127.0.0.1:15000/intermediates/0", context=tls_context
    ) as u:
        intermediate = x509.load_pem_x509_certificate(u.read(), default_backend())

    # check that the certificates were issued correctly
    for domainset in ["example.com,www.example.com", "example.net"]:
        domains = domainset.split(",")
        certpath = os.path.join(mockargs[1], domains[0] + ".crt")
        with open(certpath, "rb") as f:
            certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
            # check that it was issued by our intermediate
            assert intermediate.subject == certificate.issuer
            # check that the cert has the right CN in subject
            name = x509.NameAttribute(
                NameOID.COMMON_NAME, domains[0].encode("idna").decode("utf-8")
            )
            cns = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            assert len(cns) == 1, "Certificate must have exactly one CN attribute"
            assert cns[0] == name, "Certificate CN does not match expected name"
            # make sure we have the full domainlist in SubjectAltName
            assert domains == certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(
                x509.DNSName
            ), "SubjectAltName extension does not contain the right list of domains"


def test_show_spki(tmp_path_factory, caplog, tmpdir_factory):
    """Test the 'show spki' subcommand."""
    # SPKI is output at level INFO
    caplog.set_level(logging.INFO)
    parser, args = parse_args(
        [
            "--path",
            str(tmpdir_factory.mktemp("certificates")),
            "--domain-list",
            "example.com,www.example.com",
            "show",
            "spki",
        ]
    )
    certgrinder = Certgrinder()
    certgrinder.configure(userconfig=vars(args))
    with pytest.raises(SystemExit) as E:
        certgrinder.grind(args)
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    # load public key
    keypair = serialization.load_pem_private_key(
        open(os.path.join(args.path, "example.com.key"), "rb").read(),
        password=None,
        backend=default_backend(),
    )
    derkey = keypair.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # calculate SPKI for the pubkey
    spki = base64.b64encode(hashlib.sha256(derkey).digest()).decode("ASCII")
    assert spki in caplog.text, "SPKI not found in output"


# UNIT TESTS (test individual methods)
def test_generate_tlsa(known_public_key):
    """Test the TLSA record generation from a known public key."""
    certgrinder = Certgrinder()

    # test with a known public key
    public_key_der_bytes = known_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tlsa310 = "30820222300D06092A864886F70D01010105000382020F003082020A0282020100B7385B728CCD6234B579EE7918329DA988DEB18B83EA7C45422B8281F53682AC57C93AC428EB3BFF216926662CC69D34FC2D8EE44673C9C87EF8DCDFFDE93FC5F483834465F075376691DA46FB157B68E3D58E16B5A5C0FAF026A6EAADC1FD47E55C0B2E98669CD13A9A42AFC7180F88769E409A46029CCE0FE3184A66FF3A1ABBB848CF7064EF299246CA42175EFBD30FA2A2437B19EFC9DA7BCAFA74D583DA8397B84B3492E7C084AA31B49CF3CDE1A661F0B112F2676F1BA6C9EB9EB42EB104EE7F0C0859D9F0C3C5821602B7D628C2E62195D2174CEAABAA2794DAEBA0EB7C165A2B6EA146CEACA08EC0534DDBF74149C694B6D03EC8CAC8251215853B4171588C5B3D8B5BB4B9C9960F75B540A61759F44474648ACF9810ABA65519379030639769EECC782EF1D0B81E956839B23B77A753868625B6648E5E0ACFD31F40EDB7B26CB5D9EAB91FECDEB9EFEF5752F4F5E9A92C87B9D20732D13FE9077ABD5767065756C01B5264722BB2740AF5A1EE2A60B08C5814C8CED874DBCE2F034A364BC59473BCB65B6463DE3E6657C6B287B02050A005D74C4617735C27B324FAE004491BB646302940BB7239FDC997F3F5EC27CA683F1742F5C279780B32CE33D24FA11B63ED390BAC417CC1206FFF49FBCE203F9C31D9AAFA106FC7169723F00BC6A59E0142790135C131D38BF549183ECE52BC683FD42D07057BABB6259E810203010001"
    assert (
        certgrinder.generate_tlsa_record(derkey=public_key_der_bytes, tlsatype="310")
        == tlsa310
    ), "Generation of DANE-EE Publickey Full (3 1 0) TLSA Record failed"

    tlsa311 = "D6F9BA311A04F711C19C459266D53561145AC1ABF403E368976AFE51B41FAE53"
    assert (
        certgrinder.generate_tlsa_record(derkey=public_key_der_bytes, tlsatype="311")
        == tlsa311
    ), "Generation of DANE-EE Publickey SHA256 (3 1 1) TLSA Record failed"

    tlsa312 = "048D0D297B5E525795CEEBB87C8CD18436766CB87DE3B5E50EE9863DB3A12FB8E639878A4B03A0C23CC2253257266F9A695EA24207CEF284EB6FD45322AE809A"
    assert (
        certgrinder.generate_tlsa_record(derkey=public_key_der_bytes, tlsatype="312")
        == tlsa312
    ), "Generation of DANE-EE Publickey SHA512 (3 1 2) TLSA Record failed"


def test_generate_spki(known_public_key):
    """Test the SPKI pin-sha256 record generation from a known public key."""
    certgrinder = Certgrinder()

    # test with a known public key
    public_key_der_bytes = known_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = "1vm6MRoE9xHBnEWSZtU1YRRawav0A+Nol2r+UbQfrlM="
    assert (
        certgrinder.generate_spki(derkey=public_key_der_bytes) == spki
    ), "SPKI pin-sha256 generation failed"


def test_argparse_version(capsys):
    """This is mostly here to demonstrate/test calling the main() function with args."""
    with pytest.raises(SystemExit) as E:
        main(["version"])
    assert E.type == SystemExit
    captured = capsys.readouterr()
    assert captured.out == f"Certgrinder version {Certgrinder.__version__}\n"


def test_argparse():
    """Test argparse works as expected."""
    parser, args = parse_args(["-D", "example.com", "show", "tlsa", "443", "tcp"])
    assert isinstance(getattr(args, "domain-list"), list)
    assert getattr(args, "domain-list") == ["example.com"]
    assert getattr(args, "command") == "show"
    assert getattr(args, "subcommand") == "tlsa"
    assert getattr(args, "tlsa-port") == "443"
    assert getattr(args, "tlsa-protocol") == "tcp"
