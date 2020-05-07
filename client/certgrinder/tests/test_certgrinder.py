# type: ignore
import logging
import os
import pathlib
import ssl
import urllib.request

from certgrinder.certgrinder import Certgrinder
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID


def test_get_certificate(
    pebble_server, certgrinder_configfile, tmp_path_factory, certgrinderd_env, caplog
):
    """
    Get a certificate and check that it looks right
    """
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder(
        configfile=certgrinder_configfile,
        staging=False,
        showtlsa="",
        checktlsa="",
        nameserver="",
        showspki=False,
        check=False,
    )
    certgrinder.main()

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
    for domainset in certgrinder.conf["domainlist"]:
        domains = domainset.split(",")
        certpath = os.path.join(certgrinder.conf["path"], domains[0] + ".crt")
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


def test_generate_tlsa(certgrinder_configfile, known_public_key):
    """
    Test the TLSA record generation from a known public key
    """
    # TLSA records are output at level INFO
    certgrinder = Certgrinder(
        configfile=certgrinder_configfile,
        staging=False,
        showtlsa="",
        checktlsa="",
        nameserver="",
        showspki=False,
        check=False,
    )

    # test with a known public key
    public_key_der_bytes = known_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tlsa310 = "30820222300D06092A864886F70D01010105000382020F003082020A0282020100B7385B728CCD6234B579EE7918329DA988DEB18B83EA7C45422B8281F53682AC57C93AC428EB3BFF216926662CC69D34FC2D8EE44673C9C87EF8DCDFFDE93FC5F483834465F075376691DA46FB157B68E3D58E16B5A5C0FAF026A6EAADC1FD47E55C0B2E98669CD13A9A42AFC7180F88769E409A46029CCE0FE3184A66FF3A1ABBB848CF7064EF299246CA42175EFBD30FA2A2437B19EFC9DA7BCAFA74D583DA8397B84B3492E7C084AA31B49CF3CDE1A661F0B112F2676F1BA6C9EB9EB42EB104EE7F0C0859D9F0C3C5821602B7D628C2E62195D2174CEAABAA2794DAEBA0EB7C165A2B6EA146CEACA08EC0534DDBF74149C694B6D03EC8CAC8251215853B4171588C5B3D8B5BB4B9C9960F75B540A61759F44474648ACF9810ABA65519379030639769EECC782EF1D0B81E956839B23B77A753868625B6648E5E0ACFD31F40EDB7B26CB5D9EAB91FECDEB9EFEF5752F4F5E9A92C87B9D20732D13FE9077ABD5767065756C01B5264722BB2740AF5A1EE2A60B08C5814C8CED874DBCE2F034A364BC59473BCB65B6463DE3E6657C6B287B02050A005D74C4617735C27B324FAE004491BB646302940BB7239FDC997F3F5EC27CA683F1742F5C279780B32CE33D24FA11B63ED390BAC417CC1206FFF49FBCE203F9C31D9AAFA106FC7169723F00BC6A59E0142790135C131D38BF549183ECE52BC683FD42D07057BABB6259E810203010001"
    assert (
        certgrinder.generate_tlsa(derkey=public_key_der_bytes, tlsatype=(3, 1, 0))
        == tlsa310
    ), "Generation of DANE-EE Publickey Full (3 1 0) TLSA Record failed"

    tlsa311 = "D6F9BA311A04F711C19C459266D53561145AC1ABF403E368976AFE51B41FAE53"
    assert (
        certgrinder.generate_tlsa(derkey=public_key_der_bytes, tlsatype=(3, 1, 1))
        == tlsa311
    ), "Generation of DANE-EE Publickey SHA256 (3 1 1) TLSA Record failed"

    tlsa312 = "048D0D297B5E525795CEEBB87C8CD18436766CB87DE3B5E50EE9863DB3A12FB8E639878A4B03A0C23CC2253257266F9A695EA24207CEF284EB6FD45322AE809A"
    assert (
        certgrinder.generate_tlsa(derkey=public_key_der_bytes, tlsatype=(3, 1, 2))
        == tlsa312
    ), "Generation of DANE-EE Publickey SHA512 (3 1 2) TLSA Record failed"


def test_generate_spki(certgrinder_configfile, known_public_key):
    """
    Test the SPKI pin-sha256 record generation from a known public key
    """
    # TLSA records are output at level INFO
    certgrinder = Certgrinder(
        configfile=certgrinder_configfile,
        staging=False,
        showtlsa="",
        checktlsa="",
        nameserver="",
        showspki=False,
        check=False,
    )

    # test with a known public key
    public_key_der_bytes = known_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = "1vm6MRoE9xHBnEWSZtU1YRRawav0A+Nol2r+UbQfrlM="
    assert (
        certgrinder.generate_spki(derkey=public_key_der_bytes) == spki
    ), "SPKI pin-sha256 generation failed"
