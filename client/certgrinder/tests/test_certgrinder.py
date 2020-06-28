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
import subprocess
import urllib.request

import pytest
from certgrinder.certgrinder import Certgrinder, main, parse_args
from cryptography import x509
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID


def test_certgrinderd_broken_configfile(
    tmpdir_factory, capsys, certgrinderd_broken_yaml_configfile
):
    """Test certgrinderd with a broken config."""
    mockargs = [
        "--path",
        str(tmpdir_factory.mktemp("certificates")),
        "--domain-list",
        "example.com,www.example.com",
        "--certgrinderd",
        f"server/certgrinderd/certgrinderd.py --config-file {certgrinderd_broken_yaml_configfile}",
        "--debug",
        "get",
        "certificate",
    ]
    with pytest.raises(SystemExit) as E:
        main(mockargs)
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    captured = capsys.readouterr()
    assert "Unable to parse YAML config file" in captured.err


def test_certgrinderd_fail(tmpdir_factory, certgrinderd_env, capsys):
    """Test a failing certbot."""
    mockargs = [
        "--path",
        str(tmpdir_factory.mktemp("certificates")),
        "--domain-list",
        "example.com,www.example.com",
        "--certgrinderd",
        f"server/certgrinderd/certgrinderd.py --certbot-command /bin/false --acme-zone acme.example.com",
        "--debug",
        "get",
        "certificate",
    ]
    with pytest.raises(SystemExit) as E:
        main(mockargs)
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    captured = capsys.readouterr()
    assert "certbot command returned non-zero exit code" in captured.err


def test_certgrinderd_broken_csr(
    csr_with_two_cn, certgrinderd_env, certgrinderd_configfile
):
    """Test calling certgrinderd with an invalid CSR."""
    if certgrinderd_configfile[0] != "dns":
        # we only need to test this once
        return

    p = subprocess.Popen(
        [
            "server/certgrinderd/certgrinderd.py",
            "--config-file",
            certgrinderd_configfile[1],
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # send the CSR to stdin and save stdout (the cert chain) + stderr (the certgrinderd logging)
    certgrinderd_stdout, certgrinderd_stderr = p.communicate(
        input=csr_with_two_cn.encode("ASCII")
    )
    assert p.returncode == 1
    assert (
        "CSR is not valid (has more or less than 1 CN), bailing out"
        in certgrinderd_stderr.decode("ASCII")
    ), "Did not find expected error message with broken CSR"


def test_get_certificate(
    pebble_server,
    certgrinderd_configfile,
    tmp_path_factory,
    certgrinderd_env,
    caplog,
    capsys,
    tmpdir_factory,
):
    """Get a couple of certificates and check that they look right."""
    caplog.set_level(logging.DEBUG)
    mockargs = [
        "--path",
        str(tmpdir_factory.mktemp("certificates")),
        "--domain-list",
        "example.com,www.example.com",
        "--domain-list",
        "example.net",
        "--certgrinderd",
        f"server/certgrinderd/certgrinderd.py --config-file {certgrinderd_configfile[1]} --acme-server-url https://127.0.0.1:14000/dir",
        "--debug",
    ]
    if certgrinderd_configfile[0] == "dns":
        # include a couple of post renew hook for one of the cert operations
        mockargs += ["--post-renew-hooks", "true", "--post-renew-hooks", "false"]

    with pytest.raises(SystemExit) as E:
        main(mockargs + ["get", "certificate"])
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

    # only check certs if we expect to get any
    if certgrinderd_configfile[0] == "":
        captured = capsys.readouterr()
        assert (
            "No more challenge types to try, unable to get certificate" in captured.err
        ), "Did not find expected errormessage with no challenge types enabled"
    else:
        # check that the certificates were issued correctly
        for domainset in ["example.com,www.example.com", "example.net"]:
            domains = domainset.split(",")
            certpath = os.path.join(mockargs[1], domains[0] + ".crt")
            with open(certpath, "rb") as f:
                certificate = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )
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

            with pytest.raises(SystemExit) as E:
                main(mockargs + ["show", "certificate"])
            assert str(certificate.serial_number) in caplog.text
            assert str(certificate.subject) in caplog.text


def test_show_spki(tmp_path_factory, caplog, tmpdir_factory):
    """Test the 'show spki' subcommand."""
    # SPKI is output at level INFO
    caplog.set_level(logging.INFO)
    parser, args = parse_args(
        [
            "--certgrinder",
            "true",
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

    with pytest.raises(ValueError):
        certgrinder.generate_tlsa_record(derkey=public_key_der_bytes, tlsatype="1337")


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


def test_no_domainlist(caplog):
    """Test Certgrinder with no domain-list config."""
    certgrinder = Certgrinder()
    with pytest.raises(SystemExit) as E:
        certgrinder.configure({})
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "No domain-list(s) configured." in caplog.text


def test_no_certgrinderd(caplog):
    """Test Certgrinder with no certgrinderd in config."""
    certgrinder = Certgrinder()
    with pytest.raises(SystemExit) as E:
        certgrinder.configure({"domain-list": ["example.com"]})
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "No certgrinderd command configured." in caplog.text


def test_no_path(caplog):
    """Test Certgrinder with no path in config."""
    certgrinder = Certgrinder()
    with pytest.raises(SystemExit) as E:
        certgrinder.configure({"domain-list": ["example.com"], "certgrinderd": "true"})
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "No configured path" in caplog.text


def test_nonexistant_path(caplog):
    """Test Certgrinder with wrong path setting."""
    certgrinder = Certgrinder()
    with pytest.raises(SystemExit) as E:
        certgrinder.configure(
            {
                "domain-list": ["example.com,www.example.com"],
                "path": "/nonexistant",
                "certgrinderd": "true",
            }
        )
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "Configured path /nonexistant does not exist" in caplog.text


def test_permission_denied_path(caplog):
    """Test Certgrinder with a path with no permissions."""
    certgrinder = Certgrinder()
    with pytest.raises(SystemExit) as E:
        certgrinder.configure(
            {
                "domain-list": ["example.com,www.example.com"],
                "path": "/dev",
                "certgrinderd": "true",
            }
        )
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "Permission error while accessing configured path" in caplog.text


def test_syslog_connect(tmpdir_factory, caplog):
    """Test syslog connect functionality."""
    certgrinder = Certgrinder()
    certgrinder.configure(
        {
            "domain-list": ["example.com,www.example.com"],
            "path": str(tmpdir_factory.mktemp("certificates")),
            "syslog-socket": "/dev/log",
            "syslog-facility": "LOG_LOCAL0",
            "certgrinderd": "true",
        }
    )


def test_syslog_connect_wrong_socket(tmpdir_factory, caplog):
    """Test syslog connect functionality."""
    certgrinder = Certgrinder()
    with pytest.raises(FileNotFoundError):
        certgrinder.configure(
            {
                "domain-list": ["example.com,www.example.com"],
                "path": str(tmpdir_factory.mktemp("certificates")),
                "syslog-socket": "/dev/notlog",
                "syslog-facility": "LOG_LOCAL0",
                "certgrinderd": "true",
            }
        )


def test_create_and_chmod_keypair(tmpdir_factory, caplog):
    """Test generating ed2519 keypair, and chmod correcting."""
    certgrinder = Certgrinder()
    with pytest.raises(ValueError):
        keypair = certgrinder.generate_private_key("foo")
    keypair = certgrinder.generate_private_key("ed25519")
    assert isinstance(keypair, openssl.ed25519.Ed25519PrivateKey)
    path = os.path.join(tmpdir_factory.mktemp("certificates"), "test.key")
    with pytest.raises(ValueError):
        certgrinder.save_keypair(keypair="notakey", path=path)
    certgrinder.save_keypair(keypair=keypair, path=path)
    assert (
        oct(os.stat(path).st_mode)[4:] == "0640"
    ), "Keypair saved with wrong permissions"
    os.chmod(path, 0o777)
    # loading the keypair should fix the mode to 0640
    certgrinder.load_keypair(path)
    assert (
        oct(os.stat(path).st_mode)[4:] == "0640"
    ), "Keypair saved with wrong permissions"
    assert "has incorrect permissions, fixing to 0640" in caplog.text


def test_check_certificate_issuer_empty_invalid_ca_cn_list(signed_certificate, caplog):
    """Test the check_certificate_issuer() method with an empty invalid_ca_cn_list."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()
    assert (
        certgrinder.check_certificate_issuer(
            certificate=signed_certificate, invalid_ca_cn_list=[]
        )
        is True
    ), "check_certificate_issuer() did not return True with an empty invalid_ca_cn_list"
    assert "We have an empty invalid_ca_cn_list, returning True" in caplog.text


def test_check_certificate_issuer_selfsigned(selfsigned_certificate, caplog):
    """Test the check_certificate_issuer() method with a selfsigned cert."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()
    assert (
        certgrinder.check_certificate_issuer(
            certificate=selfsigned_certificate, invalid_ca_cn_list=["badca"]
        )
        is False
    ), "check_certificate_issuer() did not return False with a selfsigned cert"
    assert "This certificate is selfsigned, returning False" in caplog.text


def test_check_certificate_issuer_invalid_ca(signed_certificate, caplog):
    """Test the check_certificate_issuer() method with a cert issued by an invalid CA."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()
    assert (
        certgrinder.check_certificate_issuer(
            certificate=signed_certificate, invalid_ca_cn_list=["example.net"]
        )
        is False
    ), "check_certificate_issuer() did not return False when checking a cert issued by a CA in the invalid_ca_cn_list"
    assert "This certificate was issued by a CA CN" in caplog.text


def test_check_certificate_expiry(selfsigned_certificate, caplog):
    """Test the check_certificate_expiry() method with a cert valid for 10 days."""
    assert (
        Certgrinder().check_certificate_expiry(
            certificate=selfsigned_certificate, threshold_days=30
        )
        is False
    ), "check_certficate_expiry() did not return False with a cert with 10 days validity"


def test_check_certificate_validity(
    selfsigned_certificate, signed_certificate, known_public_key, caplog
):
    """Test the various failure modes of the check_certificate_validity() method."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()

    assert (
        certgrinder.check_certificate_validity(
            certificate=signed_certificate,
            invalid_ca_cn_list=["example.net"],
            threshold_days=30,
            san_names=["example.com"],
        )
        is False
    ), "check_certificate_validity() did not return False when checking a cert issued by a CA in the invalid_ca_cn_list"
    assert "CN is on our list of invalid CAs" in caplog.text
    caplog.clear()

    assert (
        certgrinder.check_certificate_validity(
            certificate=signed_certificate,
            invalid_ca_cn_list=["badca"],
            threshold_days=100,
            san_names=["example.com"],
        )
        is False
    ), "check_certificate_validity() did not return False when checking a cert with 90 days validity when the threshold is 100"
    assert "Certificate expires in less than" in caplog.text
    caplog.clear()

    assert (
        certgrinder.check_certificate_validity(
            certificate=signed_certificate,
            invalid_ca_cn_list=["badca"],
            threshold_days=30,
            san_names=["example.com"],
            public_key=known_public_key,
        )
        is False
    ), "check_certificate_validity() did not return False when checking a cert with a wrong public key"
    assert "Certificate public key is different from the expected" in caplog.text
    caplog.clear()

    assert (
        certgrinder.check_certificate_validity(
            certificate=signed_certificate,
            invalid_ca_cn_list=["badca"],
            threshold_days=30,
            san_names=["example.com"],
            subject="wrong",
        )
        is False
    ), "check_certificate_validity() did not return False when checking a cert with a wrong subject"
    assert "Certificate subject is different from the expected" in caplog.text
    caplog.clear()

    assert (
        certgrinder.check_certificate_validity(
            certificate=signed_certificate,
            invalid_ca_cn_list=["badca"],
            threshold_days=30,
            san_names=["example.org"],
        )
        is False
    ), "check_certificate_validity() did not return False when checking a cert with a wrong san_names list"
    assert "Certificate SAN name list is different from the expected" in caplog.text


def test_get_certgrinderd_command_staging(
    tmpdir_factory, certgrinderd_configfile, caplog
):
    """Make sure we use the staging url when using --staging."""
    caplog.set_level(logging.DEBUG)
    parser, args = parse_args(
        [
            "--path",
            str(tmpdir_factory.mktemp("certificates")),
            "--domain-list",
            "example.com,www.example.com",
            "--certgrinderd",
            f"server/certgrinderd/certgrinderd.py --config-file {certgrinderd_configfile[1]}",
            "--staging",
            "get",
            "certificate",
        ]
    )
    certgrinder = Certgrinder()
    certgrinder.configure(userconfig=vars(args))
    command = certgrinder.get_certgrinderd_command()
    assert "https://acme-staging-v02.api.letsencrypt.org/directory" in command
    assert "'invalid-ca-cn-list': []" in caplog.text


def test_parse_certgrinderd_output_not_pem(
    caplog, tmpdir_factory, known_csr, signed_certificate
):
    """Test the various failure modes of the parse_certgrinderd_output()."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
        }
    )
    csr = x509.load_pem_x509_csr(known_csr.encode("ascii"), default_backend())
    assert (
        certgrinder.parse_certgrinderd_output(
            certgrinderd_stdout=b"NOT_A_PEM_CERT", csr=csr
        )
        is None
    ), "The parse_certgrinderd_output() method did not return None with a non-PEM certificate input"
    assert "This is stdout from the certgrinderd call" in caplog.text
    assert "NOT_A_PEM_CERT" in caplog.text
    caplog.clear()

    stdout = b"""-----BEGIN CERTIFICATE-----
NOT_A_PEM
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ALSO_NOT_A_PEM
-----END CERTIFICATE-----"""
    assert (
        certgrinder.parse_certgrinderd_output(certgrinderd_stdout=stdout, csr=csr)
        is None
    ), "The parse_certgrinderd_output() method did not return None with a PEM-ish but invalid certificate input"
    assert "This is stdout from the certgrinderd call" in caplog.text
    assert "ALSO_NOT_A_PEM" in caplog.text
    caplog.clear()

    stdout = signed_certificate.public_bytes(primitives.serialization.Encoding.PEM)
    stdout += b"""-----BEGIN CERTIFICATE-----
ALSO_NOT_A_PEM
-----END CERTIFICATE-----"""
    assert (
        certgrinder.parse_certgrinderd_output(certgrinderd_stdout=stdout, csr=csr)
        is None
    ), "The parse_certgrinderd_output() method did not return None with a non-PEM certificate input"
    assert (
        "The Certgrinder server did not return a valid PEM formatted intermediate."
        in caplog.text
    )
    assert "This is stdout from the certgrinderd call" in caplog.text
    assert "ALSO_NOT_A_PEM" in caplog.text


def test_get_certificate_method(caplog, tmpdir_factory, known_csr, signed_certificate):
    """Test various failure modes of the get_certificate() method."""
    caplog.set_level(logging.DEBUG)
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
            "log-level": "DEBUG",
        }
    )
    certgrinder.load_domainset(certgrinder.conf["domain-list"][0].split(","))
    csr = x509.load_pem_x509_csr(known_csr.encode("ascii"), default_backend())
    stdout = signed_certificate.public_bytes(primitives.serialization.Encoding.PEM) * 2
    assert (
        certgrinder.get_certificate(csr=csr, stdout=stdout) is False
    ), "The get_certificate() method did not return False as expected"
    assert "Certificate public key is different from the expected" in caplog.text
    assert "Certificate is not valid." in caplog.text
    assert "Did not get a certificate :(" in caplog.text
    caplog.clear()


def test_check_certificate_no_file(caplog, tmpdir_factory):
    """Make sure the check_certificate() method behaves if the file doesn't exist."""
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
            "log-level": "DEBUG",
        }
    )
    assert (
        certgrinder.check_certificate() is False
    ), "check_certificate() method did not return False as expected when called with a nonexiststant certificate path"
    assert "not found" in caplog.text
    assert (
        certgrinder.error is True
    ), "certgrinder.error is not True as expected after an error happened"


def test_check_certificate_not_cert(caplog, tmpdir_factory):
    """Make sure the check_certificate() method behaves with a file that isn't a cert."""
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
            "log-level": "DEBUG",
        }
    )
    certgrinder.certificate_path = pathlib.Path(__file__).absolute()
    with pytest.raises(ValueError):
        certgrinder.check_certificate()


def test_check_certificate_selfsigned(caplog, tmpdir_factory, selfsigned_certificate):
    """Make sure the check_certificate() method behaves if the cert is selfsigned."""
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
            "log-level": "DEBUG",
        }
    )
    certgrinder.load_domainset(certgrinder.conf["domain-list"][0].split(","))
    assert (
        certgrinder.check_certificate(certificate=selfsigned_certificate) is False
    ), "check_certificate() method did not return False as expected when called with a selfsigned certificate"
    assert (
        certgrinder.error is True
    ), "certgrinder.error is not True as expected after an error happened"


def test_show_certificate(caplog, tmpdir_factory):
    """Make sure the show_certificate() method logs the right error when file not found."""
    certgrinder = Certgrinder()
    certgrinder.configure(
        userconfig={
            "path": str(tmpdir_factory.mktemp("certificates")),
            "domain-list": ["example.com,www.example.com"],
            "certgrinderd": "true",
            "log-level": "DEBUG",
        }
    )
    certgrinder.certificate_path = "/nonexistant"
    assert (
        certgrinder.show_certificate() is None
    ), "show_certificate() did not return None as expected"
