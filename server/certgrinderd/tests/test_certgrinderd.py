"""certgrinderd.py tests.

Runs with pytest and Tox.
"""

import logging
from pathlib import Path
from typing import NamedTuple

import cryptography
import pytest

from certgrinderd.certgrinderd import Certgrinderd, main


def test_parse_csr(known_csr: str) -> None:
    """Test the parse_csr() method with a valid CSR."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(known_csr)
    assert isinstance(csr, cryptography.x509.CertificateSigningRequest), (
        "CSR should be a cryptography.x509.CertificateSigningRequest, but is not"
    )


def test_parse_broken_csr(known_csr: str) -> None:
    """Test the parse_csr() method with an invalid CSR."""
    certgrinderd = Certgrinderd()
    # use the known_csr with 1 line removed
    broken_csr = "\n".join(known_csr.split("\n")[:5] + known_csr.split("\n")[6:])
    with pytest.raises(ValueError, match="error parsing asn1 value"):
        certgrinderd.parse_csr(broken_csr)


def test_check_csr(known_csr: str, certgrinderd_env: None) -> None:
    """Test the check_csr() method with a valid CSR."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    csr = certgrinderd.parse_csr(known_csr)
    assert certgrinderd.check_csr(csr) is True, "CSR not valid"


def test_check_csr_two_cn(csr_with_two_cn: str, caplog: pytest.LogCaptureFixture, certgrinderd_env: None) -> None:
    """Test the check_csr method with a CSR with two CN."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_with_two_cn)
    assert certgrinderd.check_csr(csr) is False
    assert "has more or less than 1 CN" in caplog.text


def test_check_csr_not_permitted(
    csr_example_org: str, caplog: pytest.LogCaptureFixture, certgrinderd_env: None
) -> None:
    """Test the check_csr method with a CSR for domains not permitted by CERTGRINDERD_DOMAINSETS."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_example_org)
    assert certgrinderd.check_csr(csr) is False
    assert "CSR contains one or more names which are not permitted for this client" in caplog.text


def test_check_csr_not_permitted_2(
    csr_example_com_and_org: str, caplog: pytest.LogCaptureFixture, certgrinderd_env: None
) -> None:
    """Test the check_csr method with a CSR with 1 name not permitted by CERTGRINDERD_DOMAINSETS."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_example_com_and_org)
    assert certgrinderd.check_csr(csr) is False
    assert "CSR contains one or more names which are not permitted for this client" in caplog.text


def test_check_csr_with_cn_not_in_san_list(
    csr_with_cn_not_in_san_list: str, caplog: pytest.LogCaptureFixture, certgrinderd_env: None
) -> None:
    """Test the check_csr method with a CSR where the CN is not in the SAN list."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_with_cn_not_in_san_list)
    assert certgrinderd.check_csr(csr) is False
    assert "not found in SAN list" in caplog.text


def test_no_env(known_csr: str, caplog: pytest.LogCaptureFixture, no_certgrinderd_env: None) -> None:
    """Make sure we we log an error and exit if env["CERTGRINDERD_DOMAINSETS"] is not defined."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(known_csr)
    assert certgrinderd.check_csr(csr) is False
    assert "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out" in caplog.text, (
        "Did not find expected errormessage with undefined env['CERTGRINDERD_DOMAINSETS']"
    )


def test_debug_loglevel(caplog: pytest.LogCaptureFixture) -> None:
    """Test debug log-level."""
    caplog.set_level(logging.DEBUG)
    Certgrinderd({"log-level": "DEBUG"})
    assert "Running with config:" in caplog.text, "Config logmessage not found even though log-level is DEBUG"


def test_syslog() -> None:
    """Test connection to syslog socket."""
    Certgrinderd({"syslog-socket": "/dev/log", "syslog-facility": "LOG_LOCAL0"})


def test_syslog_wrong_socket() -> None:
    """Test connection to nonexistant syslog socket."""
    with pytest.raises(FileNotFoundError):
        Certgrinderd(
            {
                "syslog-socket": "/dev/logfoo",
                "syslog-facility": "LOG_LOCAL0",
                "log-level": "DEBUG",
            }
        )


def test_parse_certificate_chain_path(certificate_chain_file: "Path") -> None:
    """Test the parse_certificate_chain() method with a valid chain."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    certificate, issuer = certgrinderd.parse_certificate_chain(certpath=certificate_chain_file, expected_length=2)
    assert isinstance(certificate, cryptography.x509.Certificate), (
        f"certificate should be an instance of cryptography.x509.Certificate but it is {type(certificate)}"
    )
    assert isinstance(issuer, cryptography.x509.Certificate), (
        f"issuer should be an instance of cryptography.x509.Certificate but it is {type(issuer)}"
    )


def test_parse_certificate_chain_path_broken_cert(
    certificate_chain_file_broken_cert: "Path", caplog: pytest.LogCaptureFixture
) -> None:
    """Test the parse_certificate_chain() method with a chain where the cert is invalid."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as e:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_broken_cert, expected_length=2
        )
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    assert e.value.code == 1, "Exit code not 1 as expected"
    assert "Parsing certificate failed" in caplog.text, "Expected error message not found with a broken cert"


def test_parse_certificate_chain_path_broken_issuer(
    certificate_chain_file_broken_issuer: "Path", caplog: pytest.LogCaptureFixture
) -> None:
    """Test the parse_certificate_chain() method with a chain where the issuer is invalid."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as e:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_broken_issuer, expected_length=2
        )
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    assert e.value.code == 1, "Exit code not 1 as expected"
    assert "Parsing certificate failed" in caplog.text, "Expected error message not found with a broken issuer"


def test_parse_certificate_chain_path_broken_input(
    certificate_chain_file_not_a_pem: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test the parse_certificate_chain() method with a chain where the input is not a cert."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as e:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_not_a_pem, expected_length=2
        )
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    assert e.value.code == 1, "Exit code not 1 as expected"
    assert (
        "The input has 0 certificates, expected a chain with 2 certificates, something is not right" in caplog.text
    ), "Expected error message not found with a non-PEM input"


def mock_requests_response_http_500(
    url: str, payload: dict[str, str], headers: dict[str, str], timeout: int
) -> NamedTuple:
    """Mock a requests response with status code 500."""

    class Response(NamedTuple):
        status_code: int

    return Response(status_code=500)


def test_verify_signature_ec(caplog: pytest.LogCaptureFixture) -> None:
    """Test the verify_signature() method with an EC key."""
    caplog.set_level(logging.DEBUG)
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
        cryptography.hazmat.backends.default_backend(),
    )
    assert (
        certgrinderd.verify_signature(
            pubkey=private_key.public_key(),
            signature=private_key.sign(
                b"hello world",
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
            ),
            payload=b"hello world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is True
    ), "verify_signature() did not return True with an EC key"
    assert "Signature is valid" in caplog.text


def test_verify_signature_invalid(caplog: pytest.LogCaptureFixture) -> None:
    """Test the verify_signature() method with an invalid signature."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
        cryptography.hazmat.backends.default_backend(),
    )
    assert (
        certgrinderd.verify_signature(
            pubkey=private_key.public_key(),
            signature=private_key.sign(
                b"hello world",
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
            ),
            payload=b"goodbye world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is False
    ), "verify_signature() did not return False with an invalid signature"
    assert "Got exception while verifying signature" in caplog.text


def test_verify_signature_unsupported_keytype(caplog: pytest.LogCaptureFixture) -> None:
    """Test the verify_signature() method with an unsupported keytype."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
        cryptography.hazmat.backends.default_backend(),
    )
    assert (
        certgrinderd.verify_signature(
            pubkey=True,  # type: ignore[arg-type]
            signature=private_key.sign(
                b"hello world",
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
            ),
            payload=b"hello world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is False
    ), "verify_signature() did not return False with an unsupported keytype"
    assert "The public key type is not supported, unable to verify signature, returning False" in caplog.text


def test_process_csr_from_file(
    known_csr: str, caplog: pytest.LogCaptureFixture, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Test the process_csr() method with a path to a CSR."""
    csrpath = tmp_path_factory.mktemp("certificates") / "foo.csr"
    print(f"csrpath is {csrpath}")
    with csrpath.open("wb") as f:
        f.write(known_csr.encode("ASCII"))
    certgrinderd = Certgrinderd({"log-level": "DEBUG", "temp-dir": tmp_path_factory.mktemp("temp")})
    with pytest.raises(SystemExit) as e:
        certgrinderd.process_csr(csrpath=csrpath)
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    assert "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out" in caplog.text


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test the help command."""
    with pytest.raises(SystemExit) as e:
        main(["help"])
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    captured = capsys.readouterr()
    assert "See the manpage" in captured.out


def test_show_configuration(caplog: pytest.LogCaptureFixture) -> None:
    """Test the 'show configuration' sub-command."""
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as e:
        main(["show", "configuration"])
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    assert "Current certgrinderd configuration:" in caplog.text, "log message not found"


def test_show_acmeaccount(capsys: pytest.CaptureFixture[str], certgrinderd_configfile: tuple[str, Path]) -> None:
    """Test the 'show acmeaccount' sub-command without calling certbot."""
    if certgrinderd_configfile[0] != "dns":
        # we only need to test this once
        return

    with pytest.raises(SystemExit) as e:
        main(
            [
                "--config-file",
                str(certgrinderd_configfile[1]),
                "--certbot-command",
                "echo",
                "show",
                "acmeaccount",
            ]
        )
    assert e.type is SystemExit, f"Exit was not as expected, it was {e.type}"
    captured = capsys.readouterr()
    assert "show_account --non-interactive --email " in captured.out
