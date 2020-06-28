# type: ignore
"""certgrinderd.py tests.

Runs with pytest and Tox.
"""
import logging

import pytest
from certgrinderd.certgrinderd import Certgrinderd
from cryptography.hazmat.backends.openssl import x509


def test_parse_csr(known_csr):
    """Test the parse_csr() method with a valid CSR."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(known_csr)
    assert isinstance(
        csr, x509._CertificateSigningRequest
    ), "CSR should be a x509._CertificateSigningRequest, but is not"


def test_parse_broken_csr(known_csr):
    """Test the parse_csr() method with an invalid CSR."""
    certgrinderd = Certgrinderd()
    # use the known_csr with 1 line removed
    broken_csr = "\n".join(known_csr.split("\n")[:5] + known_csr.split("\n")[6:])
    with pytest.raises(ValueError):
        certgrinderd.parse_csr(broken_csr)


def test_check_csr(known_csr, certgrinderd_env):
    """Test the check_csr() method with a valid CSR."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    csr = certgrinderd.parse_csr(known_csr)
    assert certgrinderd.check_csr(csr) is True, "CSR not valid"


def test_check_csr_two_cn(csr_with_two_cn, caplog, certgrinderd_env):
    """Test the check_csr method with a CSR with two CN."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_with_two_cn)
    assert certgrinderd.check_csr(csr) is False
    assert "has more or less than 1 CN" in caplog.text


def test_check_csr_not_permitted(csr_example_org, caplog, certgrinderd_env):
    """Test the check_csr method with a CSR for domains not permitted by CERTGRINDERD_DOMAINSETS."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_example_org)
    assert certgrinderd.check_csr(csr) is False
    assert (
        "CSR contains one or more names which are not permitted for this client"
        in caplog.text
    )


def test_check_csr_not_permitted_2(csr_example_com_and_org, caplog, certgrinderd_env):
    """Test the check_csr method with a CSR with 1 name not permitted by CERTGRINDERD_DOMAINSETS."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_example_com_and_org)
    assert certgrinderd.check_csr(csr) is False
    assert (
        "CSR contains one or more names which are not permitted for this client"
        in caplog.text
    )


def test_check_csr_with_cn_not_in_san_list(
    csr_with_cn_not_in_san_list, caplog, certgrinderd_env
):
    """Test the check_csr method with a CSR where the CN is not in the SAN list."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_with_cn_not_in_san_list)
    assert certgrinderd.check_csr(csr) is False
    assert "not found in SAN list" in caplog.text


def test_no_env(known_csr, caplog, no_certgrinderd_env):
    """Make sure we we log an error and exit if env["CERTGRINDERD_DOMAINSETS"] is not defined."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(known_csr)
    assert certgrinderd.check_csr(csr) is False
    assert (
        "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out" in caplog.text
    ), "Did not find expected errormessage with undefined env['CERTGRINDERD_DOMAINSETS']"


def test_debug_loglevel(caplog):
    """Test debug log-level."""
    caplog.set_level(logging.DEBUG)
    Certgrinderd({"log-level": "DEBUG"})
    assert (
        "Running with config:" in caplog.text
    ), "Config logmessage not found even though log-level is DEBUG"


def test_syslog():
    """Test connection to syslog socket."""
    Certgrinderd({"syslog-socket": "/dev/log", "syslog-facility": "LOG_LOCAL0"})


def test_syslog_wrong_socket():
    """Test connection to nonexistant syslog socket."""
    with pytest.raises(FileNotFoundError):
        Certgrinderd(
            {
                "syslog-socket": "/dev/logfoo",
                "syslog-facility": "LOG_LOCAL0",
                "log-level": "DEBUG",
            }
        )
