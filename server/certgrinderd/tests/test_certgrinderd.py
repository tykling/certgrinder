# type: ignore
"""certgrinderd.py tests.

Runs with pytest and Tox.
"""
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


def test_check_csr(csr_with_two_cn, caplog, certgrinderd_env):
    """Test the check_csr method with a CSR with two CN."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(csr_with_two_cn)
    with pytest.raises(SystemExit):
        assert certgrinderd.check_csr(csr) is False
    assert "has more or less than 1 CN" in caplog.text
