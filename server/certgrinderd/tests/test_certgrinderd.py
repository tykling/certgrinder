# type: ignore
"""certgrinderd.py tests.

Runs with pytest and Tox.
"""
import datetime
import logging
from collections import namedtuple

import cryptography
import pytest
import requests
from certgrinderd.certgrinderd import Certgrinderd, main


def test_parse_csr(known_csr):
    """Test the parse_csr() method with a valid CSR."""
    certgrinderd = Certgrinderd()
    csr = certgrinderd.parse_csr(known_csr)
    assert isinstance(
        csr, cryptography.x509.CertificateSigningRequest
    ), "CSR should be a cryptography.x509.CertificateSigningRequest, but is not"


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


def test_parse_certificate_chain_path(certificate_chain_file):
    """Test the parse_certificate_chain() method with a valid chain."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    certificate, issuer = certgrinderd.parse_certificate_chain(
        certpath=certificate_chain_file, expected_length=2
    )
    assert isinstance(
        certificate, cryptography.x509.Certificate
    ), f"certificate should be an instance of cryptography.x509.Certificate but it is {type(certificate)}"
    assert isinstance(
        issuer, cryptography.x509.Certificate
    ), f"issuer should be an instance of cryptography.x509.Certificate but it is {type(issuer)}"


def test_parse_certificate_chain_path_broken_cert(
    certificate_chain_file_broken_cert, caplog
):
    """Test the parse_certificate_chain() method with a chain where the cert is invalid."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as E:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_broken_cert, expected_length=2
        )
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "Parsing certificate failed" in caplog.text
    ), "Expected error message not found with a broken cert"


def test_parse_certificate_chain_path_broken_issuer(
    certificate_chain_file_broken_issuer, caplog
):
    """Test the parse_certificate_chain() method with a chain where the issuer is invalid."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as E:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_broken_issuer, expected_length=2
        )
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "Parsing certificate failed" in caplog.text
    ), "Expected error message not found with a broken issuer"


def test_parse_certificate_chain_path_broken_input(
    certificate_chain_file_not_a_pem, caplog
):
    """Test the parse_certificate_chain() method with a chain where the input is not a cert."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    with pytest.raises(SystemExit) as E:
        certificate, issuer = certgrinderd.parse_certificate_chain(
            certpath=certificate_chain_file_not_a_pem, expected_length=2
        )
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "The input has 0 certificates, expected a chain with 2 certificates, something is not right"
        in caplog.text
    ), "Expected error message not found with a non-PEM input"


def test_get_ocsp_response_no_aia(certificate_file_no_aia, caplog):
    """Test the get_ocsp_response() method with a cert with no AIA."""
    certgrinderd = Certgrinderd(
        {"log-level": "DEBUG", "preferred-chain": "Fake LE Root X2"}
    )
    with pytest.raises(SystemExit) as E:
        certgrinderd.get_ocsp_response(certpath=certificate_file_no_aia)
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "No AUTHORITY_INFORMATION_ACCESS extension found in the certificate"
        in caplog.text
    ), "Expected error message not found with a cert without AIA"


def mock_requests_response_http_500(url, payload, headers):
    """Mock a requests response with status code 500."""
    Response = namedtuple("Response", ["status_code"])
    return Response(500)


def test_get_ocsp_response_not_http_200(certificate_chain_file, monkeypatch, caplog):
    """Test the get_ocsp_response() method with a mocked requests response with a HTTP status code other than 200."""
    monkeypatch.setattr(requests, "post", mock_requests_response_http_500)
    certgrinderd = Certgrinderd(
        {"log-level": "DEBUG", "preferred-chain": "Fake LE Root X2"}
    )
    with pytest.raises(SystemExit) as E:
        certgrinderd.get_ocsp_response(certpath=certificate_chain_file)
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "OCSP request failed for URL" in caplog.text
    ), "Expected error message not found with a non-200 HTTP status code"


def test_check_ocsp_response_not_successful(signed_certificate, caplog):
    """Test the check_ocsp_response() method with an unsuccessful OCSP response."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=signed_certificate
            ),
            ocsp_response=cryptography.x509.ocsp.OCSPResponseBuilder.build_unsuccessful(
                cryptography.x509.ocsp.OCSPResponseStatus.UNAUTHORIZED
            ),
            certificate=signed_certificate,
            issuer=signed_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with an unsuccessful OCSP response"
    assert (
        "OCSP response status is not SUCCESSFUL, it is OCSPResponseStatus.UNAUTHORIZED"
        in caplog.text
    )


def test_check_ocsp_response_wrong_serial(
    signed_certificate, selfsigned_certificate, known_private_key, caplog
):
    """Test the check_ocsp_response() method with a wrong serial."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    # generate an OCSP response with a different cert from the request
    builder = builder.add_response(
        cert=selfsigned_certificate,  # use the wrong cert here
        issuer=signed_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow(),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, signed_certificate
    )
    ocsp_response = builder.sign(
        known_private_key, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=signed_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=signed_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with the wrong serial"
    assert (
        "The OCSP response has a different serial_number than the OCSP request"
        in caplog.text
    )


def test_check_ocsp_response_wrong_hash_algo(
    signed_certificate, selfsigned_certificate, known_private_key, caplog
):
    """Test the check_ocsp_response() method with a wrong hash algo."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    # generate an OCSP response with a different hash algorithm from the request
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=signed_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),  # use the wrong algo here
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow(),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, signed_certificate
    )
    ocsp_response = builder.sign(
        known_private_key, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=signed_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=signed_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with the wrong hash algorithm"
    assert (
        "The OCSP response has a different hash_algorithm than the OCSP request"
        in caplog.text
    )


def test_check_ocsp_response_wrong_issuer_key(
    signed_certificate, selfsigned_certificate, known_private_key, caplog
):
    """Test the check_ocsp_response() method with a wrong issuer key."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    # generate an OCSP response with a different hash algorithm from the request
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow(),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, signed_certificate
    )
    # sign with the wrong key
    ocsp_response = builder.sign(
        known_private_key, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=signed_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=signed_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with the wrong issuer key"
    assert (
        "The OCSP response has a different issuer_key_hash than the OCSP request"
        in caplog.text
    )


def test_check_ocsp_response_this_update_in_future(
    signed_certificate, selfsigned_certificate, known_private_key_2, caplog
):
    """Test the check_ocsp_response() method with a thisUpdate time in the future."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow() + datetime.timedelta(days=1),
        next_update=datetime.datetime.utcnow(),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, selfsigned_certificate
    )
    ocsp_response = builder.sign(
        known_private_key_2, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with thisUpdate in the future"
    assert (
        "The this_update parameter of the OCSP response is in the future" in caplog.text
    )


def test_check_ocsp_response_no_next_update(
    signed_certificate, selfsigned_certificate, known_private_key_2, caplog
):
    """Test the check_ocsp_response() method with no nextUpdate time."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=None,
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, selfsigned_certificate
    )
    ocsp_response = builder.sign(
        known_private_key_2, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with no nextUpdate time"
    assert (
        "OCSP response has no nextUpdate attribute. This violates RFC5019 2.2.4."
        in caplog.text
    )


def test_check_ocsp_response_next_update_in_past(
    signed_certificate, selfsigned_certificate, known_private_key_2, caplog
):
    """Test the check_ocsp_response() method with nextUpdate in the past."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow() - datetime.timedelta(days=1),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, selfsigned_certificate
    )
    ocsp_response = builder.sign(
        known_private_key_2, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with nextUpdate in the past"
    assert (
        "The next_update parameter of the OCSP response is in the past" in caplog.text
    )


def test_check_ocsp_response_delegated_signer(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate,
    known_private_key_3,
    caplog,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder."""
    caplog.set_level(logging.DEBUG)
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate,
        )
        .certificates([delegated_signer_certificate])
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is True
    ), "check_ocsp_response() did not return True with a delegated responder"
    assert "This OCSP response is signed by a delegated OCSP responder" in caplog.text
    assert (
        "Found OCSP responder cert with the right namehash and keyhash in OCSP response:"
        in caplog.text
    )


def test_check_ocsp_response_delegated_signer_cert_missing(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate,
    known_private_key_3,
    caplog,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate,
        )
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a missing delegated responder certificate"
    assert "Unable to find delegated OCSP responder certificate" in caplog.text


def test_check_ocsp_response_delegated_signer_not_signed_by_issuer(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate_not_signed_by_issuer,
    known_private_key_3,
    caplog,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder which is not signed by the issuer."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate_not_signed_by_issuer,
        )
        .certificates([delegated_signer_certificate_not_signed_by_issuer])
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a delegated responder which is not signed by the issuer"
    assert (
        "The OCSP responder certificate is not signed by certificate issuer"
        in caplog.text
    )


def mock_verify_signature_fail(pubkey, signature, payload, hashalgo):
    """Mock a signature verify failure."""
    return False


def test_check_ocsp_response_delegated_signer_invalid_signature(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate,
    known_private_key_3,
    caplog,
    monkeypatch,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder with an invalid issuer signature, by monkeypatching the verify_signature method."""
    monkeypatch.setattr(Certgrinderd, "verify_signature", mock_verify_signature_fail)
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate,
        )
        .certificates([delegated_signer_certificate])
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with an invalid signature on the delegated responder certificate"
    assert "The issuer signature on the responder certificate is invalid" in caplog.text


def test_check_ocsp_response_delegated_signer_no_extendedkeyusage(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate_no_eku,
    known_private_key_3,
    caplog,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder without ExtendedKeyUsage extension in the cert."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate_no_eku,
        )
        .certificates([delegated_signer_certificate_no_eku])
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a delegated responder without ExtendedKeyUsage extension"
    assert (
        "No ExtendedKeyUsage extension found in delegated OCSP responder certificate"
        in caplog.text
    )


def test_check_ocsp_response_delegated_signer_no_ocsp_perm(
    signed_certificate,
    selfsigned_certificate,
    delegated_signer_certificate_no_ocsp_perm,
    known_private_key_3,
    caplog,
):
    """Test the check_ocsp_response() method with an OCSP response signed by a delegated responder with ExtendedKeyUsage but no OCSP signing perm."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = (
        cryptography.x509.ocsp.OCSPResponseBuilder()
        .add_response(
            cert=signed_certificate,
            issuer=selfsigned_certificate,
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.datetime.utcnow(),
            next_update=datetime.datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(
            cryptography.x509.ocsp.OCSPResponderEncoding.HASH,
            delegated_signer_certificate_no_ocsp_perm,
        )
        .certificates([delegated_signer_certificate_no_ocsp_perm])
    )
    ocsp_response = builder.sign(
        known_private_key_3, cryptography.hazmat.primitives.hashes.SHA256()
    )
    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a delegated responder with ExtendedKeyUsage but no OCSP signing perm"
    assert (
        "Delegated OCSP responder certificate is not permitted to sign OCSP responses"
        in caplog.text
    )


def test_check_ocsp_response_verify_signature_fail(
    signed_certificate, selfsigned_certificate, known_private_key_2, caplog, monkeypatch
):
    """Test the check_ocsp_response() method with a monkeypatched verify_signature method set to fail."""
    monkeypatch.setattr(Certgrinderd, "verify_signature", mock_verify_signature_fail)
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow() + datetime.timedelta(days=1),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, selfsigned_certificate
    )
    ocsp_response = builder.sign(
        known_private_key_2, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a verify_signature monkeypatched to fail"
    assert "The OCSP response signature is invalid" in caplog.text


def test_check_ocsp_response_unknown_cert(
    signed_certificate, selfsigned_certificate, known_private_key_2, caplog
):
    """Test the check_ocsp_response() method with unknown cert status."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    builder = cryptography.x509.ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=signed_certificate,
        issuer=selfsigned_certificate,
        algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
        cert_status=cryptography.x509.ocsp.OCSPCertStatus.UNKNOWN,
        this_update=datetime.datetime.utcnow(),
        next_update=datetime.datetime.utcnow() + datetime.timedelta(days=1),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(
        cryptography.x509.ocsp.OCSPResponderEncoding.HASH, selfsigned_certificate
    )
    ocsp_response = builder.sign(
        known_private_key_2, cryptography.hazmat.primitives.hashes.SHA256()
    )

    assert (
        certgrinderd.check_ocsp_response(
            ocsp_request=certgrinderd.create_ocsp_request(
                certificate=signed_certificate, issuer=selfsigned_certificate
            ),
            ocsp_response=ocsp_response,
            certificate=signed_certificate,
            issuer=selfsigned_certificate,
        )
        is False
    ), "check_ocsp_response() did not return False with a response with OCSP status unknown"
    assert "OCSP response is valid, but certificate status is UNKNOWN" in caplog.text


def test_verify_signature_ec(caplog):
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
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256()
                ),
            ),
            payload=b"hello world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is True
    ), "verify_signature() did not return True with an EC key"
    assert "Signature is valid" in caplog.text


def test_verify_signature_invalid(caplog):
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
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256()
                ),
            ),
            payload=b"goodbye world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is False
    ), "verify_signature() did not return False with an invalid signature"
    assert "Got exception while verifying signature" in caplog.text


def test_verify_signature_unsupported_keytype(caplog):
    """Test the verify_signature() method with an unsupported keytype."""
    certgrinderd = Certgrinderd({"log-level": "DEBUG"})
    private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
        cryptography.hazmat.backends.default_backend(),
    )
    assert (
        certgrinderd.verify_signature(
            pubkey=True,
            signature=private_key.sign(
                b"hello world",
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cryptography.hazmat.primitives.hashes.SHA256()
                ),
            ),
            payload=b"hello world",
            hashalgo=cryptography.hazmat.primitives.hashes.SHA256(),
        )
        is False
    ), "verify_signature() did not return False with an unsupported keytype"
    assert (
        "The public key type is not supported, unable to verify signature, returning False"
        in caplog.text
    )


def test_process_csr_from_file(known_csr, caplog, tmp_path_factory):
    """Test the process_csr() method with a path to a CSR."""
    csrpath = tmp_path_factory.mktemp("certificates") / "foo.csr"
    print(f"csrpath is {csrpath}")
    with open(csrpath, "wb") as f:
        f.write(known_csr.encode("ASCII"))
    certgrinderd = Certgrinderd(
        {"log-level": "DEBUG", "temp-dir": tmp_path_factory.mktemp("temp")}
    )
    with pytest.raises(SystemExit) as E:
        certgrinderd.process_csr(csrpath=csrpath)
    assert E.value.code == 1, "Exit code not 1 as expected"
    assert (
        "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out" in caplog.text
    )


def test_help(capsys):
    """Test the help command."""
    with pytest.raises(SystemExit) as E:
        main(["help"])
    assert E.type == SystemExit
    captured = capsys.readouterr()
    assert "See the manpage certgrinderd(8)" in captured.out


def test_show_configuration(caplog):
    """Test the 'show configuration' sub-command."""
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as E:
        main(["show", "configuration"])
    assert E.type == SystemExit
    assert "Current certgrinderd configuration:" in caplog.text


def test_show_acmeaccount(capsys, certgrinderd_configfile):
    """Test the 'show acmeaccount' sub-command without calling certbot."""
    if certgrinderd_configfile[0] != "dns":
        # we only need to test this once
        return

    with pytest.raises(SystemExit) as E:
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
    assert E.type == SystemExit
    captured = capsys.readouterr()
    assert "show_account --non-interactive --email " in captured.out
