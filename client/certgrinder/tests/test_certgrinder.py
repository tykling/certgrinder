# type: ignore
import urllib.request
import pathlib
import ssl
import os
from certgrinder.certgrinder import Certgrinder
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


def test_certgrinder(pebble_server, certgrinder_configfile, tmp_path_factory):
    """
    Get a certificate and check that it looks right
    """
    certgrinder = Certgrinder(
        configfile=certgrinder_configfile,
        staging=False,
        showtlsa="",
        checktlsa="",
        nameserver="",
        showspki=False,
        debug=True,
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
