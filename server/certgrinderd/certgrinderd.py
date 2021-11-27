#!/usr/bin/env python
"""Certgrinderd v0.17.2 module.

See https://certgrinder.readthedocs.io/en/latest/certgrinderd.html
and https://github.com/tykling/certgrinder for more.
"""
import argparse
import logging
import logging.handlers
import os
import subprocess
import sys
import tempfile
import typing
from datetime import datetime, timedelta

import cryptography.x509
import requests
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import x509
from pid import PidFile  # type: ignore

logger = logging.getLogger("certgrinderd.%s" % __name__)
__version__ = "0.17.2"


class Certgrinderd:
    """The Certgrinderd server class."""

    # save version as a class attribute
    __version__ = __version__

    def __init__(
        self,
        userconfig: typing.Optional[
            typing.Dict[str, typing.Union[str, bool, None]]
        ] = None,
    ) -> None:
        """Merge userconfig with defaults and configure logging.

        Args:
            userconfig: A dict of configuration to merge with default config

        Returns:
            None
        """
        # default config
        self.conf: typing.Dict[str, typing.Union[str, bool, int, None]] = {
            "acme-email": None,
            "acme-server-url": "https://acme-v02.api.letsencrypt.org/directory",
            "acme-zone": None,
            "auth-hook": "manual-auth-hook.sh",
            "certbot-command": "/usr/local/bin/sudo /usr/local/bin/certbot",
            "certbot-config-dir": "",
            "certbot-logs-dir": "",
            "certbot-work-dir": "",
            "certificate-file": "",
            "cleanup-hook": "manual-cleanup-hook.sh",
            "config-file": "",
            "csr-path": "",
            "debug": False,
            "log-level": "INFO",
            "pid-dir": "/tmp",
            "preferred-chain": "DST_Root_CA_X3",
            "skip-acme-server-cert-verify": False,
            "syslog-facility": None,
            "syslog-socket": None,
            "temp-dir": "",
            "web-root": "",
        }

        if userconfig:
            self.conf.update(userconfig)

        # define the log format used for stdout depending on the requested loglevel
        if self.conf["log-level"] == "DEBUG":
            console_logformat = "%(asctime)s certgrinderd %(levelname)s Certgrinderd.%(funcName)s():%(lineno)i:  %(message)s"
        else:
            console_logformat = "%(asctime)s certgrinderd %(levelname)s %(message)s"

        # configure the log format used for console
        logging.basicConfig(
            level=getattr(logging, str(self.conf["log-level"])),
            format=console_logformat,
            datefmt="%Y-%m-%d %H:%M:%S %z",
        )

        # connect to syslog?
        if self.conf["syslog-socket"] and self.conf["syslog-facility"]:
            facility: int = getattr(
                logging.handlers.SysLogHandler, str(self.conf["syslog-facility"])
            )
            syslog_handler = logging.handlers.SysLogHandler(
                address=str(self.conf["syslog-socket"]), facility=facility
            )
            syslog_format = logging.Formatter("certgrinderd: %(message)s")
            syslog_handler.setFormatter(syslog_format)
            logger.addHandler(syslog_handler)
            # usually SysLogHandler is lazy and doesn't connect the socket until
            # a message has to be sent. Call _connect_unixsocket() now to force
            # an exception now if we can't connect to the socket
            syslog_handler._connect_unixsocket(  # type: ignore
                self.conf["syslog-socket"]
            )
            # OK, we are connected to syslog
            logger.debug(
                f"Connected to syslog-socket {self.conf['syslog-socket']}, logging to facility {self.conf['syslog-facility']}"
            )
        else:
            logger.debug("Not configuring syslog")

        logger.info(
            f"certgrinderd {__version__} running, log-level is {self.conf['log-level']}"
        )

        if self.conf["preferred-chain"] in ["DST_Root_CA_X3", "Fake_LE_Root_X1"]:
            # two intermediates
            self.conf["expected-chain-length"] = 3
        else:
            # one intermediate
            self.conf["expected-chain-length"] = 2

        logger.debug("Running with config: %s" % self.conf)

    # CSR methods

    @staticmethod
    def parse_csr(csrstring: str = "") -> x509._CertificateSigningRequest:
        """Parse CSR with cryptography.x509.load_pem_x509_csr(), return CSR object.

        Takes the CSR data from ``sys.stdin`` if the ``csrstring`` argument is empty.

        Args:
            csrstring: The PEM formatted CSR as a string (optional)

        Returns:
            The CSR object
        """
        if not csrstring:
            # get the CSR from stdin
            logger.debug("Reading PEM CSR from stdin ...")
            csrstring = sys.stdin.read()

        # parse and return the csr
        return cryptography.x509.load_pem_x509_csr(
            csrstring.encode("ascii"), default_backend()
        )

    def process_csr(self, csrpath: str = "") -> None:
        """Load the CSR, use it to get a certificate, and cleanup.

        Calls ``self.parse_csr()`` followed by ``self.check_csr()``, and then exists if any
        problems are found with the CSR.

        Then ``self.get_certificate()`` is called, which in turn calls Certbot, which writes
        the certificate to stdout.

        Finally the CSR is deleted.

        Args:
            None

        Returns:
            None
        """
        # get the CSR from stdin or file
        if csrpath:
            with open(csrpath, "r") as f:
                csrstring = f.read()
        else:
            csrstring = ""
        csr = self.parse_csr(csrstring)

        # get temp path for the csr so we can save it to disk
        csrfd, csrpath = tempfile.mkstemp(
            suffix=".csr", prefix="certgrinderd-", dir=str(self.conf["temp-dir"])
        )

        # save the csr to disk
        self.save_csr(csr, csrpath)

        # check CSR creaminess
        if not self.check_csr(csr):
            # something is fucky with the CSR
            sys.exit(1)

        # alright, get the cert for this CSR
        self.get_certificate(csrpath)

        # clean up temp file
        os.remove(csrpath)

    @staticmethod
    def save_csr(csr: x509._CertificateSigningRequest, path: str) -> None:
        """Save the CSR object to the path in PEM format.

        Args:
            csr: The CSR object
            path: The path to save it in

        Returns:
            None
        """
        with open(path, "wb") as f:
            f.write(csr.public_bytes(primitives.serialization.Encoding.PEM))

    @staticmethod
    def check_csr(csr: x509._CertificateSigningRequest) -> bool:
        """Check that this CSR is valid, all things considered.

        First check that the CSR has exactly one ``CommonName``, and that that CN is
        also present in the list of ``SubjectAltNames``.

        Then make sure that the environment var ``CERTGRINDERD_DOMAINSETS`` exists
        and contains all the names from the CSR in one of the domainsets.

        Args:
            csr: The CSR object

        Returns:
            True if the CSR is OK, False otherwise
        """
        # get the list of allowed names from env
        allowed_names = os.environ.get("CERTGRINDERD_DOMAINSETS", None)
        if not allowed_names:
            logger.error(
                "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out"
            )
            return False

        # get CommonName from CSR
        cn_list = csr.subject.get_attributes_for_oid(
            cryptography.x509.oid.NameOID.COMMON_NAME
        )
        if len(cn_list) != 1:
            # we have more or less than one CN, fuckery is afoot
            logger.error("CSR is not valid (has more or less than 1 CN), bailing out")
            return False
        cn = cn_list[0].value

        # get list of SubjectAltNames from CSR
        san_list = [
            name.lower()
            for name in csr.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(cryptography.x509.DNSName)
        ]
        if cn not in san_list:
            # CSR CommonName is not in SAN list
            logger.error(
                f"CSR is not valid (CN {cn} not found in SAN list {san_list}), bailing out"
            )
            return False

        # domainsets is a semicolon-separated list of comma-separated domainsets.
        # loop over domainsets until we find a match and break out, or hit the else
        # if we never find a domainset covering all names in the CSR
        logger.debug(f"testing if {san_list} is allowed in {allowed_names}")
        for domainset in allowed_names.split(";"):
            domainsetlist = [
                d.encode("idna").decode("ascii") for d in domainset.split(",")
            ]
            logger.debug(f"checking domainset {domainsetlist} ...")
            if cn not in domainsetlist:
                # cert CN is not in this domainset
                continue
            # loop over SubjectAltNames and check if each is present in domainset,
            # break out of the loop if a name is not in the domainset
            for san in san_list:
                if san not in domainsetlist:
                    # this name is not in this domainset, no need to keep checking,
                    # break out of the innermost loop and continue checking the list
                    break
            else:
                # all names in the CSR are permitted for this client,
                # no need to check more domainsets, break out now
                logger.debug(
                    f"All names in the CSR ({san_list}) are permitted for this client"
                )
                break
        else:
            # this CSR contains names which are not permitted for this client
            logger.error(
                f"CSR contains one or more names which are not permitted for this client. Permitted names: {allowed_names} - Requested names: {san_list}"
            )
            return False

        # all good
        return True

    # certificate methods

    def get_certificate_command(self) -> None:
        """This method is called when the `get certificate` subcommand is used.

        Args:
            None

        Returns:
            None
        """
        self.process_csr(csrpath=str(self.conf["csr-path"]))

    def get_certbot_command(
        self,
        challengetype: str,
        csrpath: str,
        fullchainpath: str,
        certpath: str,
        chainpath: str,
    ) -> typing.List[str]:
        """Put the certbot command together.

        Start with ``self.conf["certbot-command"]`` and append all the needed options.

        Optionally add ``--email`` and a bunch of certbot settings as needed.

        Args:
            challengetype: The type of challenge, ``dns`` or ``http``
            csrpath: The path to the CSR
            fullchainpath: The path to save the certificate+issuer
            certpath: The path to save the certificate (without issuer)
            chainpath: The path to save the issuer (without certificate)

        Returns:
            The certbot command as a list
        """
        command: typing.List[str] = str(self.conf["certbot-command"]).split(" ") + [
            "certonly",
            "--non-interactive",
            "--quiet",
            "--authenticator",
            "manual",
            "--preferred-challenges",
            challengetype,
            "--manual-auth-hook",
            str(self.conf["auth-hook"]),
            "--manual-cleanup-hook",
            str(self.conf["cleanup-hook"]),
            "--csr",
            csrpath,
            "--fullchain-path",
            fullchainpath,
            "--cert-path",
            certpath,
            "--chain-path",
            chainpath,
            "--agree-tos",
        ]

        if self.conf["acme-email"]:
            command.append("--email")
            command.append(str(self.conf["acme-email"]))

        if self.conf["acme-server-url"]:
            command.append("--server")
            command.append(str(self.conf["acme-server-url"]))

        if self.conf["skip-acme-server-cert-verify"]:
            command.append("--no-verify-ssl")

        if self.conf["certbot-config-dir"]:
            command.append("--config-dir")
            command.append(str(self.conf["certbot-config-dir"]))

        if self.conf["certbot-work-dir"]:
            command.append("--work-dir")
            command.append(str(self.conf["certbot-work-dir"]))

        if self.conf["certbot-logs-dir"]:
            command.append("--logs-dir")
            command.append(str(self.conf["certbot-logs-dir"]))

        if self.conf["preferred-chain"]:
            command.append("--preferred-chain")
            # replace underscores with spaces in the chain name before passing to Certbot
            assert isinstance(self.conf["preferred-chain"], str)
            command.append(self.conf["preferred-chain"].replace("_", " "))

        return command

    def get_certificate(self, csrpath: str) -> None:
        """Get a cert using ``DNS-01`` or ``HTTP-01`` by calling ``self.run_certbot()`` for each.

        If ``self.conf["acme-zone"]`` is set then ``DNS-01`` is attempted. Return if it
        results in a new certificate.

        If ``self.conf["web-root"]`` is set then ``HTTP-01`` is attempted. Return if it
        results in a new certificate.

        If there is still no certificate log an error and return anyway.

        Args:
            csrpath: The path to the CSR

        Returns:
            None
        """
        # get temp paths for certbot
        fullchainpath = os.path.join(str(self.conf["temp-dir"]), "fullchain.pem")
        certpath = os.path.join(str(self.conf["temp-dir"]), "certificate.pem")
        chainpath = os.path.join(str(self.conf["temp-dir"]), "chain.pem")

        # try DNS-01 first, if we have an acme zone
        if self.conf["acme-zone"]:
            logger.debug(f"Attempting DNS-01 with zone {self.conf['acme-zone']} ...")
            env = os.environ.copy()
            env.update({"ACMEZONE": str(self.conf["acme-zone"])})
            command = self.get_certbot_command(
                challengetype="dns",
                csrpath=csrpath,
                fullchainpath=fullchainpath,
                certpath=certpath,
                chainpath=chainpath,
            )
            result = self.run_certbot(command, env, fullchainpath)
            # no need to continue if we got a certificate with DNS-01
            if result:
                logger.info("Success, got a new certificate")
                return

        # then try HTTP-01, if we have a web-root
        if self.conf["web-root"]:
            logger.debug(f"Attempting HTTP-01 with webroot {self.conf['web-root']} ...")
            env = os.environ.copy()
            env.update({"WEBROOT": str(self.conf["web-root"])})
            command = self.get_certbot_command(
                challengetype="http",
                csrpath=csrpath,
                fullchainpath=fullchainpath,
                certpath=certpath,
                chainpath=chainpath,
            )
            result = self.run_certbot(command, env, fullchainpath)
            if result:
                logger.info("Success, got a new certificate")
                return

        # we are done here
        logger.error("No more challenge types to try, unable to get certificate")

    def run_certbot(
        self, command: typing.List[str], env: typing.Dict[str, str], fullchainpath: str
    ) -> bool:
        """Call certbot, check exitcode, output cert, return bool success.

        Args:
            command: A list of certbot command elements
            env: A dictionary of the environment to pass to subprocess.run()
            fullchainpath: The path to read the certificate+chain from after Certbot runs

        Returns:
            True if Certbot command exitcode was 0, False otherwise
        """
        # call certbot
        logger.debug(f"Running certbot command with env {env}: {command}")
        p = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )

        certbot_stdout, certbot_stderr = p.communicate()

        if p.returncode == 0:
            # success, read chain from disk
            with open(fullchainpath) as f:
                chainbytes = f.read()
            assert isinstance(self.conf["expected-chain-length"], int)
            self.parse_certificate_chain(
                fullchainpath, expected_length=self.conf["expected-chain-length"]
            )
            # output chain to stdout
            print(chainbytes)
            return True
        else:
            logger.error("certbot command returned non-zero exit code")
            logger.error("certbot stderr:")
            for line in certbot_stderr.strip().decode("utf-8").split("\n"):
                logger.error(line)
            return False

    @staticmethod
    def split_pem_chain(pem_chain_bytes: bytes) -> typing.List[bytes]:
        """Split a PEM chain into a list of bytes of the individual PEM certificates.

        Args:
            pem_chain_bytes: The bytes representing the PEM chain

        Returns:
            A list of 0 or more bytes chunks representing each certificate
        """
        logger.debug(f"Parsing certificates from {len(pem_chain_bytes)} bytes input")
        certificates = []
        cert_list = pem_chain_bytes.decode("ASCII").split("-----BEGIN CERTIFICATE-----")
        for cert in cert_list[1:]:
            certificates.append(("-----BEGIN CERTIFICATE-----" + cert).encode("ASCII"))
        logger.debug(
            f"Returning a list of {len(certificates)} chunks of bytes resembling PEM certificates"
        )
        return certificates

    @classmethod
    def parse_certificate_chain(
        cls,
        certpath: typing.Optional[str],
        expected_length: typing.Optional[int] = None,
    ) -> typing.List[cryptography.x509.Certificate]:
        """Parse certificate chain from path or stdin.

        Args:
            certpath: The path of the certificate chain to parse (optional),
                      chainbytes are taken from stdin if not provided.
            expected_length: The number of certificates to expect. Optional.

        Returns:
            A list of cryptography.x509.Certificate objects in the order they appear
            in the input.
        """
        if certpath:
            logger.debug(f"Reading PEM cert chain from file {certpath} ...")
            with open(certpath, "rb") as f:
                chainbytes = f.read()
        else:
            logger.debug("Reading PEM cert chain from stdin ...")
            chainbytes = sys.stdin.read().encode("ASCII")

        certs = cls.split_pem_chain(chainbytes)
        if expected_length and len(certs) != expected_length:
            logger.error(
                f"The input has {len(certs)} certificates, expected a chain with {expected_length} certificates, something is not right."
            )
            sys.exit(1)

        chain = []
        for certbytes in certs:
            cert = cls.parse_certificate(certbytes)
            chain.append(cert)
        return chain

    @classmethod
    def parse_certificate(
        cls, certificate_bytes: bytes
    ) -> cryptography.x509.Certificate:
        """Parse and return individual certificate, or calls sys.exit(1) if something goes wrong.

        Args:
            certificate_bytes: A chunk of bytes representing a PEM certificate

        Returns:
            A cryptography.x509.Certificate object.
        """
        try:
            return cryptography.x509.load_pem_x509_certificate(
                certificate_bytes, default_backend()
            )
        except Exception:
            logger.error("Parsing certificate failed.")
            sys.exit(1)

    # OCSP methods

    def get_ocsp_command(self) -> None:
        """This method is called when the `get ocsp` subcommand is used.

        It simply prints the DER formatted OCSP response to stdout if we get one.

        Args:
            None

        Returns:
            None
        """
        assert isinstance(self.conf["certificate-file"], str)
        ocsp_response = self.get_ocsp_response(certpath=self.conf["certificate-file"])
        der = ocsp_response.public_bytes(primitives.serialization.Encoding.DER)
        logger.info(
            f"Success, got a new OCSP response, outputting {len(der)} bytes DER encoded data to stdout"
        )
        sys.stdout.buffer.write(der)

    @classmethod
    def create_ocsp_request(
        cls,
        certificate: cryptography.x509.Certificate,
        issuer: cryptography.x509.Certificate,
    ) -> cryptography.hazmat.backends.openssl.ocsp._OCSPRequest:
        """Create and return an OCSP request based on the cert+issuer.

        Args:
            certificate: The certificate to create an OCSP request for
            issuer: The issuer of the certificate

        Returns:
            The OCSP request
        """
        # create OCSP request
        builder = cryptography.x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(certificate, issuer, primitives.hashes.SHA1())
        ocsp_request_object = builder.build()
        return ocsp_request_object

    def get_ocsp_response(
        self, certpath: typing.Optional[str]
    ) -> cryptography.hazmat.backends.openssl.ocsp._OCSPResponse:
        """Parse certificate, get and return OCSP response.

        Args:
            certpath: The path of the certificate chain to get OCSP response for (optional)

        Returns:
            The OCSPRequest object
        """
        assert isinstance(self.conf["expected-chain-length"], int)
        chain = self.parse_certificate_chain(certpath)
        certificate = chain[0]
        issuers = chain[1:]
        logger.debug(f"Getting OCSP response for cert {certificate.subject}")

        ocsp_request_object = self.create_ocsp_request(certificate, issuers[0])
        ocsp_request_bytes = ocsp_request_object.public_bytes(
            primitives.serialization.Encoding.DER
        )
        logger.debug(f"Raw OCSP request: {ocsp_request_bytes}")

        # get AuthorityInformationAccess extensions
        try:
            aias = certificate.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
        except cryptography.x509.extensions.ExtensionNotFound:
            logger.error(
                "No AUTHORITY_INFORMATION_ACCESS extension found in the certificate"
            )
            sys.exit(1)

        # loop over AuthorityInformationAccess extensions in the cert and try each OCSP server
        for aia in aias.value:
            # we only understand OCSP servers
            assert (
                aia.access_method._name == "OCSP"
            ), f"Unsupported access method found in AUTHORITY_INFORMATION_ACCESS extension in certificate with subject {certificate.subject}. Access method found was: '{aia.access_method._name}', please file a certgrinder bug with this info and if possible a URL for the certificate."

            # get the OCSP server URL
            url = aia.access_location.value

            # wrap the HTTP request in a try/except in case something goes wrong
            try:
                r = requests.post(
                    url,
                    ocsp_request_bytes,
                    headers={
                        "Accept": "application/ocsp-response",
                        "Content-Type": "application/ocsp-request",
                    },
                )
            except requests.exceptions.RequestException:
                logger.exception(
                    f"OCSP request failed for URL {url} - trying next OCSP server"
                )
                continue

            # check the HTTP response status code
            if r.status_code != 200:
                logger.error(
                    f"OCSP request failed for URL {url} with HTTP status code {r.status_code} - trying next OCSP server"
                )
                continue

            # parse the OCSP response from the HTTP response body
            ocsp_response_object = cryptography.x509.ocsp.load_der_ocsp_response(
                r.content
            )

            logger.debug(
                f"Received response with HTTP status code {r.status_code} and OCSP response status {ocsp_response_object.response_status}"
            )
            if self.check_ocsp_response(
                ocsp_request_object, ocsp_response_object, certificate, issuers[0]
            ):
                logger.debug(
                    f"Certificate status: {ocsp_response_object.certificate_status}"
                )
                logger.debug(f"This update: {ocsp_response_object.this_update}")
                logger.debug(f"Produced at: {ocsp_response_object.produced_at}")
                logger.debug(f"Next update: {ocsp_response_object.next_update}")
                logger.debug(f"Revocation time: {ocsp_response_object.revocation_time}")
                logger.debug(
                    f"Revocation reason: {ocsp_response_object.revocation_reason}"
                )
                return ocsp_response_object

        # if we got this far we either didn't find any OCSP servers, or none of them worked
        logger.error("Unable to get OCSP response.")
        sys.exit(1)

    @classmethod
    def check_ocsp_response(
        cls,
        ocsp_request: cryptography.hazmat.backends.openssl.ocsp._OCSPRequest,
        ocsp_response: cryptography.hazmat.backends.openssl.ocsp._OCSPResponse,
        certificate: cryptography.x509.Certificate,
        issuer: cryptography.x509.Certificate,
    ) -> bool:
        """Check that the OCSP response is valid for the OCSP request and cert/issuer.

        Return True if the OCSP response is good, regardless of the certificate revocation status. Implements all the checks in RFC2560 3.2.

        Args:
            ocsp_request: The OCSP request object to check
            ocsp_response: The OCSP response object to check
            certificate: The certificate the OCSP request is for
            issuer: The issuer of the certificate

        Returns:
            True if the OCSP response is valid, False if not
        """
        logger.debug("Checking validity of OCSP response")

        # Check OCSP response status
        if (
            ocsp_response.response_status
            != cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL
        ):
            logger.error(
                f"OCSP response status is not SUCCESSFUL, it is {ocsp_response.response_status}"
            )
            return False

        if not cls.check_ocsp_response_issuer(ocsp_request, ocsp_response):
            logger.error("Check issuer failed")
            return False

        if not cls.check_ocsp_response_timing(ocsp_response):
            logger.error("Check timing failed")
            return False

        if not cls.check_ocsp_response_signature(ocsp_response, [issuer]):
            logger.error("Check signature failed")
            return False

        if (
            ocsp_response.certificate_status
            == cryptography.x509.ocsp.OCSPCertStatus.UNKNOWN
        ):
            logger.error("OCSP response is valid, but certificate status is UNKNOWN")
            return False

        # all good
        logger.debug("OCSP response is valid!")
        return True

    @staticmethod
    def check_ocsp_response_issuer(
        ocsp_request: cryptography.hazmat.backends.openssl.ocsp._OCSPRequest,
        ocsp_response: cryptography.hazmat.backends.openssl.ocsp._OCSPResponse,
    ) -> bool:
        """Check that the response matches the request.

        Args:
            ocsp_request: The OCSP request object
            ocsp_response: The OCSP response object

        Returns:
            Boolean - True if all is well, False if a problem was found
        """
        # check that serial number matches
        if ocsp_request.serial_number != ocsp_response.serial_number:
            logger.error(
                "The OCSP response has a different serial_number than the OCSP request"
            )
            return False

        # check that the hash algorithm matches
        if not isinstance(
            ocsp_request.hash_algorithm, type(ocsp_response.hash_algorithm)
        ):
            logger.error(
                "The OCSP response has a different hash_algorithm than the OCSP request"
            )
            return False

        # check that the issuer key hash matches
        if ocsp_request.issuer_key_hash != ocsp_response.issuer_key_hash:
            logger.error(
                "The OCSP response has a different issuer_key_hash than the OCSP request"
            )
            return False

        # all good
        return True

    @staticmethod
    def check_ocsp_response_timing(
        ocsp_response: cryptography.hazmat.backends.openssl.ocsp._OCSPResponse,
    ) -> bool:
        """Check the timestamps of the OCSP response.

        Args:
            ocsp_response: The OCSP response object to check

        Returns:
            Boolean - True if all is well, False if a problem was found
        """
        # check that this_update is in the past
        if ocsp_response.this_update > datetime.utcnow() + timedelta(minutes=5):
            logger.error(
                f"The this_update parameter of the OCSP response is in the future: {ocsp_response.this_update}"
            )
            return False

        # check that we have a next_update attribute
        if not ocsp_response.next_update:
            logger.error(
                "OCSP response has no nextUpdate attribute. This violates RFC5019 2.2.4."
            )
            return False

        # check that next_update is in the future
        if ocsp_response.next_update < datetime.utcnow() - timedelta(minutes=5):
            logger.error(
                f"The next_update parameter of the OCSP response is in the past: {ocsp_response.this_update}"
            )
            return False

        # all good
        return True

    @classmethod
    def check_ocsp_response_signature(
        cls,
        ocsp_response: cryptography.hazmat.backends.openssl.ocsp._OCSPResponse,
        issuers: typing.List[cryptography.x509.Certificate],
    ) -> bool:
        """Check the signature of the OCSP response.

        Args:
            ocsp_response: The OCSP response to check
            issuers: A list of issuer(s)

        Returns:
            Boolean - True if all is well, False if a problem was found
        """
        # to check the signature we need to know if the responder is also the issuer
        issuer = issuers[0]
        if (
            ocsp_response.responder_name == issuer.subject
            or ocsp_response.responder_key_hash
            == cryptography.x509.SubjectKeyIdentifier.from_public_key(
                issuer.public_key()
            ).digest
        ):
            # The OCSP responder is the issuer
            logger.debug("This OCSP response is signed by the issuer")
            ocsp_responder_cert = issuer
        else:
            # The issuer delegated to an OCSP responder
            logger.debug(
                "This OCSP response is signed by a delegated OCSP responder, looking for responder cert"
            )

            # loop over certificates in the response and find the responder cert
            for cert in ocsp_response.certificates:
                if (
                    cert.subject == ocsp_response.responder_name
                    or cryptography.x509.SubjectKeyIdentifier.from_public_key(
                        cert.public_key()
                    ).digest
                    == ocsp_response.responder_key_hash
                ):
                    ocsp_responder_cert = cert
                    logger.debug(
                        f"Found OCSP responder cert with the right namehash and keyhash in OCSP response: {ocsp_responder_cert.subject} serial {ocsp_responder_cert.serial_number}. It is signed by {ocsp_responder_cert.issuer}"
                    )
                    break
            else:
                logger.error("Unable to find delegated OCSP responder certificate")
                return False

            # check that the issuer (or issuers issuer) signed the responder cert
            for issuer in issuers:
                if ocsp_responder_cert.issuer == issuer.subject:
                    logger.debug(
                        "The delegated OCSP responder cert is signed by a cert in the issuer chain."
                    )
                    break
                else:
                    logger.debug(
                        f"The delegated OCSP responder cert is not signed by the issuer {issuer.subject}"
                    )
            else:
                logger.error(
                    "The OCSP responder certificate is not signed by certificate issuer or issuers issuer."
                )
                return False

            # verify the issuer signature
            logger.debug(
                "Verifying issuer signature on delegated responder certificate"
            )
            if not cls.verify_signature(
                pubkey=issuer.public_key(),
                signature=ocsp_responder_cert.signature,
                payload=ocsp_responder_cert.tbs_certificate_bytes,
                hashalgo=ocsp_responder_cert.signature_hash_algorithm,
            ):
                logger.error(
                    "The issuer signature on the responder certificate is invalid"
                )
                return False

            # get the ExtendedKeyUsage extension to check for OCSP_SIGNING capability
            try:
                extension = ocsp_responder_cert.extensions.get_extension_for_class(
                    cryptography.x509.ExtendedKeyUsage
                )
            except cryptography.x509.extensions.ExtensionNotFound:
                logger.error(
                    "No ExtendedKeyUsage extension found in delegated OCSP responder certificate"
                )
                return False

            # check if the delegated responder cert is permitted to sign OCSP responses
            if (
                cryptography.x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING
                not in extension.value
            ):
                logger.error(
                    "Delegated OCSP responder certificate is not permitted to sign OCSP responses"
                )
                return False

        # check that the ocsp responder (cert issuer or delegated) signed the OCSP response we got
        logger.debug("Verifying OCSP response signature")
        if not cls.verify_signature(
            pubkey=ocsp_responder_cert.public_key(),
            signature=ocsp_response.signature,
            payload=ocsp_response.tbs_response_bytes,
            hashalgo=ocsp_response.signature_hash_algorithm,
        ):
            logger.error("The OCSP response signature is invalid")
            return False

        # all good
        return True

    # utility methods

    @staticmethod
    def verify_signature(
        pubkey: typing.Union[
            primitives.asymmetric.dsa.DSAPublicKey,
            primitives.asymmetric.ed25519.Ed25519PublicKey,
            primitives.asymmetric.ed448.Ed448PublicKey,
            primitives.asymmetric.ec.EllipticCurvePublicKey,
            primitives.asymmetric.rsa.RSAPublicKey,
        ],
        signature: bytes,
        payload: bytes,
        hashalgo: cryptography.hazmat.primitives.hashes.HashAlgorithm,
    ) -> bool:
        """Verify a signature on a payload using the provided public key and hash algorithm.

        Supports RSA and EC public keys. Assumes PKCS1v15 padding for RSA keys.

        Args:
            pubkey: The public key
            signature: The bytes representing the signature
            payload: The bytes representing the signed data
            hashalgo: The hashing algorithm used for the signature
        """
        logger.debug(
            f"Verifying {type(pubkey)} signature with hash algorithm {hashalgo}. Payload is {len(payload)} bytes."
        )
        try:
            if isinstance(pubkey, primitives.asymmetric.rsa.RSAPublicKey):
                pubkey.verify(
                    signature=signature,
                    data=payload,
                    padding=primitives.asymmetric.padding.PKCS1v15(),
                    algorithm=hashalgo,
                )
            elif isinstance(pubkey, primitives.asymmetric.ec.EllipticCurvePublicKey):
                pubkey.verify(
                    signature=signature,
                    data=payload,
                    signature_algorithm=primitives.asymmetric.ec.ECDSA(hashalgo),
                )
            else:
                logger.error(
                    "The public key type is not supported, unable to verify signature, returning False"
                )
                return False
        except cryptography.exceptions.InvalidSignature:  # type: ignore
            logger.error("Got exception while verifying signature")
            return False

        # all good
        logger.debug("Signature is valid")
        return True

    @staticmethod
    def ping_command() -> None:
        """Reply to the ping command by outputting the string 'pong' to stdout.

        Args: None
        Returns: None
        """
        logger.debug("Responding to ping_command() with 'pong'")
        print("pong")


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description="certgrinderd version %s. See the manpage certgrinderd(8) or ReadTheDocs for more info."
        % __version__
    )

    # add topmost subparser for main command
    subparsers = parser.add_subparsers(
        help="Command (required)", dest="command", required=True
    )

    # "get" command
    get_parser = subparsers.add_parser(
        "get", help='Use the "get" command to get certificates or OCSP responses'
    )
    get_subparsers = get_parser.add_subparsers(
        help="Specify what to get using one of the available get sub-commands",
        dest="subcommand",
        required=True,
    )

    # "get certificate" subcommand
    get_cert_parser = get_subparsers.add_parser(
        "certificate", help="Get a new certificate. Requires a CSR."
    )
    get_cert_parser.set_defaults(method="get_certificate_command")

    # "get ocsp" subcommand
    get_ocsp_parser = get_subparsers.add_parser(
        "ocsp", help="Get an OCSP response for the provided certificate."
    )
    get_ocsp_parser.set_defaults(method="get_ocsp_command")

    # "show" command
    show_parser = subparsers.add_parser(
        "show",
        help='Use the "show" command to show configuration, CSR info, or certificate info.',
    )
    show_subparsers = show_parser.add_subparsers(
        help="Specify what to show using one of the available show sub-commands",
        dest="subcommand",
        required=True,
    )

    # "show certificate" subcommand
    show_certificate_parser = show_subparsers.add_parser(
        "certificate",
        help="Tell certgrinder to output information about the provided certificate.",
    )
    show_certificate_parser.set_defaults(method="show_certificate_command")

    # "show csr" subcommand
    show_csr_parser = show_subparsers.add_parser(
        "csr", help="Tell certgrinder to output information about the provided CSR."
    )
    show_csr_parser.set_defaults(method="show_csr_command")

    # "show configuration" subcommand
    show_configuration_parser = show_subparsers.add_parser(
        "configuration", help="Tell certgrinder to output the current configuration"
    )
    show_configuration_parser.set_defaults(method="show_configuration_command")

    # "help" command
    subparsers.add_parser("help", help='The "help" command just outputs the usage help')

    # "ping" command
    ping_parser = subparsers.add_parser(
        "ping",
        help='The "ping" command is used by the certgrinder client to verify connectivity to the server. It just outputs the word "pong" to stdout.',
    )
    ping_parser.set_defaults(method="ping_command")

    parser.add_argument(
        "--acme-email",
        dest="acme-email",
        help="The email for the ACME account.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--acme-server-url",
        dest="acme-server-url",
        help="The url for the ACME server to use.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-z",
        "--acme-zone",
        dest="acme-zone",
        help="The DNS zone to pass to the auth hook script as env. var. ACMEZONE. For DNS-01 challenges.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-A",
        "--auth-hook",
        dest="auth-hook",
        help="The hook script to call to prepare auth challenges before calling Certbot",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--certbot-command",
        dest="certbot-command",
        help="The Certbot command to call between auth hook and cleanup hook",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--certbot-config-dir",
        dest="certbot-config-dir",
        help="The path to pass to Certbot as --config-dir",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--certbot-logs-dir",
        dest="certbot-logs-dir",
        help="The path to pass to Certbot as --logs-dir",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--certbot-work-dir",
        dest="certbot-work-dir",
        help="The path to pass to Certbot as --work-dir",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-C",
        "--cleanup-hook",
        dest="cleanup-hook",
        help="The hook script to call to clean up auth challenges after calling Certbot",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config-file",
        help="The path to the certgrinderd config file to use, in YML format.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--certificate-file",
        dest="certificate-file",
        help="The path to the PEM formatted certificate chain file to use instead of getting it from stdin.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--csr-file",
        dest="csr-file",
        help="The path to the PEM formatted CSR file to use instead of getting it from stdin.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        dest="log-level",
        const="DEBUG",
        help="Debug mode. Equal to setting --log-level=DEBUG.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level. One of DEBUG, INFO, WARNING, ERROR, CRITICAL. Defaults to INFO.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-p",
        "--pid-dir",
        dest="pid-dir",
        help="The directory to store the PID file in",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--preferred-chain",
        dest="preferred-chain",
        help="The preferred chain to use. Adds --preferred-chain to the Certbot command. Use to pick preferred signing chain when alternatives are available. Replace spaces with underscores in the chain name, so DST_Root_CA_X3 or ISRG_Root_X1 for prod or Fake_LE_Root_X1 or Fake_LE_Root_X2 for staging.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--skip-acme-server-cert-verify",
        dest="skip-acme-server-cert-verify",
        action="store_true",
        help="Do not verify the ACME servers certificate",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-s",
        "--staging",
        dest="acme-server-url",
        action="store_const",
        const="https://acme-staging-v02.api.letsencrypt.org/directory",
        help="Staging mode. Equal to setting --acme-server-url https://acme-staging-v02.api.letsencrypt.org/directory",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--syslog-facility",
        dest="syslog-facility",
        help="The facility to use for syslog messages",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--syslog-socket",
        dest="syslog-socket",
        help="The socket to use for syslog messages",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-t",
        "--temp-dir",
        dest="temp-dir",
        help="The directory to store temporary files in",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-w",
        "--web-root",
        dest="web-root",
        help="The path to pass to the auth hook script as env WEBROOT to use for HTTP-01 challenges.",
        default=argparse.SUPPRESS,
    )
    return parser


def parse_args(
    mockargs: typing.Optional[typing.List[str]] = None,
) -> typing.Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parse and return command-line args."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: typing.Optional[typing.List[str]] = None) -> None:
    """Make the initial preparations before calling the requested (sub)command.

    - Read config from file and/or commandline args
    - Configure temporary paths
    - Configure logging

    Finally instantiate the Certgrinderd class with the config and call the method.

    Args:
        mockargs: A list of args to use instead of command-line arguments. Optional.

    Returns:
        None
    """
    # get commandline arguments
    parser, args = parse_args(mockargs)

    if args.command == "help":
        parser.print_help()
        sys.exit(0)

    # read and parse the config file
    if hasattr(args, "config-file"):
        with open(getattr(args, "config-file"), "r") as f:
            try:
                config = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(
                    f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out."
                )
                sys.exit(1)
    else:
        # we have no config file
        config = {}

    # command line arguments override config file settings
    config.update(vars(args))

    # remove command and subcommand (part of argparse internals)
    if "command" in config:
        del config["command"]
    if "subcommand" in config:
        del config["subcommand"]

    # create tempfile directory if needed
    kwargs = {"prefix": "certgrinderd-temp-"}
    if "temp-dir" in config and config["temp-dir"]:
        kwargs["dir"] = config["temp-dir"]
    tempdir = tempfile.TemporaryDirectory(**kwargs)
    config["temp-dir"] = tempdir.name

    # instantiate Certgrinderd class
    certgrinderd = Certgrinderd(userconfig=config)

    # all good
    try:
        logger.debug(f"Calling method {args.method}")
        method = getattr(certgrinderd, args.method)
        method()
    finally:
        tempdir.cleanup()

    # we are done here
    logger.info("All done, certgrinderd exiting cleanly.")


if __name__ == "__main__":
    with PidFile("certgrinder"):
        main()
