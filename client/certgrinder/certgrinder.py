#!/usr/bin/env python
"""Certgrinder module.

See https://certgrinder.readthedocs.io/en/latest/certgrinder.html
and https://github.com/tykling/certgrinder for more.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import logging
import logging.handlers
import os
import random
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from pprint import pprint

import cryptography.x509
import dns.resolver
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from pid import PidFile  # type: ignore[import-not-found]
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(f"certgrinder.{__name__}")

# get version number from package metadata if possible
__version__: str
"""The value of this variable is taken from the Python package registry,
and if that fails from the ``_version.py`` file written by ``setuptools_scm``."""

try:
    __version__ = version("certgrinder")
except PackageNotFoundError:
    # package is not installed, get version from file
    try:
        from _version import version as __version__  # type: ignore[import-not-found,no-redef]
    except ImportError:
        # this must be a git checkout with no _version.py file, version unknown
        __version__ = "0.0.0"


class Config(BaseSettings, validate_assignment=True):
    """The Certgrinder settings class.

    Defines default settings, supports env overrides.
    """

    model_config = SettingsConfigDict(env_prefix="certgrinder_", validate_assignment=True)

    acme_server_url: str = ""
    caa_validation_methods: str = "dns-01,http-01"
    certgrinderd: str = "certgrinderd"
    cert_renew_threshold_days: int = 30
    domain_list: list[str] = []
    expected_chain_length: int = 2
    invalid_ca_cn_list: list[str] = ["Fake LE Intermediate X1", "Fake LE Intermediate X2"]
    key_type_list: list[str] = ["rsa", "ecdsa"]
    log_level: str = "INFO"
    name_server: str = ""
    path: Path | None = None
    periodic_sleep_minutes: int = 60
    pid_dir: Path = Path("/tmp")  # noqa: S108
    preferred_chain: str = ""
    post_renew_hooks: list[str] = []
    post_renew_hooks_dir: Path | None = None
    post_renew_hooks_dir_runner: Path | None = None
    staging: bool = False
    syslog_facility: str | None = None
    syslog_socket: str | None = None
    tlsa_port: int = 443
    tlsa_protocol: str = "tcp"
    tlsa_type_list: list[str] = ["310", "311", "312"]


class Certgrinder:
    """The Certgrinder client class."""

    # save version as a class attribute
    __version__ = __version__

    def __init__(
        self,
    ) -> None:
        """Initialise the Certgrinder object."""
        # current domainset
        self.domainset: list[str] = []

        # variabes for paths for local certificate and keys
        self.keypair_path: Path
        self.csr_path: Path
        self.certificate_path: Path
        self.certificate_chain_path: Path
        self.issuer_path: Path
        self.concat_path: Path

        # this is set to True if an error occurs
        self.error: bool = False

        # this is set to True if we need to run post renew hooks
        self.hook_needed: bool = False

        self.conf = Config()

    def configure(
        self,
        userconfig: Mapping[str, str | int | bool | list[str] | Path],
    ) -> None:
        """Merge and check configuration and configure logging.

        Merge the supplied userconfig dict with the default config,
        checks for missing required settings, and configures logging and syslog.

        Args:
            userconfig: dict of the config to be merged with the default config

        Returns:
            None
        """
        # convert dashes to underscores in config keys before setting each in the Config object
        for key in list(userconfig.keys()):
            newkey = key.replace("-", "_") if "-" in key else key
            setattr(self.conf, newkey, userconfig[key])

        # define the log format used for stdout depending on the requested loglevel
        if self.conf.log_level == "DEBUG":
            console_logformat = (
                "%(asctime)s certgrinder %(levelname)s Certgrinder.%(funcName)s():%(lineno)i:  %(message)s"
            )
        else:
            console_logformat = "%(asctime)s certgrinder %(levelname)s %(message)s"

        # configure the log format used for console
        logging.basicConfig(
            level=getattr(logging, str(self.conf.log_level)),
            format=console_logformat,
            datefmt="%Y-%m-%d %H:%M:%S %z",
        )

        # check if we have a domain-list
        if not self.conf.domain_list:
            logger.error(
                "No domain-list(s) configured. Specify --domain-list "
                "example.com[,www.example.com] (once per certificate) or "
                "define domain-list: in the config file."
            )
            sys.exit(1)

        # check if we have a path
        if self.conf.path is None:
            logger.error("No configured path. Specify --path or define path: in the config file.")
            sys.exit(1)

        # check if configured path exists
        if not self.conf.path.exists():
            logger.error(f"Configured path {self.conf.path} does not exist")
            sys.exit(1)

        # check if configured path is writable
        try:
            with tempfile.TemporaryFile(dir=self.conf.path) as _:
                pass
        except PermissionError:
            logger.error("Permission error while accessing configured path {self.conf.path}")  # noqa: TRY400
            sys.exit(1)

        # connect to syslog?
        if self.conf.syslog_socket and self.conf.syslog_facility:
            facility: int = getattr(logging.handlers.SysLogHandler, str(self.conf.syslog_facility))
            syslog_handler = logging.handlers.SysLogHandler(address=str(self.conf.syslog_socket), facility=facility)
            syslog_format = logging.Formatter("certgrinder: %(message)s")
            syslog_handler.setFormatter(syslog_format)
            logger.addHandler(syslog_handler)
            # usually SysLogHandler is lazy and doesn't connect the socket until
            # a message has to be sent. Call _connect_unixsocket() now to force
            # an exception now if we can't connect to the socket
            syslog_handler._connect_unixsocket(  # type: ignore[attr-defined] # noqa: SLF001
                self.conf.syslog_socket
            )
        else:
            logger.debug("Not configuring syslog")

        # is this staging mode?
        if self.conf.staging:
            logger.debug(
                "Staging mode enabled. Setting acme-server-url to "
                "'https://acme-staging-v02.api.letsencrypt.org/directory' and "
                "invalid-ca-cn-list to an empty list."
            )
            self.conf.acme_server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
            self.conf.invalid_ca_cn_list = []
            # one intermediate
            self.conf.preferred_chain = "Fake_LE_Root_X2"
        else:
            # the current LE chain has one intermediate
            self.conf.preferred_chain = "ISRG_Root_X1"

        # one intermediate
        self.conf.expected_chain_length = 2

        logger.debug(f"Certgrinder {__version__} configured OK - running with config: {self.conf}")

    # RSA KEY METHODS

    @staticmethod
    def load_keypair(
        path: Path,
    ) -> (
        primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey
    ):
        """Load keypair bytes from disk, load key and return the object.

        Fixes keypair permissions to 640 if they are not 640.

        Args:
            path: The path to load the keypair from

        Returns:
            The keypair object
        """
        # check permissions for self.keypair_path and fix to 640 if needed
        if oct(path.stat().st_mode)[4:] != "0640":
            logger.warning(f"Keypair {path} has incorrect permissions, fixing to 0640...")
            path.chmod(0o640)

        # read keypair
        with path.open("rb") as f:
            keypair_bytes = f.read()

        # parse and return keypair
        return primitives.serialization.load_pem_private_key(keypair_bytes, password=None, backend=default_backend())  # type: ignore[no-any-return]

    @staticmethod
    def generate_private_key(
        keytype: str,
    ) -> (
        primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
    ):
        """Generate and returns a private key.

        Args:
            keytype: "rsa" for RSA key, "ecdsa" for ECDSA and "ed25519" for ed25519

        Returns:
            The keypair object

        Raises:
            ValueError: For unsupported keytypes
        """
        if keytype == "rsa":
            return primitives.asymmetric.rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
        if keytype == "ecdsa":
            return primitives.asymmetric.ec.generate_private_key(
                primitives.asymmetric.ec.SECP384R1(),
                backend=default_backend(),
            )
        if keytype == "ed25519":
            return primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        msg = f"Unsupported keytype: {keytype}"
        raise TypeError(msg)

    @staticmethod
    def save_keypair(
        keypair: primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey,
        path: Path,
    ) -> None:
        """Save keypair to disk.

        Args:
            keypair: The keypair to save
            path: The path to save the keypair in

        Returns:
            None

        Raises:
            TypeError: For unsupported keytypes
        """
        if isinstance(keypair, primitives.asymmetric.rsa.RSAPrivateKey):
            keyformat = primitives.serialization.PrivateFormat.TraditionalOpenSSL
        elif isinstance(
            keypair, primitives.asymmetric.ed25519.Ed25519PrivateKey | primitives.asymmetric.ec.EllipticCurvePrivateKey
        ):
            keyformat = primitives.serialization.PrivateFormat.PKCS8
        else:
            msg = f"Unsupported keytype: {type(keypair)}"
            raise TypeError(msg)

        with path.open("wb") as f:
            f.write(
                keypair.private_bytes(  # type: ignore[union-attr]
                    encoding=primitives.serialization.Encoding.PEM,
                    format=keyformat,
                    encryption_algorithm=primitives.serialization.NoEncryption(),
                )
            )
        path.chmod(0o640)

    @staticmethod
    def get_der_pubkey(
        keypair: primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey,
    ) -> bytes:
        """Return the DER formatted publickey.

        Args:
            keypair: The keypair which contains the public key

        Returns:
            The bytes representing the DER formatted public key
        """
        derbytes: bytes = keypair.public_key().public_bytes(
            encoding=primitives.serialization.Encoding.DER,
            format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return derbytes

    # CSR METHODS

    @staticmethod
    def generate_csr(
        keypair: primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey,
        domains: list[str],
    ) -> cryptography.x509.CertificateSigningRequest:
        """Generate and return a new CSR based on the public key and list of domains.

        Only set CN since everything else is removed by LetsEncrypt in the certificate anyway.
        Add all domains in subjectAltName, including the one put into CN.

        Args:
            keypair: The keypair to base the CSR on
            domains: A list of domains to put in the CSR. First in the list will be cert CN.

        Returns:
            The CSR object
        """
        # build list of cryptography.x509.DNSName objects for SAN
        x509_name_list: list[cryptography.x509.GeneralName] = []
        for domain in domains:
            idnadomain = domain.encode("idna").decode("utf-8")
            logger.debug(f"Adding {idnadomain} to CSR...")
            x509_name_list.append(cryptography.x509.DNSName(idnadomain))

        # build and return the CSR
        return (
            cryptography.x509.CertificateSigningRequestBuilder()
            .subject_name(
                cryptography.x509.Name(
                    [
                        cryptography.x509.NameAttribute(
                            cryptography.x509.oid.NameOID.COMMON_NAME,
                            domains[0].encode("idna").decode("utf-8"),
                        )
                    ]
                )
            )
            .add_extension(
                cryptography.x509.SubjectAlternativeName(x509_name_list),
                critical=False,
            )
            .sign(
                keypair,
                primitives.hashes.SHA256(),
                default_backend(),
            )
        )

    @staticmethod
    def save_csr(csr: cryptography.x509.CertificateSigningRequest, path: Path) -> None:
        """Save the PEM version of the CSR to the path.

        chmods the file 644 after writing.

        Args:
            csr: The CSR to be saved
            path: The path to save the CSR to

        Returns:
            None
        """
        with path.open("wb") as f:
            f.write(csr.public_bytes(primitives.serialization.Encoding.PEM))
        path.chmod(0o644)

    # CERTIFICATE METHODS

    def load_certificates(self, path: Path) -> list[cryptography.x509.Certificate]:
        """Reads PEM certificate data from the path, parses the certificate(s), and returns them in a list.

        Args:
            path: The path to read the PEM certificate(s) from

        Returns:
            A list of cryptography.x509.Certificate objects
        """
        with path.open("rb") as f:
            pem_bytes = f.read()
        cert_bytes_list = self.split_pem_chain(pem_bytes)
        certificates = []
        for certbytes in cert_bytes_list:
            certificate = self.parse_certificate(certbytes)
            if not certificate:
                # something went wrong while parsing this certificate,
                # just return an empty list
                return []
            certificates.append(certificate)
        return certificates

    @staticmethod
    def check_certificate_issuer(certificate: cryptography.x509.Certificate, invalid_ca_cn_list: list[str]) -> bool:
        """Check the issuer of the certificate.

        Args:
            certificate: The certificate to check
            invalid_ca_cn_list: The list of CA CommonName strings to consider invalid

        Returns:
            True if the certificate issuer CN is not in invalid_ca_cn_list
        """
        # Return False if the certificate was issued by itself
        if certificate.issuer == certificate.subject:
            logger.debug("This certificate is selfsigned, returning False")
            return False

        # do we have any invalid CA CNs? otherwise bail out now
        if not invalid_ca_cn_list:
            logger.debug("We have an empty invalid_ca_cn_list, returning True")
            return True

        # check if certificate was issued by an invalid CA CN
        for x in certificate.issuer:
            if x.oid == cryptography.x509.oid.NameOID.COMMON_NAME and x.value in invalid_ca_cn_list:
                logger.debug(
                    f"This certificate was issued by a CA CN ({x.value}) in "
                    f"invalid_ca_cn_list ({invalid_ca_cn_list}), check_certificate_issuer() "
                    "returning False"
                )
                return False

        # all good
        return True

    @staticmethod
    def check_certificate_expiry(certificate: cryptography.x509.Certificate, threshold_days: int) -> bool:
        """Check the remaining validity of the certificate.

        Args:
            certificate: The certificate to check
            threshold_days: The lowest number of remaining days of validity that is considered valid

        Returns:
            True if remaining certificate lifetime is >= threshold_days, False if not
        """
        expiredelta = certificate.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)  # type: ignore[attr-defined]
        return expiredelta.days > threshold_days  # type: ignore[no-any-return]

    @staticmethod
    def check_certificate_public_key(
        certificate: cryptography.x509.Certificate,
        public_key: primitives.asymmetric.rsa.RSAPublicKey
        | primitives.asymmetric.ed25519.Ed25519PublicKey
        | primitives.asymmetric.ec.EllipticCurvePublicKey,
    ) -> bool:
        """Make sure certificate has the specified public key.

        Args:
            certificate: The certificate to check
            public_key: The public key

        Returns:
            True if the public key matches, False if not
        """
        return bool(
            public_key.public_bytes(
                encoding=primitives.serialization.Encoding.PEM,
                format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            == certificate.public_key().public_bytes(
                encoding=primitives.serialization.Encoding.PEM,
                format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    @staticmethod
    def check_certificate_subject(certificate: cryptography.x509.Certificate, subject: cryptography.x509.Name) -> bool:
        """Make sure the certificate has the specified subject.

        Args:
            certificate: The certificate to check
            subject: The subject to expect

        Returns:
            True if the subject matches the cert, False if not
        """
        return str(certificate.subject) == str(subject)

    @staticmethod
    def check_certificate_san_names(certificate: cryptography.x509.Certificate, san_names: list[str]) -> bool:
        """Make sure the certificate has the provided list of names as SAN.

        Args:
            certificate: The certificate to check
            san_names: A list of the names to expect

        Returns:
            True if all san_names were found in the cert, and no others.
        """
        cert_san = certificate.extensions.get_extension_for_oid(
            cryptography.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        # make mypy happy
        cert_san_names = cert_san.get_values_for_type(cryptography.x509.DNSName)

        # make sure san_names list is idna encoded
        san_names = [name.encode("idna").decode("ascii") for name in san_names]

        # if there is a difference between the sets we want to return False
        return not bool(set(cert_san_names).symmetric_difference(san_names))

    @classmethod
    def check_certificate_validity(  # noqa: PLR0913
        cls,
        certificate: cryptography.x509.Certificate,
        invalid_ca_cn_list: list[str],
        threshold_days: int,
        san_names: list[str],
        public_key: primitives.asymmetric.rsa.RSAPublicKey
        | primitives.asymmetric.ed25519.Ed25519PublicKey
        | primitives.asymmetric.ec.EllipticCurvePublicKey
        | None = None,
        subject: cryptography.x509.Name | None = None,
    ) -> bool:
        """Perform a few sanity checks of the certificate.

        - Check that the issuer is valid
        - Check that the certificate expiry is not exceeded
        - Check that the public key is correct (if provided)
        - Check that the subject is correct (if provided)
        - Check that the SubjectAltName data is correct

        Args:
            certificate: The certificate to check
            invalid_ca_cn_list: A list of CA CommonNames to consider invalid
            threshold_days: The minimum number of remaining days lifetime to considered valid.
            san_names: A list of domain names to expect in SubjectAltName of the certificate.
            public_key: The pubkey the certificate is for.
            subject: The expected subject of the certificate

        Returns:
            False if a problem is found, True if all is well.
        """
        if not cls.check_certificate_issuer(certificate, invalid_ca_cn_list):
            logger.error(
                f"Certificate is self-signed or the issuer {certificate.issuer} "
                f"CN is on our list of invalid CAs: {invalid_ca_cn_list}."
            )
            return False
        if not cls.check_certificate_expiry(certificate, threshold_days):
            logger.error(f"Certificate expires in less than {threshold_days} days")
            return False
        if public_key and not cls.check_certificate_public_key(certificate, public_key):
            logger.error("Certificate public key is different from the expected")
            return False
        if subject and not cls.check_certificate_subject(certificate, subject):
            logger.error("Certificate subject is different from the expected")
            return False
        if not cls.check_certificate_san_names(certificate, san_names):
            logger.error(f"Certificate SAN name list is different from the expected: {san_names}")
            return False
        logger.debug("Certificate is OK, returning True")
        return True

    @staticmethod
    def save_certificate(
        certificate: cryptography.x509.Certificate,
        path: Path,
        issuers: list[cryptography.x509.Certificate] | None = None,
    ) -> None:
        """Save the PEM certificate to the path, optionally with an issuer chain.

        Args:
            certificate: The certificate to save
            path: The path to save the certificate in
            issuers: The list of issuer certificates to write after the certificate (if any)

        Returns:
            None
        """
        with path.open("wb") as f:
            f.write(certificate.public_bytes(primitives.serialization.Encoding.PEM))
            if issuers:
                for issuer in issuers:
                    f.write(issuer.public_bytes(primitives.serialization.Encoding.PEM))
        path.chmod(0o644)

    @classmethod
    def save_concat_certkey(
        cls,
        keypair: primitives.asymmetric.rsa.RSAPrivateKey
        | primitives.asymmetric.ed25519.Ed25519PrivateKey
        | primitives.asymmetric.ec.EllipticCurvePrivateKey,
        certificate: cryptography.x509.Certificate,
        issuers: list[cryptography.x509.Certificate],
        path: Path,
    ) -> None:
        """Create a single file with the private key, the cert and the issuer(s), in that order.

        Args:
            keypair: The keypair to save in the concat file
            certificate: The certificate to save in the concat file
            issuers: The list of issuer(s) to save in the concat file
            path: The path to save the concat file in

        Returns:
            None
        """
        cls.save_keypair(keypair, path)
        with path.open("ab") as f:
            f.write(certificate.public_bytes(primitives.serialization.Encoding.PEM))
            for issuer in issuers:
                f.write(issuer.public_bytes(primitives.serialization.Encoding.PEM))
        path.chmod(0o640)

    def get_certgrinderd_command(self, subcommand: list[str]) -> list[str]:
        """Return the certgrinderd command to run.

        Adds ``--log-level`` with the current ``self.conf.log_level``.
        Also adds --acme-server-url if configured, and --preferred-chain.

        Args:
            subcommand: The certgrinderd subcommand to run as a list, like ["get", "certificate"]

        Returns:
            A list of the elements which make up the ``certgrinderd`` command
        """
        # put the command together, first the base command, then the args, then subcommand
        command = str(self.conf.certgrinderd)
        commandlist = shlex.split(command)

        # pass the certgrinder log-level to certgrinderd
        commandlist.append("--log-level")
        commandlist.append(str(self.conf.log_level))

        # pass the acme-server-url if we have one
        if self.conf.acme_server_url:
            commandlist.append("--acme-server-url")
            commandlist.append(str(self.conf.acme_server_url))

        # pass the preferred-chain
        commandlist.append("--preferred-chain")
        commandlist.append(str(self.conf.preferred_chain))

        # add the requested certgrinderd command and subcommand,
        # like "get certificate" mostly
        commandlist += subcommand

        # all good
        return commandlist

    def run_certgrinderd(
        self,
        stdin: bytes,
        command: list[str],
        certgrinderd_stdout: bytes = b"",
        certgrinderd_stderr: bytes = b"",
    ) -> bytes:
        """Run the configured ``self.conf.certgrinderd`` command.

        The stdin argument will be passed to stdin of the command. A CSR is needed for
        the "get certificate" certgrinderd command.

        Args:
            stdin: bytes representing CSR or cert chain to pass to the certgrinderd command
            command: The certgrinderd command and subcommand to call
            certgrinderd_stdout: Mocked certgrinderd stdout to use instead of calling the command
            certgrinderd_stderr: Mocked certgrinderd stderr to use instead of calling the command

        Returns:
            The bytes representing the stdout from the subprocess call
        """
        if not certgrinderd_stdout and not certgrinderd_stderr:
            commandlist = self.get_certgrinderd_command(subcommand=command)
            logger.debug(f"Running certgrinderd command: {commandlist}")
            p = subprocess.Popen(  # noqa: S603
                commandlist,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # send stdin and save stdout (the certificate chain/other output) +
            # stderr (the certgrinderd logging)
            certgrinderd_stdout, certgrinderd_stderr = p.communicate(input=stdin)
        logger.debug(
            f"certgrinderd command returned {len(certgrinderd_stdout)} bytes "
            f"stdout and {len(certgrinderd_stderr)} bytes stderr output"
        )

        # log certgrinderd_stderr (which contains the certgrinderd logging) at the level it was logged to, as possible
        if isinstance(certgrinderd_stderr, bytes):
            for line in certgrinderd_stderr.strip().decode("utf-8").split("\n"):
                # do not log empty lines
                if not line:
                    continue

                # split line in words
                words = line.split(" ")
                if len(words) < 5:  # noqa: PLR2004
                    # cannot parse, log the whole line
                    logger.warning(line)
                    continue

                # get the loglevel
                level = words[4]
                message = " ".join(words[5:])
                if hasattr(logger, level.lower()):
                    if level.lower() == "debug":
                        getattr(logger, level.lower())(message)
                    else:
                        getattr(logger, level.lower())(f"certgrinderd: {message}")
                else:
                    # cannot grok, log the whole line
                    logger.warning(line)

        # finally return the actual output to caller
        return certgrinderd_stdout

    @staticmethod
    def split_pem_chain(pem_chain_bytes: bytes) -> list[bytes]:
        """Split a PEM chain into a list of bytes of the individual PEM certificates.

        Args:
            pem_chain_bytes: The bytes representing the PEM chain

        Returns:
            A list of 0 or more bytes chunks representing each certificate
        """
        logger.debug(f"Parsing certificates from {len(pem_chain_bytes)} bytes input")
        cert_list = pem_chain_bytes.decode("ASCII").split("-----BEGIN CERTIFICATE-----")
        certificates = [("-----BEGIN CERTIFICATE-----" + cert).encode("ASCII") for cert in cert_list[1:]]
        logger.debug(f"Returning a list of {len(certificates)} chunks of bytes resembling PEM certificates")
        return certificates

    @staticmethod
    def parse_certificate(
        certificate_bytes: bytes,
    ) -> cryptography.x509.Certificate | None:
        """Parse a bunch of bytes representing a PEM certificate and return.

        Args:
            certificate_bytes: The PEM certificate

        Returns:
            The parsed cryptography.x509.Certificate object or None
        """
        try:
            return cryptography.x509.load_pem_x509_certificate(certificate_bytes, default_backend())
        except Exception:  # noqa: BLE001
            logger.error("Unable to parse, this is not a valid PEM formatted certificate.")  # noqa: TRY400
            logger.debug("This is the certificate which failed to parse:")
            logger.debug(certificate_bytes)
            return None

    def parse_certificate_chain(
        self, certificate_chain: bytes, csr: cryptography.x509.CertificateSigningRequest
    ) -> list[cryptography.x509.Certificate] | None:
        """Split a PEM chain into a list of certificates.

        Args:
            certificate_chain: The bytes representing the PEM formatted certificate chain
            csr: The CSR this certificate was issued from

        Returns:
            A list of certificates with the leaf certificate first,
            or None if an error happens
        """
        certs = self.split_pem_chain(certificate_chain)
        if len(certs) != self.conf.expected_chain_length:
            logger.error(
                "The input does not contain a valid certificate chain (it does not have "
                f"{self.conf.expected_chain_length} PEM-looking chunks, it has {len(certs)})."
            )
            logger.debug("This is the certificate chain which failed to parse:")
            logger.debug(certificate_chain)
            # we do not have a valid certificate
            return None

        certificates = []
        for certbytes in certs:
            certificate = self.parse_certificate(certbytes)
            if not certificate:
                return None
            certificates.append(certificate)

        # a few sanity checks of the certificate seems like a good idea
        valid = self.check_certificate_validity(
            certificate=certificates[0],
            invalid_ca_cn_list=[] if self.conf.staging else [str(x) for x in self.conf.invalid_ca_cn_list],
            threshold_days=self.conf.cert_renew_threshold_days,
            public_key=self.keypair.public_key(),
            subject=csr.subject,
            san_names=self.domainset,
        )
        if not valid:
            logger.error("Certificate is not valid.")
            self.error = True
            return None

        # we have a new certificate, so we will need to run the post renew hook later
        self.hook_needed = True

        # done, return the certificate chain bytes
        return certificates

    def get_certificate(
        self,
        csr: cryptography.x509.CertificateSigningRequest | None = None,
        stdout: bytes | None = None,
    ) -> bool:
        """Get a new certificate for self.domainset.

        This method gets a new certificate regardless of the status of any
        existing certificate. It is called by ``self.periodic()`` as needed.
        It can also be called by the ``get certificate`` subcommand.

        Args:
            csr: The CSR to use instead of generating one
            stdout: The stdout bytes to use instead of calling self.run_certgrinderd(csr)

        Returns:
            False something goes wrong, True if all is well
        """
        logger.info(f"Getting new certificate for domainset {self.domainset} ...")
        # do we have a CSR or do we generate one?
        if not csr:
            # generate new CSR
            csr = self.generate_csr(self.keypair, self.domainset)
        self.save_csr(csr, self.csr_path)
        logger.debug(
            f"Wrote {len(csr.public_bytes(primitives.serialization.Encoding.PEM))} bytes CSR to path {self.csr_path}"
        )

        # do we have stdout or do we run certgrinderd for real?

        if not stdout:
            # get certificate
            stdout = self.run_certgrinderd(
                stdin=csr.public_bytes(primitives.serialization.Encoding.PEM),
                command=["get", "certificate"],
            )

        # did we get any output?
        if not stdout:
            logger.error("Did not get any output, expected a certificate chain in stdout from certgrinderd")
            return False

        # parse the output
        certificates = self.parse_certificate_chain(stdout, csr)

        # certificates should be a tuple of 2 or 3 certificates
        if certificates:
            certificate = certificates[0]
            issuers = certificates[1:]
        else:
            logger.error("Did not get a certificate :(")
            return False

        issuerlen = 0
        for issuer in issuers:
            issuerlen += len(issuer.public_bytes(primitives.serialization.Encoding.PEM))

        logger.info(
            f"Success! Got {len(certificate.public_bytes(primitives.serialization.Encoding.PEM))} "
            f"bytes certificate and {issuerlen} bytes representing {len(issuers)} issuer "
            "certificates from certgrinderd"
        )

        # save cert, chain and concat
        self.save_certificate(certificate, self.certificate_path)
        self.save_certificate(certificate, self.certificate_chain_path, issuers)
        self.save_certificate(issuers[0], self.issuer_path, issuers[1:])
        self.save_concat_certkey(self.keypair, certificate, issuers, self.concat_path)

        # all done
        self.hook_needed = True
        logger.debug(
            f"Saved new certificate and chain to files {self.certificate_chain_path}, "
            f"{self.certificate_path}, and {self.concat_path}"
        )
        return True

    def check_certificate(
        self,
        certificate: cryptography.x509.Certificate | None = None,
        public_key: primitives.asymmetric.rsa.RSAPublicKey
        | primitives.asymmetric.ed25519.Ed25519PublicKey
        | primitives.asymmetric.ec.EllipticCurvePublicKey
        | None = None,
    ) -> bool:
        """Check certificate validity and returns True or False.

        This method is called by self.grind() once per domainset when the "check certificate"
        subcommand is invoked.
        It reads the certificate from self.certificate_path if there is no certificate arg

        Args:
            certificate: The certificate to be checked
            public_key: The keypair the certificate is based on

        Returns:
            True if everything is OK, False otherwise
        """
        # load certificate from disk?
        if not certificate:
            # does the file exist?
            if self.certificate_chain_path.exists():
                certificate = self.load_certificates(self.certificate_chain_path)[0]
            else:
                logger.error(f"Certificate {self.certificate_chain_path} not found")
                self.error = True
                return False

        # check cert
        valid = self.check_certificate_validity(
            certificate=certificate,
            invalid_ca_cn_list=[] if self.conf.staging else [str(x) for x in self.conf.invalid_ca_cn_list],
            threshold_days=self.conf.cert_renew_threshold_days,
            public_key=public_key,
            san_names=self.domainset,
        )
        # set self.error if cert is not valid (we may need the information later)
        if not valid:
            self.error = True
        return valid

    def show_certificate(self) -> None:
        """The ``show certificate`` subcommand method, called for each domainset by ``self.grind()``.

        Returns:
            None
        """
        if not self.certificate_path.exists():
            logger.error(f"Certificate {self.certificate_path} not found")
            return
        certificate = self.load_certificates(self.certificate_path)[0]
        logger.info(f"- Showing certificate for keytype '{self.keytype}' for domain set: {self.domainset}")
        logger.info(f"Certificate keypair path: {self.keypair_path}")
        logger.info(f"Certificate chain path: {self.certificate_chain_path}")
        logger.info(f"Certificate path: {self.certificate_path}")
        logger.info(f"Certificate serial: {certificate.serial_number}")
        logger.info(f"Certificate subject: {certificate.subject}")
        logger.info(f"Certificate issuer: {certificate.issuer}")
        san = certificate.extensions.get_extension_for_oid(cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        logger.info(f"Certificate SAN: {san.value.get_values_for_type(cryptography.x509.DNSName)}")
        logger.info(f"Certificate not valid before: {certificate.not_valid_before_utc}")  # type: ignore[attr-defined]
        logger.info(f"Certificate not valid after: {certificate.not_valid_after_utc}")  # type: ignore[attr-defined]

    # POST RENEW HOOK METHOD

    def run_post_renew_hooks(self) -> bool:
        """Loops over configured post_renew_hooks and executables in post_renew_hooks_dir and runs them.

        Returns:
            None
        """
        # Process any configured post-renew-hooks
        if not self.conf.post_renew_hooks:
            logger.debug("No post-renew-hooks found in config")
        else:
            # loop over and run hooks
            for hook in self.conf.post_renew_hooks:
                self.run_post_renew_hook(hook.split(" "))

        # Process any executables in post-renew-hooks-dir if configured
        if self.conf.post_renew_hooks_dir is None:
            logger.debug("No post-renew-hooks-dir found in config")
            return True

        # loop over files in the hooks dir
        for dirhook in self.conf.post_renew_hooks_dir.iterdir():
            # skip directories
            if dirhook.is_dir():
                continue
            # and files not executable by the current user
            if not os.access(dirhook, os.X_OK):
                continue

            if self.conf.post_renew_hooks_dir_runner is not None:
                # use the configured hook runner
                self.run_post_renew_hook([self.conf.post_renew_hooks_dir_runner, dirhook])
            else:
                # run hooks in dir as is
                self.run_post_renew_hook([dirhook])

        # all done
        return True

    @staticmethod
    def run_post_renew_hook(hook: Sequence[Path | str]) -> bool:
        """Run a specific post renew hook.

        Args:
            hook: A list of string components of the command and arguments

        Returns: True if exit code was 0, False otherwise.
        """
        logger.info(f"Running post renew hook: {hook!s}")
        start = datetime.datetime.now(tz=datetime.timezone.utc)
        p = subprocess.Popen(hook)  # noqa: S603
        runtime = datetime.datetime.now(tz=datetime.timezone.utc) - start
        exitcode = p.wait()
        if exitcode != 0:
            logger.error(f"Got exit code {exitcode} when running post_renew_hook {hook!s} - hook runtime was {runtime}")
            return False
        logger.info(f"Post renew hook {hook!s} ended with exit code 0, good. Hook runtime was {runtime}")
        return True

    # SPKI METHODS

    @staticmethod
    def generate_spki(derkey: bytes) -> str:
        """Generate and return a pin-sha256 spki hpkp style pin for the provided public key.

        OpenSSL equivalent command is:
            openssl x509 -in example.com.crt -pubkey -noout | openssl pkey \
            -pubin -outform der | openssl dgst -sha256 -binary | openssl base64

        Args:
            derkey: The bytes representing the public key in DER format

        Returns:
            A string of the SPKI pin
        """
        return base64.b64encode(hashlib.sha256(derkey).digest()).decode("ASCII")

    @classmethod
    def output_spki(cls, derkey: bytes) -> None:
        """Get and print the spki pin for the supplied DER public key.

        Args:
            derkey: The bytes representation of the DER formatted public key

        Returns:
            None
        """
        spki = cls.generate_spki(derkey)
        logger.info(f"pin-sha256='{spki}'")

    def show_spki(self) -> None:
        """The ``show spki`` subcommand method, called for each domainset by ``self.grind()``.

        Call ``self.output_spki()`` with the DER formatted public key and output the result.

        Returns:
            None
        """
        logger.debug(f"Generated SPKI pin-sha256 for public key for domainset {self.domainset}:")
        self.output_spki(derkey=self.get_der_pubkey(self.keypair))

    # TLSA METHODS

    @staticmethod
    def generate_tlsa_record(derkey: bytes, tlsatype: str) -> str:
        """Generate and return the data part of a TLSA record of the requested type.

        TLSA record is generated from the DER formatted public key supplied.
        Returns an uppercase hex string.

        Args:
            derkey: The bytes representing the public key in DER format
            tlsatype: The TLSA type (like "310")

        Returns:
            String of the TLSA data

        Raises:
            ValueError: If an unknown TLSA type is passed
        """
        if tlsatype == "310":
            # Generate DANE-EE Publickey Full (3 1 0) TLSA Record
            return binascii.hexlify(derkey).decode("ASCII").upper()
        if tlsatype == "311":
            # Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record
            return hashlib.sha256(derkey).hexdigest().upper()
        if tlsatype == "312":
            # Generate DANE-EE Publickey SHA512 (3 1 2) TLSA Record
            return hashlib.sha512(derkey).hexdigest().upper()
        msg = f"Unsupported TLSA type: {tlsatype}"
        raise ValueError(msg)

    @staticmethod
    def lookup_tlsa_record(  # noqa: C901
        domain: str,
        port: int,
        protocol: str,
        tlsatype: str | None = None,
        nameserver: str = "",
    ) -> list[str] | None:
        """Lookup TLSA records in DNS for the configured domain, port, and protocol.

        Loop over any responses and look for the requested tlsatype.
        Return a list of results, optionally limited to the specified tlsatype, or None.
        Use system resolver unless nameserver is specified.

        Args:
            domain: The service domain name (like ``mail.example.com``)
            port: The service port (like ``443``)
            protocol: The service protocol (like ``tcp``)
            tlsatype: The TLSA type (like ``312``)
            nameserver: The DNS server IP to use instead of system resolver (optional)

        Returns:
            A list of records or None
        """
        record = f"_{port}._{protocol}.{domain}"
        nameserverstr = f"configured DNS server {nameserver}" if nameserver else "system resolver"
        if tlsatype:
            tlsastr = " ".join(tlsatype)
            tlsadesc = f"TLSA type {tlsastr}"
        else:
            tlsadesc = "all TLSA types"

        logger.debug(f"Looking up TLSA record in DNS using {nameserverstr}: {record} - {tlsadesc}")
        try:
            if nameserver:
                res = dns.resolver.Resolver(configure=False)
                res.nameservers = [nameserver]
            else:
                res = dns.resolver  # type: ignore[assignment]
            dnsresponse = res.query(record, "TLSA")
        except dns.resolver.NXDOMAIN:
            logger.debug(f"NXDOMAIN returned by {nameserverstr}, no TLSA records found in DNS for: {record}")
            return None
        except dns.resolver.NoAnswer:
            logger.error(f"Empty answer returned by {nameserverstr}. No TLSA records found in DNS for: {record}")  # noqa: TRY400
            return None
        except ValueError:
            logger.error(f"Error parsing DNS server '{nameserver}'. Only IP addresses and https URLs are supported.")  # noqa: TRY400
            sys.exit(1)
        except dns.exception.Timeout:
            logger.error(f"Timeout while waiting for {nameserverstr}. Error.")  # noqa: TRY400
            sys.exit(1)
        except Exception as E:  # noqa: BLE001
            logger.error(f"Exception {type(E)} received during DNS lookup: {E}")  # noqa: TRY400
            return None

        # loop over the responses
        result = []
        for reply in dnsresponse:
            replytype = f"{reply.usage} {reply.selector} {reply.mtype}"  # type: ignore[attr-defined]
            logger.debug(f"Found TLSA record type {replytype}")
            if not tlsatype or tlsastr == replytype:
                # add this record to the result to be returned
                result.append(binascii.hexlify(reply.cert).decode("ASCII"))  # type: ignore[attr-defined]

        if result:
            logger.debug(f"Returning {len(result)} TLSA records")
            return result
        logger.debug(f"{len(dnsresponse)} TLSA records found, but none of the type {tlsatype} were found")
        return None

    @classmethod
    def output_tlsa_record(  # noqa: PLR0913
        cls,
        *,
        derkey: bytes,
        domain: str,
        port: int,
        protocol: str,
        tlsatype: str,
        warning: bool = False,
    ) -> None:
        """Output the TLSA record for the given DER key, domain, port, protocol and tlsatype.

        Call ``self.generate_tlsa()`` and output the result formatted as a DNS record

        Args:
            derkey: The bytes representation the public key in DER format
            domain: The service domain name (like ``mail.example.com``)
            port: The service port (like ``443``)
            protocol: The service protocol (like ``tcp``)
            tlsatype: The TLSA type (like ``312``)
            warning: Set True to output at level ``WARNING`` (default ``INFO``)

        Returns:
            None
        """
        tlsarecord = f"_{port}._{protocol}.{domain}"
        tlsadata = cls.generate_tlsa_record(derkey, tlsatype)
        tlsastr = " ".join(tlsatype)
        if warning:
            logger.warning(f"{tlsarecord} TLSA {tlsastr} {tlsadata}")
        else:
            logger.info(f"{tlsarecord} TLSA {tlsastr} {tlsadata}")

    @classmethod
    def verify_tlsa_record(  # noqa: PLR0913
        cls,
        derkey: bytes,
        domain: str,
        port: int,
        protocol: str,
        tlsatype: str,
        nameserver: str = "",
    ) -> bool:
        """Check the TLSA records for the port/protocol/domain and DER key in the DNS.

        Output the info needed to fix things when missing records are found.

        Args:
            derkey: The bytes representation the public key in DER format
            domain: The service domain name (like ``mail.example.com``)
            port: The service port (like ``443``)
            protocol: The service protocol (like ``tcp``)
            tlsatype: The TLSA type (like ``312``)
            nameserver: The DNS server IP to use instead of system resolver (optional)

        Return:
            True if all is well, False if one or more problems are found
        """
        tlsarecord = f"_{port}._{protocol}.{domain}"
        tlsadata = cls.generate_tlsa_record(derkey, tlsatype)
        tlsastr = " ".join(map(str, tlsatype))

        # do the DNS lookup
        dns_reply = cls.lookup_tlsa_record(
            domain=domain,
            port=port,
            protocol=protocol,
            tlsatype=tlsatype,
            nameserver=nameserver,
        )

        # bail out early if we got nothing from DNS
        if dns_reply is None:
            logger.warning(
                f"No TLSA records for name {tlsarecord} of type {tlsastr} was found in "
                "DNS. This record needs to be added:"
            )
            cls.output_tlsa_record(
                derkey=derkey,
                domain=domain,
                port=port,
                protocol=protocol,
                tlsatype=tlsatype,
                warning=True,
            )
            return False

        # we have a response
        logger.debug(
            f"Received DNS response for TLSA type {tlsastr}: {len(dns_reply)} answers - "
            "looking for an answer matching the public key..."
        )
        for reply in dns_reply:
            if reply.upper() == tlsadata:
                logger.info(
                    f"TLSA record for name {tlsarecord} type {tlsastr} matching the local key found in DNS, good."
                )
                return True

        logger.warning(
            f"None of the TLSA records found in DNS for the name {tlsarecord} and "
            f"type {tlsatype} match the local key. This record needs to be added to the DNS:"
        )
        cls.output_tlsa_record(
            derkey=derkey,
            domain=domain,
            port=port,
            protocol=protocol,
            tlsatype=tlsatype,
            warning=True,
        )
        return False

    def show_tlsa(self) -> None:
        """The 'show tlsa' subcommand method, called for each domainset by ``self.grind()``.

        Returns:
            None
        """
        logger.info(
            f"- Showing TLSA records for keytype '{self.keytype}' for domain set: "
            "{self.domainset} port '{self.conf.tlsa_port}' protocol '{self.conf.tlsa_protocol}':"
        )
        for domain in self.domainset:
            for tlsatype in self.conf.tlsa_type_list:
                self.output_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf.tlsa_port,
                    protocol=self.conf.tlsa_protocol,
                    tlsatype=tlsatype,
                )

    def check_tlsa(self) -> None:
        """The 'check tlsa' subcommand method, called for each domainset by ``self.grind()``.

        Loops over the configured TLSA types and calls ``self.verify_tlsa_record()`` which
        does the heavy lifting.

        Returns:
            None
        """
        for domain in self.domainset:
            logger.debug(
                f"Checking DNS for TLSA records for {domain} port "
                "{self.conf.tlsa_port} protocol {self.conf.tlsa_protocol}:"
            )
            for tlsatype in self.conf.tlsa_type_list:
                result = self.verify_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf.tlsa_port,
                    protocol=self.conf.tlsa_protocol,
                    tlsatype=tlsatype,
                    nameserver=self.conf.name_server,
                )
                if not result and not self.error:
                    logger.debug("Problem discovered in check mode, setting self.error=True")
                    self.error = True
            logger.debug(
                f"Done checking DNS for TLSA records for {domain} port "
                f"{self.conf.tlsa_port} protocol {self.conf.tlsa_protocol}"
            )

    # CAA METHODS

    def show_caa(self) -> None:
        """The ``show caa`` subcommand method, called for each domainset by ``self.grind()``.

        Returns:
            None
        """
        # get acmeaccount from certgrinderd
        stdout = self.run_certgrinderd(stdin=b"", command=["show", "acmeaccount"])
        url: str = ""
        for line in stdout.decode().split("\n"):
            if line[:15] == "  Account URL: ":
                url = line[15:]
                break
        else:
            logger.error("certgrinderd did not return an acmeaccount")
            sys.exit(1)

        # output CAA records
        for domain in self.domainset:
            if domain[0] == "*":
                # wildcard certificates only support dns-01
                print(f'{domain} IN CAA 128 issuewild "letsencrypt.org; validationmethods=dns-01; accounturi={url}"')  # noqa: T201
                print(f'{domain} IN CAA 128 issue ";"')  # noqa: T201
            else:
                print(  # noqa: T201
                    f'{domain} IN CAA 128 issue "letsencrypt.org; '
                    f'validationmethods={self.conf.caa_validation_methods}; accounturi={url}"'
                )
                print(f'{domain} IN CAA 128 issuewild ";"')  # noqa: T201

    # MAIN METHODS

    def periodic(self) -> bool:
        """The periodic method performs periodic maintenance tasks.

        This method is called by the 'periodic' command, from cron or similar.
        It starts out by sleeping for a random period and then checks certificates and renews as needed.
        """
        if self.conf.periodic_sleep_minutes:
            sleep = random.randint(0, self.conf.periodic_sleep_minutes)  # noqa: S311
            logger.debug(f"Sleeping for {sleep} minutes before doing periodic...")
            time.sleep(sleep * 60)

        # check if we have a valid certificate for this domainset, get new cert if needed
        if not self.check_certificate() and not self.get_certificate():
            # unable to get new certificate
            logger.error(f"Failed getting a new certificate for domainset: {self.domainset}")
            return False

        # all good
        return True

    def show_paths(self) -> None:
        """The ``show paths`` subcommand method, called for each domainset by ``self.grind()``.

        Returns:
            None
        """
        msg = {True: "file found", False: "file not found"}
        logger.info(f"- Showing paths for keytype '{self.keytype}' for domain set: {self.domainset}")
        logger.info(f"Keypair path: {self.keypair_path} [{msg[self.keypair_path.exists()]}]")
        logger.info(f"CSR path: {self.csr_path} [{msg[self.csr_path.exists()]}]")
        logger.info(f"Certificate path: {self.certificate_path} [{msg[self.certificate_path.exists()]}]")
        logger.info(f"Chain path: {self.certificate_chain_path} [{msg[self.certificate_chain_path.exists()]}]")
        logger.info(f"Issuer certificate path: {self.issuer_path} [{msg[self.issuer_path.exists()]}]")
        logger.info(f"Key+chain concat path: {self.concat_path} [{msg[self.concat_path.exists()]}]")

    def check_connection(
        self,
        stdout: bytes | None = None,
    ) -> bool:
        """The ``check connection`` subcommand method.

        Args:
            stdout: The certgrinderd response to use instead of calling certgrinderd (optional)

        Returns:
            None
        """
        if stdout is None:
            # call certgrinderd ping command
            stdout = self.run_certgrinderd(stdin=b"", command=["ping"])

        if not stdout or stdout.decode() != "pong\n":
            logger.error(f"Did not get a pong response in stdout from certgrinderd, got '{stdout!r}' instead")
            self.error = True
            return False

        logger.info("Success! Got pong response from certgrinderd.")
        return True

    def get_filename(self, hostname: str) -> str:
        """Calculate the hostname string to be used for filenames.

        Files are named after the ascii idna representation of the first hostname
        in the list (which is also the CN in the subject of the CSR and certificate).

        Max filename length on some platforms is 255 bytes, but a hostname could be
        up to 253 bytes (RFC 1035 section 2.3.4), and we need some room for the usage
        and keytype and extension, so we only use the last 230 bytes of the ascii idna
        representation of the hostname for the filename, leaving 25 bytes for metadata.

        Args:
            hostname: The hostname to use

        Returns:
            The string to use in filenames
        """
        return hostname.encode("idna").decode("ascii")[-230:]

    def load_domainset(self, domainset: list[str], keytype: str) -> None:
        """Prepare paths and create/load private key.

        Args:
            domainset: The list of hostnames to load
            keytype: The keytype to use, "rsa" or "ecdsa".

        Returns:
            None
        """
        logger.debug(f"Loading domainset {domainset} for keytype {keytype}")

        # this is mostly here to make mypy happy
        if self.conf.path is None:
            logger.error("path is None")
            sys.exit(1)

        self.domainset = domainset
        self.keytype = keytype

        # get the hostname to use for filenames
        filename = self.get_filename(domainset[0])

        # keypair
        self.keypair_path = self.conf.path / f"{filename}-keypair.{keytype}.key"
        logger.debug(f"keypair path: {self.keypair_path}")

        # CSR
        self.csr_path = self.conf.path / f"{filename}-request.{keytype}.csr"
        logger.debug(f"CSR path: {self.csr_path}")

        # certificate chain
        self.certificate_chain_path = self.conf.path / f"{filename}-chain.{keytype}.crt"
        logger.debug(f"Certificate chain path: {self.certificate_chain_path}")

        # certificate only
        self.certificate_path = self.conf.path / f"{filename}-certificate.{keytype}.crt"
        logger.debug(f"certificate path: {self.certificate_path}")

        # issuer certificate
        self.issuer_path = self.conf.path / f"{filename}-issuer.{keytype}.crt"
        logger.debug(f"issuer path: {self.issuer_path}")

        # concat of privkey + chain
        self.concat_path = self.conf.path / f"{filename}-concat.{keytype}.pem"
        logger.debug(f"concat path: {self.concat_path}")

        # finally load or create the keypair
        if self.keypair_path.exists():
            # load private key
            self.keypair = self.load_keypair(self.keypair_path)
            logger.debug(f"Loaded {keytype} keypair from {self.keypair_path}")
        else:
            # create new private key
            self.keypair = self.generate_private_key(keytype=keytype)
            self.save_keypair(self.keypair, self.keypair_path)
            logger.debug(f"Created new {keytype} keypair, saved to {self.keypair_path}")

    def grind(self, args: argparse.Namespace) -> None:
        """Loop over enabled keytypes and domainsets in ``self.conf.domain_list`` and call args.method for each."""
        logger.debug(f"Certgrinder {__version__} running")

        if args.method == "check_connection":
            # we only need to do this once, and we don't need to load_domainset() first
            getattr(self, args.method)()
        else:
            # loop over keytypes
            for kcounter, keytype in enumerate(self.conf.key_type_list):
                if kcounter == 1 and args.method in ["show_caa"]:
                    # we dont need to see CAA records once per keytype
                    break
                # loop over domains
                for dcounter, domainset in enumerate(self.conf.domain_list):
                    logger.debug(
                        f"-- Processing keytype {keytype} ({kcounter} of "
                        f"{len(self.conf.key_type_list)} keytypes) for domainset "
                        f"{dcounter} of {len(self.conf.domain_list)}: {domainset.split(',')}"
                    )
                    # prepare paths and create/load private key
                    self.load_domainset(domainset=domainset.split(","), keytype=keytype)
                    # run the requested method
                    getattr(self, args.method)()

        # do we need to run post-renew hooks?
        if self.hook_needed:
            logger.info("At least one certificate was renewed, running post renew hooks...")
            self.run_post_renew_hooks()

        # are we running in check mode?
        if args.command == "check" and self.error:
            logger.error("Running in check mode and one or more errors were encountered, exit code 1")
            sys.exit(1)

        logger.debug("All done, exiting cleanly")
        sys.exit(0)


def get_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description=f"Certgrinder version {__version__}. See the manpage or ReadTheDocs for more info."
    )
    # add topmost subparser for main command
    subparsers = parser.add_subparsers(help="Command (required)", dest="command", required=True)

    # "check" command
    check_parser = subparsers.add_parser(
        "check",
        help='Use the "check" command to check certificates and TLSA records. '
        "Returns exit code 0 if all is well, and 1 if something needs attention.",
    )
    check_subparsers = check_parser.add_subparsers(
        help="Specify what to check using one of the available check sub-commands.",
        dest="subcommand",
        required=True,
    )

    # "check certificate" subcommand
    check_certificate_parser = check_subparsers.add_parser(
        "certificate",
        help="Tell certgrinder to check certificate validity for all configured domainsets. "
        "Returns exit code 1 if any problem is found, exit code 0 if all is well.",
    )
    check_certificate_parser.set_defaults(method="check_certificate")

    # "check connection" subcommand
    check_connection_parser = check_subparsers.add_parser(
        "connection",
        help="Tell certgrinder to check the connection to the certgrinderd server by calling "
        "the certgrinderd 'ping' command which should return the string 'pong' if all is well.",
    )
    check_connection_parser.set_defaults(method="check_connection")

    # "check tlsa" subcommand
    check_tlsa_parser = check_subparsers.add_parser(
        "tlsa",
        help="Tell certgrinder to lookup TLSA records for the given port and protocol in the "
        "DNS and compare with what we have locally, for example: 'certgrinder check tlsa 853 tcp'",
    )
    check_tlsa_parser.set_defaults(method="check_tlsa")
    check_tlsa_parser.add_argument("tlsa-port", type=int, help="The port of the service, for example 443")
    check_tlsa_parser.add_argument("tlsa-protocol", help="The protocol of the service, for example tcp")

    # "get" command
    get_parser = subparsers.add_parser("get", help='Use the "get" command to get certificates')
    get_subparsers = get_parser.add_subparsers(
        help="Specify what to get using one of the available get sub-commands",
        dest="subcommand",
        required=True,
    )

    # "get certificate" subcommand
    get_cert_parser = get_subparsers.add_parser(
        "certificate",
        help="Tell certgrinder to get new certificate(s), regardless of their current state. "
        "Rarely needed, use 'periodic' command instead.",
    )
    get_cert_parser.set_defaults(method="get_certificate")

    # "help" command
    subparsers.add_parser("help", help='The "help" command just outputs the usage help')

    # "periodic" command
    periodic_parser = subparsers.add_parser(
        "periodic",
        help='The "periodic" command checks certificates and renews them as needed. '
        "Meant to be run from cron or similar daily.",
    )
    periodic_parser.set_defaults(method="periodic")

    # "show" command
    show_parser = subparsers.add_parser(
        "show",
        help='Use the "show" command to show certificates, TLSA records, SPKI pins or configuration.',
    )
    show_subparsers = show_parser.add_subparsers(
        help="Specify what to show using one of the available show sub-commands",
        dest="subcommand",
        required=True,
    )

    # "show certificate" subcommand
    show_certificate_parser = show_subparsers.add_parser(
        "certificate", help="Tell certgrinder to output information about certificates."
    )
    show_certificate_parser.set_defaults(method="show_certificate")

    # "show configuration" subcommand
    show_subparsers.add_parser("configuration", help="Tell certgrinder to output the current configuration")

    # "show paths" subcommand
    show_paths_parser = show_subparsers.add_parser("paths", help="Tell certgrinder to output the paths used")
    show_paths_parser.set_defaults(method="show_paths")

    # "show spki" subcommand
    show_spki_parser = show_subparsers.add_parser(
        "spki",
        help="Tell certgrinder to generate and print the pin-sha256 spki pins for the public keys it manages.",
    )
    show_spki_parser.set_defaults(method="show_spki")

    # "show tlsa" subcommand
    show_tlsa_parser = show_subparsers.add_parser(
        "tlsa",
        help="Use the 'show tlsa' sub-command to tell certgrinder to generate and print "
        "TLSA records for the given service, for example: 'certgrinder show tlsa 443 tcp'",
    )
    show_tlsa_parser.set_defaults(method="show_tlsa")
    show_tlsa_parser.add_argument("tlsa-port", type=int, help="The port of the service, for example 443")
    show_tlsa_parser.add_argument("tlsa-protocol", help="The protocol of the service, for example tcp")

    # "show caa" subcommand
    show_caa_parser = show_subparsers.add_parser(
        "caa",
        help="Use the 'show caa' sub-command to tell certgrinder to output a CAA record "
        "suitable for the specified domainset(s).",
    )
    show_caa_parser.set_defaults(method="show_caa")

    # "version" command
    subparsers.add_parser("version", help='The "version" command just outputs the version of Certgrinder')

    # optional arguments
    parser.add_argument(
        "--certgrinderd",
        dest="certgrinderd",
        help="The command to reach the certgrinderd server, will get the input (CSR or cert "
        "chain) on stdin. Usually something like 'ssh certgrinderd@server -T'",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--caa-validation-methods",
        required=False,
        help="The ACME validation methods to include when outputting CAA records. Default: dns-01,http-01",
        dest="caa-validation-methods",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cert-renew-threshold-days",
        dest="cert-renew-threshold-days",
        type=int,
        help="A certificate is renewed when it has less than this many days of lifetime left. Default: `30`",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config-file",
        help="The path to the certgrinder.yml config file to use",
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
        "-D",
        "--domain-list",
        action="append",
        dest="domain-list",
        help="Comma separated list of domains for a certificate. Can be specified multiple times.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--invalid-ca-cn-list",
        action="append",
        dest="invalid-ca-cn-list",
        help="The CommonName of an issuer (CA intermediate) to consider invalid. Can be specified multiple times.",
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
        "-k",
        "--key-type-list",
        action="append",
        dest="key-type-list",
        choices=["rsa", "ecdsa"],
        help="The keytypes to enable. Valid values are 'rsa' and 'ecdsa'. "
        "Can be specified multiple times. Defaults to both rsa and ecdsa.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-n",
        "--name-server",
        dest="name-server",
        help="Tell certgrinder to use this DNS server IP to lookup TLSA records. "
        "Only relevant with -c / --checktlsa. Only v4/v6 IPs, no hostnames.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--now",
        dest="periodic-sleep-minutes",
        action="store_const",
        const=0,
        help="Run periodic command without delay. Equal to setting --periodic-sleep-minutes 0.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--path",
        dest="path",
        help="Tell certgrinder to use the specified directory for keys, CSRs and certificates. "
        "The directory must exist and be writeable by the user running certgrinder.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--periodic-sleep-minutes",
        dest="periodic-sleep-minutes",
        type=int,
        help="Tell certgrinder to sleep for a random number of minutes between 0 and this "
        "number before doing anything when the periodic command is used. Set to 0 to "
        "disable sleeping.",
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
        "--post-renew-hooks",
        action="append",
        dest="post-renew-hooks",
        help="The list of commands to run after one or more certificates are renewed. Most "
        "such commands will need root access to run, remember to prefix the command with "
        "'sudo' as needed. Can be specified multiple times. Default: `None`",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--post-renew-hooks-dir",
        dest="post-renew-hooks-dir",
        help="Path to a folder containing executables to run after one or more certificates "
        "are renewed. These will execute under the regular certgrinder user uid, "
        "so make sure to use sudo/doas in scripts or suid executables as needed. Default: `None`",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--post-renew-hooks-dir-runner",
        dest="post-renew-hooks-dir-runner",
        help="Path to an executable like sudo to be used to run each of the executables "
        "in the post renew hooks dir. Default: `None`",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="log-level",
        const="WARNING",
        help="Quiet mode. No output at all if there is nothing to do, and no errors "
        "are encountered. Equal to setting --log-level=WARNING.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-s",
        "--staging",
        dest="staging",
        action="store_true",
        help="Staging mode. Sets --acme-server-url "
        "https://acme-staging-v02.api.letsencrypt.org/directory "
        "and --invalid-ca-cn-list empty. Use this while playing around to "
        "avoid hitting rate limits!",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--syslog-facility",
        dest="syslog-facility",
        help="The syslog facility to use. Set this and syslog-socket to enable logging to syslog.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--syslog-socket",
        dest="syslog-socket",
        help="The syslog socket to connect to. Set this and syslog-facility to enable logging to syslog.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tlsa-port",
        dest="tlsa-port",
        type=int,
        help="The service port number (like 443) for TLSA operations.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tlsa-protocol",
        dest="tlsa-protocol",
        help="The service protocol (like tcp) for TLSA operations.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tlsa-type-list",
        action="append",
        dest="tlsa-type-list",
        choices=["310", "311", "312"],
        help="Enables a TLSA type for TLSA operations. Can be specified multiple times.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        action="store_true",
        help="Show version and exit.",
        default=argparse.SUPPRESS,
    )
    return parser


def parse_args(
    mockargs: list[str] | None = None,
) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Create an argparse monster and parse mockargs or sys.argv[1:]."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: list[str] | None = None) -> None:
    """Initialise script and ``Certgrinder()`` object, then call ``certgrinder.grind()``.

    Parse command-line arguments, read config file if needed, configure logging,
    and then call ``certgrinder.grind()`` method.
    """
    # get parser and parse args
    parser, args = parse_args(mockargs)

    # handle a couple of special cases before reading config
    if args.command == "version" or hasattr(args, "version"):
        print(f"Certgrinder version {__version__}")  # noqa: T201
        sys.exit(0)
    if args.command == "help":
        parser.print_help()
        sys.exit(0)

    # read and parse the config file
    if hasattr(args, "config-file"):
        with Path(getattr(args, "config-file")).open() as f:
            try:
                config = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out.")
                sys.exit(1)
    else:
        # we have no config file
        config = {}

    # update file config (if any) with command-line arguments,
    # so they take precedence over config file configuration
    config.update(vars(args))

    # remove command, subcommand, and method from config (part of argparse internals)
    # also remove config-file
    for key in ["command", "subcommand", "method", "config-file"]:
        if key in config:
            del config[key]

    # configure certgrinder
    certgrinder = Certgrinder()
    certgrinder.configure(userconfig=config)

    # if the command is "show configuration" just output certgrinder.conf and exit now
    if args.command == "show" and args.subcommand == "configuration":
        logger.info("Current certgrinder configuration:")
        pprint(certgrinder.conf)  # noqa: T203
        sys.exit(0)

    # call main method
    certgrinder.grind(args)


def init() -> None:
    """This is here just as a testable way of calling main()."""
    if __name__ == "__main__":
        with PidFile("certgrinder"):
            main()


init()
