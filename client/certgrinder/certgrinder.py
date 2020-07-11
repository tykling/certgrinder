#!/usr/bin/env python
"""Certgrinder v0.13.2 module.

See https://certgrinder.readthedocs.io/en/latest/certgrinder.html
and https://github.com/tykling/certgrinder for more.
"""
import argparse
import base64
import binascii
import hashlib
import logging
import logging.handlers
import os
import random
import subprocess
import sys
import tempfile
import time
import typing
from datetime import datetime
from pprint import pprint

import cryptography.x509
import dns.resolver  # type: ignore
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.backends.openssl import x509  # type: ignore

logger = logging.getLogger("certgrinder.%s" % __name__)
__version__ = "0.13.2"


class Certgrinder:
    """The Certgrinder client class."""

    # save version as a class attribute
    __version__ = __version__

    def __init__(self) -> None:
        """Define the default config."""
        self.conf: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]] = {
            "certgrinderd": "",
            "cert-renew-threshold-days": 30,
            "domain-list": [],
            "invalid-ca-cn-list": [
                "Fake LE Intermediate X1",
                "Fake LE Intermediate X2",
            ],
            "log-level": "INFO",
            "name-server": "",
            "path": "",
            "periodic-sleep-minutes": 60,
            "pid-dir": "/tmp",
            "post-renew-hooks": [],
            "staging": False,
            "syslog-facility": "",
            "syslog-socket": "",
            "tlsa-port": "",
            "tlsa-protocol": "",
            "tlsa-type-list": ["310", "311", "312"],
        }

        # current domainset
        self.domainset: typing.List[str] = []

        # paths for current certificate and keys
        self.keypair_path: str = ""
        self.csr_path: str = ""
        self.certificate_path: str = ""
        self.certificate_chain_path: str = ""
        self.intermediate_path: str = ""
        self.concat_path: str = ""

        # this is set to True if an error occurs
        self.error: bool = False

        # this is set to True if we need to run a post renew hook
        self.hook_needed: bool = False

    def configure(
        self,
        userconfig: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]],
    ) -> None:
        """Merge and check configuration and configure logging.

        Merge the supplied userconfig dict with the default config,
        checks for missing required settings, and configures logging and syslog.

        Args:
            userconfig: dict of the config to be merged with the default config

        Returns:
            None
        """
        # merge default config with userconfig
        self.conf.update(userconfig)

        # define the log format used for stdout depending on the requested loglevel
        if self.conf["log-level"] == "DEBUG":
            console_logformat = "%(asctime)s certgrinder %(levelname)s Certgrinder.%(funcName)s():%(lineno)i:  %(message)s"
        else:
            console_logformat = "%(asctime)s certgrinder %(levelname)s: %(message)s"

        # configure the log format used for console
        logging.basicConfig(
            level=getattr(logging, str(self.conf["log-level"])),
            format=console_logformat,
            datefmt="%Y-%m-%d %H:%M:%S %z",
        )

        # check if we have a domain-list
        if not self.conf["domain-list"]:
            logger.error(
                "No domain-list(s) configured. Specify --domain-list example.com[,www.example.com] (once per certificate) or define domain-list: in the config file."
            )
            sys.exit(1)

        # check if we have a certgrinderd command
        if not self.conf["certgrinderd"]:
            logger.error(
                "No certgrinderd command configured. Specify --certgrinderd or define certgrinderd: in the config file."
            )
            sys.exit(1)

        # check if we have a path
        if not self.conf["path"]:
            logger.error(
                f"No configured path. Specify --path or define path: in the config file."
            )
            sys.exit(1)

        # check if configured path exists
        if not os.path.exists(str(self.conf["path"])):
            logger.error(f"Configured path {self.conf['path']} does not exist")
            sys.exit(1)

        # check if configured path is writable
        try:
            with tempfile.TemporaryFile(dir=str(self.conf["path"])) as _:
                pass
        except PermissionError:
            logger.error(
                "Permission error while accessing configured path {self.conf['path']}"
            )
            sys.exit(1)

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
        else:
            logger.debug("Not configuring syslog")

        # is this staging mode?
        if self.conf["staging"]:
            logger.debug(
                "Staging mode enabled. Setting acme-server-url to 'https://acme-staging-v02.api.letsencrypt.org/directory' and invalid-ca-cn-list to an empty list."
            )
            self.conf[
                "acme-server-url"
            ] = "https://acme-staging-v02.api.letsencrypt.org/directory"
            self.conf["invalid-ca-cn-list"] = []

        logger.debug(
            f"Certgrinder {__version__} configured OK - running with config: {self.conf}"
        )

    # RSA KEY METHODS

    @staticmethod
    def load_keypair(
        path: str
    ) -> typing.Union[openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey]:
        """Load keypair bytes from disk, load key and return the object.

        Fixes keypair permissions to 640 if they are not 640.

        Args:
            path: The path to load the keypair from

        Returns:
            The keypair object
        """
        # check permissions for self.keypair_path and fix to 640 if needed
        if oct(os.stat(path).st_mode)[4:] != "0640":
            logger.warning(
                f"Keypair {path} has incorrect permissions, fixing to 0640..."
            )
            os.chmod(path, 0o640)

        # read keypair
        keypair_bytes = open(path, "rb").read()

        # parse and return keypair
        return primitives.serialization.load_pem_private_key(
            keypair_bytes, password=None, backend=default_backend()
        )

    @staticmethod
    def generate_private_key(
        keytype: str = "rsa"
    ) -> typing.Union[openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey]:
        """Generate and returns a private key.

        Args:
            keytype: "rsa" for RSA key, "ed25519" for EC

        Returns:
            The keypair object

        Raises:
            ValueError: For unsupported keytypes
        """
        if keytype == "rsa":
            return primitives.asymmetric.rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
        elif keytype == "ed25519":
            return primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Unsupported keytype")

    @staticmethod
    def save_keypair(
        keypair: typing.Union[
            openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey
        ],
        path: str,
    ) -> None:
        """Save keypair to disk.

        Args:
            keypair: The keypair to save
            path: The path to save the keypair in

        Returns:
            None

        Raises:
            ValueError: For unsupported keytypes
        """
        if isinstance(keypair, openssl.rsa._RSAPrivateKey):
            keyformat = primitives.serialization.PrivateFormat.TraditionalOpenSSL
        elif isinstance(keypair, openssl.ed25519.Ed25519PrivateKey):
            keyformat = primitives.serialization.PrivateFormat.PKCS8
        else:
            raise ValueError("Unsupported keytype")

        with open(path, "wb") as f:
            f.write(
                keypair.private_bytes(
                    encoding=primitives.serialization.Encoding.PEM,
                    format=keyformat,
                    encryption_algorithm=primitives.serialization.NoEncryption(),
                )
            )
        os.chmod(path, 0o640)

    @staticmethod
    def get_der_pubkey(
        keypair: typing.Union[
            openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey
        ]
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
        keypair: typing.Union[
            openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey
        ],
        domains: typing.List[str],
    ) -> x509._CertificateSigningRequest:
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
        x509_name_list: typing.List[cryptography.x509.GeneralName] = []
        for domain in domains:
            domain = domain.encode("idna").decode("utf-8")
            logger.debug("Adding %s to CSR..." % domain)
            x509_name_list.append(cryptography.x509.DNSName(domain))

        # build the CSR
        csr = (
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
                # TODO: should SubjectAltName be critical?
                critical=False,
            )
            .sign(keypair, primitives.hashes.SHA256(), default_backend())
        )
        return csr

    @staticmethod
    def save_csr(csr: x509._CertificateSigningRequest, path: str) -> None:
        """Save the PEM version of the CSR to the path.

        chmods the file 644 after writing.

        Args:
            csr: The CSR to be saved
            path: The path to save the CSR to

        Returns:
            None
        """
        with open(path, "wb") as f:
            f.write(csr.public_bytes(primitives.serialization.Encoding.PEM))
        os.chmod(path, 0o644)

    # CERTIFICATE METHODS

    @staticmethod
    def load_certificate(path: str) -> cryptography.x509.Certificate:
        """Reads PEM certificate data from the path and returns the object.

        Args:
            path: The path to read the certificate from

        Returns:
            The certificate object
        """
        pem_data = open(path, "rb").read()
        return cryptography.x509.load_pem_x509_certificate(pem_data, default_backend())

    @staticmethod
    def check_certificate_issuer(
        certificate: cryptography.x509.Certificate, invalid_ca_cn_list: typing.List[str]
    ) -> bool:
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
            if (
                x.oid == cryptography.x509.oid.NameOID.COMMON_NAME
                and x.value in invalid_ca_cn_list
            ):
                logger.debug(
                    f"This certificate was issued by a CA CN ({x.value}) in invalid_ca_cn_list ({invalid_ca_cn_list}), check_certificate_issuer() returning False"
                )
                return False

        # all good
        return True

    @staticmethod
    def check_certificate_expiry(
        certificate: cryptography.x509.Certificate, threshold_days: int
    ) -> bool:
        """Check the remaining validity of the certificate.

        Args:
            certificate: The certificate to check
            threshold_days: The lowest number of remaining days of validity that is considered valid

        Returns:
            True if remaining certificate lifetime is >= threshold_days, False if not
        """
        expiredelta = certificate.not_valid_after - datetime.now()
        if expiredelta.days < threshold_days:
            return False
        else:
            return True

    @staticmethod
    def check_certificate_public_key(
        certificate: cryptography.x509.Certificate,
        public_key: typing.Union[
            openssl.rsa._RSAPublicKey, openssl.ed25519.Ed25519PublicKey
        ],
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
    def check_certificate_subject(
        certificate: cryptography.x509.Certificate, subject: str
    ) -> bool:
        """Make sure the certificate has the specified subject.

        Args:
            certificate: The certificate to check
            subject: The subject to expect

        Returns:
            True if the subject matches the cert, False if not
        """
        return str(certificate.subject) == str(subject)

    @staticmethod
    def check_certificate_san_names(
        certificate: cryptography.x509.Certificate, san_names: typing.List[str]
    ) -> bool:
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
        assert isinstance(cert_san, cryptography.x509.SubjectAlternativeName)
        cert_san_names = cert_san.get_values_for_type(cryptography.x509.DNSName)

        # if there is a difference between the sets we want to return False
        return not bool(set(cert_san_names).symmetric_difference(san_names))

    @classmethod
    def check_certificate_validity(
        cls,
        certificate: cryptography.x509.Certificate,
        invalid_ca_cn_list: typing.List[str],
        threshold_days: int,
        san_names: typing.List[str],
        public_key: typing.Optional[
            typing.Union[openssl.rsa._RSAPublicKey, openssl.ed25519.Ed25519PublicKey]
        ] = None,
        subject: str = "",
    ) -> bool:
        """Perform a few sanity checks of the certificate.

        - Check that the issuer is valid
        - Check that the certificate expiry is not exceeded
        - Check that the public key is correct
        - Check that the subject is correct
        - Check that the SubjectAltName data is correct

        Args:
            certificate: The certificate to check
            invalid_ca_cn_list: A list of CA CommonNames to consider invalid
            threshold_days: The minimum number of remaining days lifetime to considered valid.
            san_names: A list of domain names to expect in SubjectAltName of the certificate.
            keypair: The keypair the certificate is for.

        Returns:
            False if a problem is found, True if all is well.
        """
        if not cls.check_certificate_issuer(certificate, invalid_ca_cn_list):
            logger.error(
                f"Certificate is self-signed or the issuer {certificate.issuer} CN is on our list of invalid CAs: {invalid_ca_cn_list}."
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
            logger.error("Certificate SAN name list is different from the expected")
            return False
        logger.debug("Certificate is OK, returning True")
        return True

    @staticmethod
    def save_certificate(
        certificate: cryptography.x509.Certificate,
        path: str,
        intermediate: typing.Optional[cryptography.x509.Certificate] = None,
    ) -> None:
        """Save the PEM certificate to the path, optionally with an intermediate.

        Args:
            certificate: The certificate to save
            path: The path to save the certificate in
            intermediate: The intermediate to write after the certificate (if any)

        Returns:
            None
        """
        with open(path, "wb") as f:
            f.write(certificate.public_bytes(primitives.serialization.Encoding.PEM))
            if intermediate:
                f.write(
                    intermediate.public_bytes(primitives.serialization.Encoding.PEM)
                )
        os.chmod(path, 0o644)

    @classmethod
    def save_concat_certkey(
        cls,
        keypair: typing.Union[
            openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey
        ],
        certificate: cryptography.x509.Certificate,
        intermediate: cryptography.x509.Certificate,
        path: str,
    ) -> None:
        """Create a single file with the private key, the cert and the intermediate, in that order.

        Args:
            keypair: The keypair to save in the concat file
            certificate: The certificate to save in the concat file
            intermediate: The intermediate to save in the concat file
            path: The path to save the concat file in

        Returns:
            None
        """
        cls.save_keypair(keypair, path)
        with open(path, "ab") as f:
            f.write(certificate.public_bytes(primitives.serialization.Encoding.PEM))
            f.write(intermediate.public_bytes(primitives.serialization.Encoding.PEM))
        os.chmod(path, 0o640)

    def get_certgrinderd_command(self) -> typing.List[str]:
        """Return the certgrinderd command to run.

        Adds ``--log-level`` with the current ``self.conf["log-level"]``.

        Returns:
            A list of the elements which make up the ``certgrinderd`` command
        """
        # put the command together
        command = str(self.conf["certgrinderd"])
        commandlist = [str(x) for x in command.split(" ")]

        # pass the certgrinder log-level to certgrinderd
        commandlist.append("--log-level")
        commandlist.append(str(self.conf["log-level"]))

        # pass the acme-server-url if we have one
        if "acme-server-url" in self.conf:
            commandlist.append("--acme-server-url")
            commandlist.append(str(self.conf["acme-server-url"]))

        # all good
        return commandlist

    def run_certgrinderd(
        self, csr: x509._CertificateSigningRequest
    ) -> typing.Optional[bytes]:
        """Run the configured ``self.conf["certgrinderd"]`` command with the CSR on stdin.

        Args:
            csr: The CSR to pass to the certgrinderd command

        Returns:
            The bytes representing the stdout from the subprocess call
        """
        commandlist = self.get_certgrinderd_command()
        logger.debug("Running certgrinderd command: %s" % commandlist)
        p = subprocess.Popen(
            commandlist,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # send the CSR to stdin and save stdout (the cert chain) + stderr (the certgrinderd logging)
        certgrinderd_stdout, certgrinderd_stderr = p.communicate(
            input=csr.public_bytes(primitives.serialization.Encoding.PEM)
        )

        # output certgrinderd_stderr (which contains all the logging from certgrinderd) to sys.stderr
        print(certgrinderd_stderr.strip().decode("utf-8"), sep="\n", file=sys.stderr)
        return certgrinderd_stdout

    def parse_certgrinderd_output(
        self, certgrinderd_stdout: bytes, csr: x509._CertificateSigningRequest
    ) -> typing.Optional[
        typing.Tuple[cryptography.x509.Certificate, cryptography.x509.Certificate]
    ]:
        """Split output chain into cert and intermediate.

        Args:
            certgrinderd_stdout: The bytes of the stdout from the certgrinderd call
            csr: The CSR this certificate was issued from

        Returns:
            A tuple of certificate, intermediate if the certificate chain is valid, None otherwise
        """
        # decode stdout as ASCII and split into lines
        chain_list = certgrinderd_stdout.decode("ASCII").split("\n")

        # do we have something resembling a PEM cert?
        if "-----BEGIN CERTIFICATE-----" not in chain_list:
            logger.error(
                "The Certgrinder server did not return a valid PEM formatted certificate."
            )
            logger.debug("This is stdout from the certgrinderd call:")
            logger.debug(certgrinderd_stdout.strip().decode("ASCII"))
            # we dont have a valid certificate
            return None

        # split chain in cert and intermediate
        cert_end_index = chain_list.index("-----END CERTIFICATE-----")
        certificate_bytes = "\n".join(chain_list[0 : cert_end_index + 1]).encode(
            "ASCII"
        )
        intermediate_bytes = "\n".join(chain_list[cert_end_index + 1 :]).encode("ASCII")

        # parse certificate
        try:
            certificate = cryptography.x509.load_pem_x509_certificate(
                certificate_bytes, default_backend()
            )
        except Exception:
            logger.error(
                "The Certgrinder server did not return a valid PEM formatted certificate."
            )
            logger.debug("This is stdout from the certgrinderd call:")
            logger.debug(certgrinderd_stdout.strip().decode("ASCII"))
            # we dont have a valid certificate
            return None

        # parse intermediate
        try:
            intermediate = cryptography.x509.load_pem_x509_certificate(
                intermediate_bytes, default_backend()
            )
        except Exception:
            logger.error(
                "The Certgrinder server did not return a valid PEM formatted intermediate."
            )
            logger.debug("This is stdout from the certgrinderd call:")
            logger.debug(certgrinderd_stdout.strip().decode("ASCII"))
            # we dont have a valid intermediate
            return None

        # keep mypy happy inspite of the mixed type self.conf dict
        assert isinstance(self.conf["invalid-ca-cn-list"], list)
        assert isinstance(self.conf["cert-renew-threshold-days"], int)
        # a few sanity checks of the certificate seems like a good idea
        valid = self.check_certificate_validity(
            certificate=certificate,
            invalid_ca_cn_list=[]
            if self.conf["staging"]
            else [str(x) for x in self.conf["invalid-ca-cn-list"]],
            threshold_days=self.conf["cert-renew-threshold-days"],
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
        return certificate, intermediate

    def get_certificate(
        self,
        csr: typing.Optional[x509._CertificateSigningRequest] = None,
        stdout: typing.Optional[bytes] = None,
    ) -> bool:
        """Get a new certificate for self.domainset.

        This methods gets a new certificate regardless of the status of any
        existing certificate. It is called by ``self.periodic()`` as needed.
        It can also be called by the ``get certificate`` subcommand.

        Args:
            csr: The CSR to use instead of generating one
            stdout: The stdout bytes to use instead of calling self.run_certgrinder(csr)

        Returns:
            False something goes wrong, True if all is well
        """
        logger.info(f"Getting new certificate for domainset {self.domainset} ...")
        if not csr:
            # generate new CSR
            csr = self.generate_csr(self.keypair, self.domainset)
        self.save_csr(csr, self.csr_path)
        logger.debug(
            f"Wrote {len(csr.public_bytes(primitives.serialization.Encoding.PEM))} bytes CSR to path {self.csr_path}"
        )

        if not stdout:
            # get certificate
            stdout = self.run_certgrinderd(csr)
        if not stdout:
            logger.error("Did not get any output from certgrinderd")
            return False
        result = self.parse_certgrinderd_output(stdout, csr)
        if result:
            certificate, intermediate = result
        else:
            logger.error("Did not get a certificate :(")
            return False

        logger.info(
            f"Success! Got {len(certificate.public_bytes(primitives.serialization.Encoding.PEM))} bytes certificate and {len(intermediate.public_bytes(primitives.serialization.Encoding.PEM))} bytes intermediate from certgrinderd"
        )

        # save cert, chain and concat
        self.save_certificate(certificate, self.certificate_path)
        self.save_certificate(certificate, self.certificate_chain_path, intermediate)
        self.save_concat_certkey(
            self.keypair, certificate, intermediate, self.concat_path
        )

        # all done
        self.hook_needed = True
        logger.debug(
            f"Saved new certificate to files {self.certificate_chain_path}, {self.certificate_path}, and {self.concat_path}"
        )
        return True

    def check_certificate(
        self,
        certificate: typing.Optional[cryptography.x509.Certificate] = None,
        public_key: typing.Optional[
            typing.Union[openssl.rsa._RSAPublicKey, openssl.ed25519.Ed25519PublicKey]
        ] = None,
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
            if os.path.exists(self.certificate_chain_path):
                certificate = self.load_certificate(self.certificate_chain_path)
            else:
                logger.error(f"Certificate {self.certificate_chain_path} not found")
                self.error = True
                return False

        # keep mypy happy inspite of the mixed type self.conf dict
        assert isinstance(self.conf["invalid-ca-cn-list"], list)
        assert isinstance(self.conf["cert-renew-threshold-days"], int)
        # check cert
        valid = self.check_certificate_validity(
            certificate=certificate,
            invalid_ca_cn_list=[]
            if self.conf["staging"]
            else [str(x) for x in self.conf["invalid-ca-cn-list"]],
            threshold_days=self.conf["cert-renew-threshold-days"],
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
        if not os.path.exists(self.certificate_path):
            logger.error(f"Certificate {self.certificate_path} not found")
            return
        certificate = self.load_certificate(self.certificate_path)
        logger.info(f"- Showing certificate for domain set: {self.domainset}")
        logger.info(f"Certificate keypair path: {self.keypair_path}")
        logger.info(f"Certificate chain path: {self.certificate_chain_path}")
        logger.info(f"Certificate path: {self.certificate_path}")
        logger.info(f"Certificate serial: {certificate.serial_number}")
        logger.info(f"Certificate subject: {certificate.subject}")
        logger.info(f"Certificate issuer: {certificate.issuer}")
        san = certificate.extensions.get_extension_for_oid(
            cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert isinstance(san.value, cryptography.x509.SubjectAlternativeName)
        logger.info(
            f"Certificate SAN: {san.value.get_values_for_type(cryptography.x509.DNSName)}"
        )

    # POST RENEW HOOK METHOD

    def run_post_renew_hooks(self) -> bool:
        """Loops over configured post_renew_hooks and runs them.

        If the hook needs sudo or doas or similar that must be included in the command.

        Returns:
            None
        """
        if "post-renew-hooks" not in self.conf or not self.conf["post-renew-hooks"]:
            logger.debug("no post-renew-hooks found in config, not doing anything")
            return True

        # loop over and run hooks
        assert isinstance(self.conf["post-renew-hooks"], list)
        for hook in self.conf["post-renew-hooks"]:
            logger.debug(f"Running post renew hook: {hook}")
            p = subprocess.Popen(hook.split(" "))
            exitcode = p.wait()
            if exitcode != 0:
                logger.error(
                    f"Got exit code {exitcode} when running post_renew_hook {hook}"
                )
            else:
                logger.debug("Post renew hook %s ended with exit code 0, good." % hook)

        # all done
        return True

    # SPKI METHODS

    @staticmethod
    def generate_spki(derkey: bytes) -> str:
        """Generate and return a pin-sha256 spki hpkp style pin for the provided public key.

        OpenSSL equivalent command is:
            openssl x509 -in example.com.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64

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
        logger.debug(
            f"Generated SPKI pin-sha256 for public key for domainset {self.domainset}:"
        )
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
        elif tlsatype == "311":
            # Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record
            return hashlib.sha256(derkey).hexdigest().upper()
        elif tlsatype == "312":
            # Generate DANE-EE Publickey SHA512 (3 1 2) TLSA Record
            return hashlib.sha512(derkey).hexdigest().upper()
        else:
            raise ValueError(f"Unsupported TLSA type: {tlsatype}")

    @staticmethod
    def lookup_tlsa_record(
        domain: str,
        port: int,
        protocol: str,
        tlsatype: typing.Optional[str] = None,
        nameserver: str = "",
    ) -> typing.Optional[typing.List[str]]:
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
        nameserverstr = (
            f"configured DNS server {nameserver}" if nameserver else "system resolver"
        )
        if tlsatype:
            tlsastr = " ".join(tlsatype)
            tlsadesc = f"TLSA type {tlsastr}"
        else:
            tlsadesc = "all TLSA types"

        logger.debug(
            f"Looking up TLSA record in DNS using {nameserverstr}: {record} - {tlsadesc}"
        )
        try:
            if nameserver:
                res = dns.resolver.Resolver(configure=False)
                res.nameservers = [nameserver]
            else:
                res = dns.resolver
            dnsresponse = res.query(record, "TLSA")
        except dns.resolver.NXDOMAIN:
            logger.debug(
                f"NXDOMAIN returned by {nameserverstr}, no TLSA records found in DNS for: {record}"
            )
            return None
        except dns.resolver.NoAnswer:
            logger.error(
                f"Empty answer returned by {nameserverstr}. No TLSA records found in DNS for: {record}"
            )
            return None
        except dns.exception.SyntaxError:
            logger.error(
                f"Error parsing DNS server IP '{nameserver}'. Only IP addresses are supported."
            )
            sys.exit(1)
        except dns.exception.Timeout:
            logger.error(f"Timeout while waiting for {nameserverstr}. Error.")
            sys.exit(1)
        except Exception as E:
            logger.error(f"Exception received during DNS lookup: {E}")
            return None

        # loop over the responses
        result = []
        for reply in dnsresponse:
            replytype = "%s %s %s" % (reply.usage, reply.selector, reply.mtype)
            logger.debug("Found TLSA record type %s" % replytype)
            if not tlsatype or tlsastr == replytype:
                # add this record to the result to be returned
                result.append(binascii.hexlify(reply.cert).decode("ASCII"))

        if result:
            logger.debug(f"Returning {len(result)} TLSA records")
            return result
        else:
            logger.debug(
                f"{len(dnsresponse)} TLSA records found, but none of the type {tlsatype} were found"
            )
            return None

    @classmethod
    def output_tlsa_record(
        cls,
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
    def verify_tlsa_record(
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
                f"No TLSA records for name {tlsarecord} of type {tlsastr} was found in DNS. This record needs to be added:"
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
            f"Received DNS response for TLSA type {tlsastr}: {len(dns_reply)} answers - looking for an answer matching the public key..."
        )
        for reply in dns_reply:
            if reply.upper() == tlsadata:
                logger.info(
                    f"TLSA record for name {tlsarecord} type {tlsastr} matching the local key found in DNS, good."
                )
                return True

        logger.warning(
            f"None of the TLSA records found in DNS for the name {tlsarecord} and type {tlsatype} match the local key. This record needs to be added to the DNS:"
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
        for domain in self.domainset:
            logger.debug(
                f"Generated TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}:"
            )
            # keep mypy happy
            assert isinstance(self.conf["tlsa-type-list"], list)
            assert isinstance(self.conf["tlsa-port"], int)
            assert isinstance(self.conf["tlsa-protocol"], str)
            for tlsatype in self.conf["tlsa-type-list"]:
                self.output_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf["tlsa-port"],
                    protocol=self.conf["tlsa-protocol"],
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
                f"Checking DNS for TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}:"
            )
            assert isinstance(self.conf["tlsa-type-list"], list)
            assert isinstance(self.conf["tlsa-port"], int)
            assert isinstance(self.conf["tlsa-protocol"], str)
            assert isinstance(self.conf["name-server"], str)
            for tlsatype in self.conf["tlsa-type-list"]:
                result = self.verify_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf["tlsa-port"],
                    protocol=self.conf["tlsa-protocol"],
                    tlsatype=tlsatype,
                    nameserver=self.conf["name-server"],
                )
                if not result and not self.error:
                    logger.debug(
                        "Problem discovered in check mode, setting self.error=True"
                    )
                    self.error = True
            logger.debug(
                f"Done checking DNS for TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}"
            )

    # MAIN METHODS

    def periodic(self) -> bool:
        """The periodic method performs periodic maintenance tasks.

        This method is called by the 'periodic' command, from cron or similar.
        It starts out by sleeping for a random period and then checks certificates and renews as needed.
        """
        if self.conf["periodic-sleep-minutes"]:
            assert isinstance(
                self.conf["periodic-sleep-minutes"], int
            )  # make mypy happy
            sleep = random.randint(0, self.conf["periodic-sleep-minutes"])
            logger.debug(f"Sleeping for {sleep} minutes before doing periodic...")
            time.sleep(sleep * 60)
        # check if we have a valid certificate
        if not self.check_certificate():
            # certificate is not valid, get new
            if not self.get_certificate():
                # unable to get new certificate
                logger.error(
                    f"Failed getting a new certificate for domainset: {self.domainset}"
                )
                return False
        # we have a valid certificate
        return True

    def load_domainset(self, domainset: typing.List[str]) -> None:
        """Prepare paths and create/load private key.

        Args:
            domainset: The list of domains to load

        Returns:
            None
        """
        logger.debug(f"Loading domainset {domainset}")
        self.domainset = domainset
        assert isinstance(self.conf["path"], str)
        # we name the files after the ascii idna representation of the first domain in the list
        filename = self.domainset[0].encode("idna").decode("ascii")
        logger.debug(f"Filenames for this domainset will be prefixed with: {filename}")

        # keypair
        self.keypair_path = os.path.join(self.conf["path"], f"{filename}.key")
        logger.debug(f"keypair path: {self.keypair_path}")

        # CSR
        self.csr_path = os.path.join(self.conf["path"], f"{filename}.csr")
        logger.debug(f"CSR path: {self.csr_path}")

        # certificate chain
        self.certificate_chain_path = os.path.join(self.conf["path"], f"{filename}.crt")
        logger.debug(f"Certificate chain path: {self.certificate_chain_path}")

        # certificate
        self.certificate_path = os.path.join(
            self.conf["path"], f"{filename}-certonly.crt"
        )
        logger.debug(f"certificate path: {self.certificate_path}")

        # intermediate
        self.intermediate_path = os.path.join(
            self.conf["path"], f"{filename}-intermediate.crt"
        )
        logger.debug(f"intermediate path: {self.intermediate_path}")

        # concat of privkey + chain
        self.concat_path = os.path.join(self.conf["path"], f"{filename}-concat.pem")
        logger.debug("concat path: %s" % self.concat_path)

        # finally load or create the keypair
        if os.path.exists(self.keypair_path):
            # load private key
            self.keypair = self.load_keypair(self.keypair_path)
            logger.debug(f"Loaded keypair from {self.keypair_path}")
        else:
            # create new private key
            self.keypair = self.generate_private_key()
            self.save_keypair(self.keypair, self.keypair_path)
            logger.debug(f"Created new keypair, saved to {self.keypair_path}")

    def grind(self, args: argparse.Namespace) -> None:
        """Loop over domainsets in ``self.conf["domain-list"]`` and call args.method for each."""
        logger.info(f"Certgrinder {__version__} running")

        # loop over domains
        counter = 0
        assert isinstance(self.conf["domain-list"], list)
        for domainset in self.conf["domain-list"]:
            counter += 1
            logger.debug(
                f"-- Processing domainset {counter} of {len(self.conf['domain-list'])}: {domainset.split(',')}"
            )
            # prepare paths and create/load private key
            self.load_domainset(domainset.split(","))
            # run the requested method
            getattr(self, args.method)()

        # do we need to run a post-renew hook?
        if self.hook_needed:
            logger.info(
                "At least one certificate was renewed, running post renew hooks..."
            )
            self.run_post_renew_hooks()

        # are we running in check mode?
        if args.command == "check" and self.error:
            logger.error(
                "Running in check mode and one or more errors were encountered, exit code 1"
            )
            sys.exit(1)

        logger.info("All done, exiting cleanly")
        sys.exit(0)


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description=f"Certgrinder version {__version__}. See the manpage or ReadTheDocs for more info."
    )
    # add topmost subparser for main command
    subparsers = parser.add_subparsers(
        help="Command (required)", dest="command", required=True
    )

    # "check" command
    check_parser = subparsers.add_parser(
        "check",
        help='Use the "check" command to check certificates, OCSP responses and TLSA records. Returns exit code 0 if all is well, and 1 if something needs attention.',
    )
    check_subparsers = check_parser.add_subparsers(
        help="Specify what to check using one of the available check sub-commands.",
        dest="subcommand",
        required=True,
    )

    # "check certificate" subcommand
    check_certificate_parser = check_subparsers.add_parser(
        "certificate",
        help="Tell certgrinder to check certificate validity for all configured domainsets. Returns exit code 1 if any problem is found, exit code 0 if all is well.",
    )
    check_certificate_parser.set_defaults(method="check_certificate")

    # "check tlsa" subcommand
    check_tlsa_parser = check_subparsers.add_parser(
        "tlsa",
        help="Tell certgrinder to lookup TLSA records for the given port and protocol in the DNS and compare with what we have locally, for example: 'certgrinder check tlsa 853 tcp'",
    )
    check_tlsa_parser.set_defaults(method="check_tlsa")
    check_tlsa_parser.add_argument(
        "tlsa-port", help="The port of the service, for example 443"
    )
    check_tlsa_parser.add_argument(
        "tlsa-protocol", help="The protocol of the service, for example tcp"
    )

    # "get" command
    get_parser = subparsers.add_parser(
        "get", help='Use the "get" command to get certificates and OCSP responses'
    )
    get_subparsers = get_parser.add_subparsers(
        help="Specify what to get using one of the available get sub-commands",
        dest="subcommand",
        required=True,
    )

    # "get certificate" subcommand
    get_cert_parser = get_subparsers.add_parser(
        "certificate",
        help="Tell certgrinder to get new certificate(s), regardless of their current state. Rarely needed, use 'periodic' command instead.",
    )
    get_cert_parser.set_defaults(method="get_certificate")

    # "help" command
    subparsers.add_parser("help", help='The "help" command just outputs the usage help')

    # "periodic" command
    periodic_parser = subparsers.add_parser(
        "periodic",
        help='The "periodic" command checks certificates and renews them as needed. Meant to be run from cron or similar daily.',
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
    show_subparsers.add_parser(
        "configuration", help="Tell certgrinder to output the current configuration"
    )

    # "show spki" subcommand
    show_spki_parser = show_subparsers.add_parser(
        "spki",
        help="Tell certgrinder to generate and print the pin-sha256 spki pins for the public keys it manages.",
    )
    show_spki_parser.set_defaults(method="show_spki")

    # "show tlsa" subcommand
    show_tlsa_parser = show_subparsers.add_parser(
        "tlsa",
        help="Use the 'show tlsa' sub-command to tell certgrinder to generate and print TLSA records for the given service, for example: 'certgrinder show tlsa 443 tcp'",
    )
    show_tlsa_parser.set_defaults(method="show_tlsa")
    show_tlsa_parser.add_argument(
        "tlsa-port", help="The port of the service, for example 443"
    )
    show_tlsa_parser.add_argument(
        "tlsa-protocol", help="The protocol of the service, for example tcp"
    )

    # "version" command
    subparsers.add_parser(
        "version", help='The "version" command just outputs the version of Certgrinder'
    )

    # optional arguments
    parser.add_argument(
        "--certgrinderd",
        dest="certgrinderd",
        help="The command to reach the certgrinderd server, will get the CSR on stdin. Usually something like 'ssh certgrinderd@server -T'",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cert-renew-threshold-days",
        dest="cert-renew-threshold-days",
        help="A certificate is renewed when it has less than this many days of lifetime left. Default: `30`",
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
        help="Comma seperated list of domains for a certificate. Can be specified multiple times.",
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
        "-f",
        "--config-file",
        dest="config-file",
        help="The path to the certgrinder.yml config file to use, default ~/certgrinder.yml",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-n",
        "--name-server",
        dest="name-server",
        help="Tell certgrinder to use this DNS server IP to lookup TLSA records. Only relevant with -c / --checktlsa. Only v4/v6 IPs, no hostnames.",
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
        help="Tell certgrinder to use the specified directory for keys, CSRs and certificates. The directory must exist and be writeable by the user running certgrinder.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--periodic-sleep-minutes",
        dest="periodic-sleep-minutes",
        help="Tell certgrinder to sleep for a random number of minutes between 0 and this number before doing anything when the periodic command is used. Set to 0 to disable sleeping.",
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
        help="The list of commands to run after one or more certificates are renewed. Most such commands will need root access to run, remember to prefix the command with 'sudo' as needed. Can be specified multiple times. Default: `None`",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="log-level",
        const="WARNING",
        help="Quiet mode. No output at all if there is nothing to do, and no errors are encountered. Equal to setting --log-level=WARNING.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-s",
        "--staging",
        dest="staging",
        action="store_true",
        help="Staging mode. Sets --acme-server-url https://acme-staging-v02.api.letsencrypt.org/directory and --invalid-ca-cn-list empty. Use this while playing around to avoid hitting rate limits!",
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
    mockargs: typing.Optional[typing.List[str]] = None
) -> typing.Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Create an argparse monster and parse mockargs or sys.argv[1:]."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: typing.Optional[typing.List[str]] = None) -> None:
    """Initialise script and ``Certgrinder()`` object, then call ``certgrinder.grind()``.

    Parse command-line arguments, read config file if needed, configure logging,
    and then call ``certgrinder.grind()`` method.
    """
    # get parser and parse args
    parser, args = parse_args(mockargs)

    # handle a couple of special cases before reading config
    if args.command == "version" or hasattr(args, "version"):
        print(f"Certgrinder version {__version__}")
        sys.exit(0)
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

    # update file config (if any) with command-line arguments,
    # so they take precedence over config file configuration
    config.update(vars(args))

    # remove command and subcommand (part of argparse internals)
    if "command" in config:
        del config["command"]
    if "subcommand" in config:
        del config["subcommand"]

    # configure certgrinder
    certgrinder = Certgrinder()
    certgrinder.configure(userconfig=config)

    if args.command == "show" and args.subcommand == "configuration":
        logger.info("Current certgrinder configuration:")
        pprint(certgrinder.conf)
        sys.exit(0)

    # call main method
    certgrinder.grind(args)


def init() -> None:
    """This is here just as a testable way of calling main()."""
    if __name__ == "__main__":
        main()


init()
