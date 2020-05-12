#!/usr/bin/env python
import argparse
import base64
import binascii
import hashlib
import logging
import logging.handlers
import os
import subprocess
import sys
import tempfile
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
__version__ = "0.13.0-beta2-dev"


class Certgrinder:
    """
    The Certgrinder client class.
    """

    # save version as a class attribute
    __version__ = __version__

    # default config
    conf: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]] = {
        "certgrinderd": "",
        "cert-renew-threshold-days": 30,
        "domain-list": [],
        "invalid-ca-cn-list": ["Fake LE Intermediate X1", "Fake LE Intermediate X2"],
        "log-level": "INFO",
        "name-server": "",
        "path": "",
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
    domainset: typing.List[str] = []

    # paths for current certificate and keys
    keypair_path: str = ""
    csr_path: str = ""
    certificate_path: str = ""
    certificate_chain_path: str = ""
    intermediate_path: str = ""
    concat_path: str = ""

    # this is set to True if an error occurs
    error: bool = False

    # this is set to True if we need to run a post renew hook
    hook_needed: bool = False

    def configure(
        self,
        userconfig: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]],
    ) -> None:
        """
        The configure() method merges the supplied userconfig dict with the default config,
        checks for missing required settings, and configures logging and syslog.
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

        # check if configured path exists
        if not os.path.exists(str(self.conf["path"])):
            logger.error(f"Configured path {self.conf['path']} does not exist")
            sys.exit(1)

        # check if configured path is writable
        try:
            with tempfile.TemporaryFile() as _:
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
            try:
                logger.addHandler(syslog_handler)
            except Exception:
                logger.exception(
                    f"Unable to connect to syslog socket {self.conf['syslog-socket']} - syslog not enabled. Exception info below:"
                )
                sys.exit(1)
        else:
            logger.debug("Not configuring syslog")

        logger.debug(
            f"Certgrinder {__version__} configured OK - running with config: {self.conf}"
        )

    # RSA KEY METHODS

    @staticmethod
    def load_keypair(
        path: str
    ) -> typing.Union[openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey]:
        """ Load keypair bytes from disk, load key and return the object """
        # check permissions for self.keypair_path and fix to 640 if needed
        if oct(os.stat(path).st_mode)[4:] != "0640":
            logger.debug(f"Keypair {path} has incorrect permissions, fixing to 640...")
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
        """ Generate and returns a private key """
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
        """ Saves keypair to disk """
        with open(path, "wb") as f:
            f.write(
                keypair.private_bytes(
                    encoding=primitives.serialization.Encoding.PEM,
                    format=primitives.serialization.PrivateFormat.TraditionalOpenSSL,
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
        """ Returns the DER formatted publickey """
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
        """
        Generates and returns a new CSR based on the public key and list of domains.
        Only sets CN since everything else is removed by LetsEncrypt in the certificate anyway.
        Add all domains in subjectAltName, including the one put into CN.
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
        """ Save the PEM version of the CSR to the path """
        with open(path, "wb") as f:
            f.write(csr.public_bytes(primitives.serialization.Encoding.PEM))
        os.chmod(path, 0o644)

    # CERTIFICATE METHODS

    @staticmethod
    def load_certificate(path: str) -> cryptography.x509.Certificate:
        """ Reads PEM certificate data from the path and returns the object """
        pem_data = open(path, "rb").read()
        return cryptography.x509.load_pem_x509_certificate(pem_data, default_backend())

    @staticmethod
    def check_certificate_issuer(
        certificate: cryptography.x509.Certificate, invalid_ca_cn_list: typing.List[str]
    ) -> bool:
        """
        Checks the issuer of the certificate. Returns False if the certificate
        was issued by any CA CN in invalid_ca_cn_list, True otherwise.
        """
        # Return False if the certificate was issued by itself
        if certificate.issuer == certificate.subject:
            return False

        # do we have any invalid CA CNs? otherwise bail out now
        if not invalid_ca_cn_list:
            return True

        # check if certificate was issued by an invalid CA
        for x in certificate.issuer:
            if (
                x.oid == cryptography.x509.oid.NameOID.COMMON_NAME
                and x.value in invalid_ca_cn_list
            ):
                logger.debug(
                    f"This certificate was issued by a CA CN in invalid_ca_cn_list, check_certificate_issuer() returning False"
                )
                return False

        # all good
        return True

    @staticmethod
    def check_certificate_expiry(
        certificate: cryptography.x509.Certificate, threshold_days: int
    ) -> bool:
        """ Checks the expiration of the certificate, return True if remaining validity is > threshold_days """
        expiredelta = certificate.not_valid_after - datetime.now()
        if expiredelta.days < threshold_days:
            return False
        else:
            return True

    @staticmethod
    def check_certificate_public_key(
        certificate: cryptography.x509.Certificate,
        keypair: typing.Union[
            openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey
        ],
    ) -> bool:
        """ Make sure certificate has the specified public key """
        # compare the PEM representation of the two public keys and return the result
        return bool(
            keypair.public_key().public_bytes(
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
        """ Make sure the certificate has the specified subject """
        return str(certificate.subject) == str(subject)

    @staticmethod
    def check_certificate_san_names(
        certificate: cryptography.x509.Certificate, san_names: typing.List[str]
    ) -> bool:
        """ Make sure the certificate has the provided list of names as SAN """
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
        keypair: typing.Optional[
            typing.Union[openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey]
        ],
        subject: str = "",
    ) -> bool:
        """
        Performs a few sanity checks of the certificate.
        - checks that the issuer is valid
        - checks that the certificate expiry is not exceeded
        - checks that the public key is correct
        - checks that the subject is correct
        - checks that the SubjectAltName data is correct (TODO)
        Return False if a problem is found, True if all is well
        """
        if not cls.check_certificate_issuer(certificate, invalid_ca_cn_list):
            logger.error(
                f"Certificate issuer is on our list of invalid CAs: {invalid_ca_cn_list}"
            )
            return False
        if not cls.check_certificate_expiry(certificate, threshold_days):
            logger.error(f"Certificate expires in less than {threshold_days} days")
            return False
        if not cls.check_certificate_san_names(certificate, san_names):
            logger.error("Certificate SAN name list is different from the expected")
            return False
        if keypair and not cls.check_certificate_public_key(certificate, keypair):
            logger.error("Certificate public key is different from the expected")
            return False
        if subject and not cls.check_certificate_subject(certificate, subject):
            logger.error("Certificate subject is different from the expected")
            return False
        logger.debug("Certificate is OK, returning True")
        return True

    @staticmethod
    def save_certificate(
        certificate: cryptography.x509.Certificate,
        path: str,
        intermediate: typing.Optional[cryptography.x509.Certificate] = None,
    ) -> None:
        """ Save the PEM certificate to the path """
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
        """ Creates a single file with the private key, the cert and the intermediate, in that order """
        cls.save_keypair(keypair, path)
        with open(path, "ab") as f:
            f.write(certificate.public_bytes(primitives.serialization.Encoding.PEM))
            f.write(intermediate.public_bytes(primitives.serialization.Encoding.PEM))
        os.chmod(path, 0o640)

    def get_certgrinderd_command(self) -> typing.List[str]:
        """ Return the certgrinderd command to run """
        # put the command together
        command = str(self.conf["certgrinderd"])
        commandlist = [str(x) for x in command.split(" ")]

        # pass the certgrinder log-level to certgrinderd
        commandlist.append("--log-level")
        commandlist.append(str(self.conf["log-level"]))

        # do we want staging mode?
        if self.conf["staging"]:
            commandlist.append("--staging")

        # all good
        return commandlist

    def run_certgrinderd(
        self, csr: x509._CertificateSigningRequest
    ) -> typing.Optional[bytes]:
        """ Run the configured certgrinderd command with the CSR on stdin """
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
        """ Split output chain into cert and intermediate """
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
            keypair=self.keypair,
            subject=csr.subject,
            san_names=self.domainset,
        )
        if not valid:
            logger.error("Certificate is not valid, not saving to disk.")
            self.error = True
            return None

        # we have a new certificate, so we will need to run the post renew hook later
        self.hook_needed = True

        # done, return the certificate chain bytes
        return certificate, intermediate

    def get_certificate(self) -> bool:
        """
        This method gets a new certificate for self.domainset, without considering
        the existing certificate. It is called by self.periodic() as needed.
        It can also be called by the 'get certificate' subcommand.
        """
        logger.info(f"Getting new certificate for domainset {self.domainset} ...")
        # get and save CSR
        csr = self.generate_csr(self.keypair, self.domainset)
        self.save_csr(csr, self.csr_path)
        logger.debug(
            f"Wrote {len(csr.public_bytes(primitives.serialization.Encoding.PEM))} bytes CSR to path {self.csr_path}"
        )

        # get certificate
        stdout = self.run_certgrinderd(csr)
        if not stdout:
            logger.error("Did not get a certificate :(")
            return False
        result = self.parse_certgrinderd_output(stdout, csr)
        if result:
            certificate, intermediate = result
        else:
            logger.error("Did not get a certificate :(")
            return False

        if not self.check_certificate(certificate):
            logger.error("The new certificate is not valid, not saving to disk")
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
        keypair: typing.Optional[
            typing.Union[openssl.rsa._RSAPrivateKey, openssl.ed25519.Ed25519PrivateKey]
        ] = None,
    ) -> bool:
        """
        This method checks certificate validity and returns True or False.
        It is called by self.grind() once per domainset when the "check certificate"
        subcommand is invoked.
        Reads the certificate from self.certificate_path if there is no certificate arg
        """
        # load certificate from disk?
        if not certificate:
            # does the file exist?
            if os.path.exists(self.certificate_path):
                certificate = self.load_certificate(self.certificate_path)
            else:
                logger.error(f"Certificate {self.certificate_path} not found")
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
            keypair=keypair,
            san_names=self.domainset,
        )
        # set self.error if cert is not valid (we may need the information later)
        if not valid:
            self.error = True
        return valid

    # POST RENEW HOOK METHOD

    def run_post_renew_hooks(self) -> bool:
        """
        Loops over configured post_renew_hooks and runs them.
        If the hook needs sudo or doas or similar that must be included in the command
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
        """
        Generates and returns an pin-sha256 spki hpkp style pin for the provided public key.
        OpenSSL equivalent command is:
        openssl x509 -in example.com.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64
        """
        return base64.b64encode(hashlib.sha256(derkey).digest()).decode("ASCII")

    @classmethod
    def output_spki(cls, derkey: bytes) -> None:
        """ Get and print the spki pin for the supplied DER public key """
        spki = cls.generate_spki(derkey)
        logger.info(f"pin-sha256='{spki}'")

    def show_spki(self) -> None:
        """ 'show spki' subcommand method, called for each domainset by self.grind() """
        logger.debug(
            f"Generated SPKI pin-sha256 for public key for domainset {self.domainset}:"
        )
        self.output_spki(derkey=self.get_der_pubkey(self.keypair))

    # TLSA METHODS

    @staticmethod
    def generate_tlsa_record(derkey: bytes, tlsatype: str) -> str:
        """
        Generates and returns the data part of a TLSA record of the requested type,
        based on the DER formatted public key supplied.
        Returns an uppercase hex string.
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
        """
        Lookup TLSA records in DNS for the configured domain, port, and protocol.
        Loop over any responses and look for the requested tlsatype.
        Return a list of results, optionally limited to the specified tlsatype, or None if none were found.
        Use system resolver unless nameserver is specified.
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
                "Empty answer returned by {nameserverstr}. No TLSA records found in DNS for: {record}"
            )
            return None
        except dns.exception.SyntaxError:
            logger.error(
                "Error parsing DNS server IP '{nameserver}'. Only IP addresses are supported."
            )
            sys.exit(1)
        except dns.exception.Timeout:
            logger.error("Timeout while waiting for {nameserverstr}. Error.")
            sys.exit(1)
        except Exception as E:
            logger.error("Exception received during DNS lookup: %s" % E)
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
        """
        Outputs the TLSA record for the given DER key, domain, port, protocol and tlsatype, as returned by self.generate_tlsa()
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
    ) -> None:
        """
        Checks the TLSA records for the port/protocol/domain and DER key in the DNS.
        Outputs the info needed to fix things when missing records are found.
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
            return

        # we have a response
        logger.debug(
            f"Received DNS response for TLSA type {tlsastr}: {len(dns_reply)} answers - looking for an answer matching the public key..."
        )
        for reply in dns_reply:
            if reply.upper() == tlsadata:
                logger.info(
                    f"TLSA record for name {tlsarecord} type {tlsastr} matching the local key found in DNS, good."
                )
                break
        else:
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

    def show_tlsa(self) -> None:
        """ 'show tlsa' subcommand method, called for each domainset by self.grind() """
        for domain in self.domainset:
            logger.debug(
                f"Generated TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}:"
            )
            # keep mypy happy
            assert isinstance(self.conf["tlsa-types"], list)
            assert isinstance(self.conf["tlsa-port"], int)
            assert isinstance(self.conf["tlsa-protocol"], str)
            for tlsatype in self.conf["tlsa-types"]:
                self.output_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf["tlsa-port"],
                    protocol=self.conf["tlsa-protocol"],
                    tlsatype=tlsatype,
                )

    def check_tlsa(self) -> None:
        """ 'check tlsa' subcommand method, called for each domainset by self.grind() """
        for domain in self.domainset:
            logger.debug(
                f"Checking DNS for TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}:"
            )
            assert isinstance(self.conf["tlsa-types"], list)
            assert isinstance(self.conf["tlsa-port"], int)
            assert isinstance(self.conf["tlsa-protocol"], str)
            assert isinstance(self.conf["name-server"], str)
            for tlsatype in self.conf["tlsa-types"]:
                self.verify_tlsa_record(
                    derkey=self.get_der_pubkey(self.keypair),
                    domain=domain,
                    port=self.conf["tlsa-port"],
                    protocol=self.conf["tlsa-protocol"],
                    tlsatype=tlsatype,
                    nameserver=self.conf["name-server"],
                )
            logger.debug(
                f"Done checking DNS for TLSA records for {domain} port {self.conf['tlsa-port']} protocol {self.conf['tlsa-protocol']}"
            )

    # MAIN METHODS

    def periodic(self) -> bool:
        """
        The periodic method performs maintenance tasks and is meant to be called
        by the 'periodic' command from cron or similar.
        """
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
        """ Prepare paths and create/load private key """
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
        """ Loop over domainsets in self.conf["domain-list"] and call args.method for each """
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


def parse_args(
    mockargs: typing.Optional[typing.List[str]] = None
) -> typing.Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """ Create an argparse monster and parse mockargs or sys.argv[1:] """
    parser = argparse.ArgumentParser(
        description=f"Certgrinder version {__version__}. See the manpage or ReadTheDocs for more info."
    )
    # add topmost subparser for main command
    subparsers = parser.add_subparsers(
        help="Command (required)", dest="command", required=True
    )

    # "check" subcommand
    check_parser = subparsers.add_parser(
        "check",
        help='Use the "check" command to check certificates, OCSP responses and TLSA records. Returns exit code 0 if all is well, and 1 if something needs attention.',
    )
    check_subparsers = check_parser.add_subparsers(
        help="check sub-command help", dest="subcommand", required=True
    )

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

    # "check certificate" subcommand
    check_cert_parser = check_subparsers.add_parser(
        "certificate",
        aliases=["cert"],
        help="Tell certgrinder check certificate validity and exit. If any certificates are missing or have less than 30 days validity the exit code will be 1.",
    )
    check_cert_parser.set_defaults(method="check_certificate")

    # "show" subcommand
    show_parser = subparsers.add_parser(
        "show",
        help='Use the "show" command to show certificates, TLSA records, SPKI pins or configuration.',
    )
    show_subparsers = show_parser.add_subparsers(
        help="show sub-command help", dest="subcommand", required=True
    )

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

    # "show spki" subcommand
    show_spki_parser = show_subparsers.add_parser(
        "spki",
        help="Tell certgrinder to generate and print the pin-sha256 spki pins for the public keys it manages.",
    )
    show_spki_parser.set_defaults(method="show_spki")

    # "show configuration" subcommand
    show_subparsers.add_parser(
        "configuration",
        aliases=["config", "conf"],
        help="Tell certgrinder to output the current configuration",
    )

    # "get" subcommand
    get_parser = subparsers.add_parser(
        "get", help='Use the "get" command to get certificates and OCSP responses'
    )
    get_subparsers = get_parser.add_subparsers(
        help="get sub-command help", dest="subcommand", required=True
    )

    # "get certificate" subcommand
    get_cert_parser = get_subparsers.add_parser(
        "certificate",
        aliases=["cert"],
        help="Tell certgrinder to get new certificate(s), regardless of their current state. Rarely needed, use 'periodic' command instead.",
    )
    get_cert_parser.set_defaults(method="get_certificate")

    # "version" subcommand
    subparsers.add_parser(
        "version", help='The "version" command just outputs the version of Certgrinder'
    )

    # "help" subcommand
    subparsers.add_parser("help", help='The "help" command just outputs the usage help')

    # "periodic" subcommand
    subparsers.add_parser(
        "periodic",
        help='The "periodic" command checks certificates and renews them as needed. It is meant to be run daily.',
    )
    get_cert_parser.set_defaults(method="periodic")

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
        dest="configfile",
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
        "--path",
        dest="path",
        help="Tell certgrinder to use the specified directory for keys, CSRs and certificates. The directory must exist and be writeable by the user running certgrinder.",
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
        help="Pass --staging to the certgrinderd command to tell the Certgrinder server to use LetsEncrypt staging servers (use for testing purposes).",
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
    # all done
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: typing.Optional[typing.List[str]] = None) -> None:
    """
    Initialise script. Instantiate Certgrinder() object, parse command-line arguments,
    read config file if needed, configure logging, and then call certgrinder.grind() method
    """
    # instantiate Certgrinder object now to enable argparse to run methods directly with func=certgrinder.foo
    certgrinder = Certgrinder()

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
    del config["command"]
    del config["subcommand"]

    # configure certgrinder
    certgrinder.configure(userconfig=config)

    if args.command == "show" and args.subcommand in [
        "conf",
        "config",
        "configuration",
    ]:
        logger.info("Current certgrinder configuration:")
        pprint(certgrinder.conf)
        sys.exit(0)

    # call main method
    certgrinder.grind(args)


if __name__ == "__main__":
    main()
