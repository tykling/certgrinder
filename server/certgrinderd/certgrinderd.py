#!/usr/bin/env python
"""Certgrinderd module.

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
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from pprint import pprint

import cryptography.x509
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from pid import PidFile  # type: ignore[import-not-found]
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(f"certgrinderd.{__name__}")

# get version number from package metadata if possible
__version__: str
"The value of this variable is taken from the Python package registry, "
"and if that fails from the ``_version.py`` file written by ``setuptools_scm``."

try:
    __version__ = version("certgrinderd")
except PackageNotFoundError:
    # package is not installed, get version from file
    try:
        from ._version import version as __version__  # type: ignore[import-not-found,no-redef]
    except ImportError:
        __version__ = "0.0.0"


class Config(BaseSettings):
    """The Certgrinderd settings class.

    Defines default settings, supports env overrides.
    """

    model_config = SettingsConfigDict(env_prefix="certgrinderd_")

    acme_email: str | None = None
    acme_server_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    acme_zone: str | None = None
    auth_hook: Path = Path("manual-auth-hook.sh")
    certbot_command: str = "/usr/local/bin/sudo /usr/local/bin/certbot"
    certbot_config_dir: Path | None = None
    certbot_logs_dir: Path | None = None
    certbot_work_dir: Path | None = None
    certificate_file: Path | None = None
    cleanup_hook: Path | None = Path("manual-cleanup-hook.sh")
    config_file: Path | None = None
    csr_path: Path | None = None
    debug: bool = False
    expected_chain_length: int = 2
    log_level: str = "INFO"
    pid_dir: Path = Path("/tmp")  # noqa: S108
    preferred_chain: str = "ISRG_Root_X1"
    skip_acme_server_cert_verify: bool = False
    syslog_facility: str | None = None
    syslog_socket: str | None = None
    temp_dir: Path = Path("/tmp")  # noqa: S108
    web_root: Path | None = None


class Certgrinderd:
    """The Certgrinderd server class."""

    # save version as a class attribute
    __version__ = __version__

    def __init__(
        self,
        userconfig: dict[str, str | bool | Path | None] | None = None,
    ) -> None:
        """Merge userconfig with defaults and configure logging.

        Args:
            userconfig: A dict of configuration to merge with default config

        Returns:
            None
        """
        # load userconfig
        if userconfig is None:
            userconfig = {}
        # convert dashes to underscores in config keys
        for key in list(userconfig.keys()):
            if "-" in key:
                newkey = key.replace("-", "_")
                userconfig[newkey] = userconfig[key]
                del userconfig[key]
        self.conf = Config(**userconfig)  # type: ignore[arg-type]

        # define the log format used for stdout depending on the requested loglevel
        if self.conf.log_level == "DEBUG":
            console_logformat = (
                "%(asctime)s certgrinderd %(levelname)s Certgrinderd.%(funcName)s():%(lineno)i:  %(message)s"
            )
        else:
            console_logformat = "%(asctime)s certgrinderd %(levelname)s %(message)s"

        # configure the log format used for console
        logging.basicConfig(
            level=getattr(logging, self.conf.log_level),
            format=console_logformat,
            datefmt="%Y-%m-%d %H:%M:%S %z",
        )

        # connect to syslog?
        if self.conf.syslog_socket and self.conf.syslog_facility:
            facility: int = getattr(logging.handlers.SysLogHandler, self.conf.syslog_facility)
            syslog_handler = logging.handlers.SysLogHandler(address=self.conf.syslog_socket, facility=facility)
            syslog_format = logging.Formatter("certgrinderd: %(message)s")
            syslog_handler.setFormatter(syslog_format)
            logger.addHandler(syslog_handler)
            # usually SysLogHandler is lazy and doesn't connect the socket until
            # a message has to be sent. Call _connect_unixsocket() now to force
            # an exception now if we can't connect to the socket
            syslog_handler._connect_unixsocket(  # type: ignore[attr-defined]  # noqa: SLF001
                self.conf.syslog_socket
            )
            # OK, we are connected to syslog
            logger.debug(
                f"Connected to syslog-socket {self.conf.syslog_socket}, logging to facility {self.conf.syslog_facility}"
            )
        else:
            logger.debug("Not configuring syslog")

        logger.info(f"certgrinderd {__version__} running, log-level is {self.conf.log_level}")
        logger.debug(f"Running with config: {self.conf}")

    # CSR methods

    @staticmethod
    def parse_csr(csrstring: str = "") -> cryptography.x509.CertificateSigningRequest:
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
        return cryptography.x509.load_pem_x509_csr(csrstring.encode("ascii"), default_backend())

    def process_csr(self, csrpath: Path | None = None) -> None:
        """Load the CSR, use it to get a certificate, and cleanup.

        Calls ``self.parse_csr()`` followed by ``self.check_csr()``, and then exits if any
        problems are found with the CSR.

        Then ``self.get_certificate()`` is called, which in turn calls Certbot, which writes
        the certificate to stdout.

        Finally the CSR is deleted.

        Args:
            csrpath(Path): The path to the CSR. Optional. Pass None to use stdin.

        Returns:
            None
        """
        # get the CSR from stdin or file
        if csrpath:
            with csrpath.open() as f:
                csrstring = f.read()
        else:
            csrstring = ""
        csr = self.parse_csr(csrstring)

        # check CSR creaminess
        if not self.check_csr(csr):
            # something is fucky with the CSR
            sys.exit(1)

        # get temp path for the csr so we can save it to disk
        _, tmppath = tempfile.mkstemp(suffix=".csr", prefix="certgrinderd-", dir=self.conf.temp_dir)
        temp_csr_path = Path(tmppath)

        # CSR is OK, save it to disk
        self.save_csr(csr, temp_csr_path)

        # alright, get the cert for this CSR
        self.get_certificate(temp_csr_path)

        # clean up temp file
        temp_csr_path.unlink()

    @staticmethod
    def save_csr(csr: cryptography.x509.CertificateSigningRequest, path: Path) -> None:
        """Save the CSR object to the path in PEM format.

        Args:
            csr: The CSR object
            path(Path): The path to save it in

        Returns:
            None
        """
        with path.open("wb") as f:
            f.write(csr.public_bytes(primitives.serialization.Encoding.PEM))

    @staticmethod
    def check_csr(csr: cryptography.x509.CertificateSigningRequest) -> bool:
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
            logger.error("Environment var CERTGRINDERD_DOMAINSETS not found, bailing out")
            return False

        # get CommonName from CSR
        cn_list = csr.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
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
            logger.error(f"CSR is not valid (CN {cn} not found in SAN list {san_list}), bailing out")
            return False

        # domainsets is a semicolon-separated list of comma-separated domainsets.
        # loop over domainsets until we find a match and break out, or hit the else
        # if we never find a domainset covering all names in the CSR
        logger.debug(f"testing if {san_list} is allowed in {allowed_names}")
        for domainset in allowed_names.split(";"):
            domainsetlist = [d.encode("idna").decode("ascii") for d in domainset.split(",")]
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
                logger.debug(f"All names in the CSR ({san_list}) are permitted for this client")
                break
        else:
            # this CSR contains names which are not permitted for this client
            logger.error(
                "CSR contains one or more names which are not permitted for this client. "
                f"Permitted names: {allowed_names} - Requested names: {san_list}"
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
        self.process_csr(csrpath=self.conf.csr_path)

    def get_certbot_command(  # noqa: PLR0913
        self,
        challengetype: str,
        csrpath: Path,
        fullchainpath: Path,
        certpath: Path,
        chainpath: Path,
        subcommand: str = "certonly",
    ) -> list[str]:
        """Put the certbot command together.

        Start with ``self.conf.certbot_command`` and append all the needed options.

        Optionally add ``--email`` and a bunch of certbot settings as needed.

        Args:
            challengetype: The type of challenge, ``dns`` or ``http``
            csrpath(Path): The path to the CSR
            fullchainpath(Path): The path to save the certificate+issuer
            certpath(Path): The path to save the certificate (without issuer)
            chainpath(Path): The path to save the issuer (without certificate)
            subcommand(str): The subcommand to run, defaults to "certonly"

        Returns:
            The certbot command as a list
        """
        command: list[str] = [
            *self.conf.certbot_command.split(" "),
            subcommand,
            "--non-interactive",
        ]

        if subcommand == "certonly":
            command += [
                "--quiet",
                "--authenticator",
                "manual",
                "--preferred-challenges",
                challengetype,
                "--manual-auth-hook",
                str(self.conf.auth_hook),
                "--manual-cleanup-hook",
                str(self.conf.cleanup_hook),
                "--csr",
                str(csrpath),
                "--fullchain-path",
                str(fullchainpath),
                "--cert-path",
                str(certpath),
                "--chain-path",
                str(chainpath),
                "--agree-tos",
            ]

        if self.conf.acme_email:
            command.append("--email")
            command.append(self.conf.acme_email)

        if self.conf.acme_server_url:
            command.append("--server")
            command.append(self.conf.acme_server_url)

        if self.conf.skip_acme_server_cert_verify:
            command.append("--no-verify-ssl")

        if self.conf.certbot_config_dir:
            command.append("--config-dir")
            command.append(str(self.conf.certbot_config_dir))

        if self.conf.certbot_work_dir:
            command.append("--work-dir")
            command.append(str(self.conf.certbot_work_dir))

        if self.conf.certbot_logs_dir:
            command.append("--logs-dir")
            command.append(str(self.conf.certbot_logs_dir))

        if self.conf.preferred_chain:
            command.append("--preferred-chain")
            # replace underscores with spaces in the chain name before passing to Certbot
            command.append(self.conf.preferred_chain.replace("_", " "))

        logger.debug(f"Returning certbot command: {command}")
        return command

    def get_certificate(self, csrpath: Path) -> None:
        """Get a cert using ``DNS-01`` or ``HTTP-01`` by calling ``self.run_certbot()`` for each.

        If ``self.conf.acme_zone`` is set then ``DNS-01`` is attempted. Return if it
        results in a new certificate.

        If ``self.conf.web_root`` is set then ``HTTP-01`` is attempted. Return if it
        results in a new certificate.

        If there is still no certificate log an error and return anyway.

        Args:
            csrpath(Path): The path to the CSR

        Returns:
            None
        """
        # get temp paths for certbot
        fullchainpath = self.conf.temp_dir / "fullchain.pem"
        certpath = self.conf.temp_dir / "certificate.pem"
        chainpath = self.conf.temp_dir / "chain.pem"

        # try DNS-01 first, if we have an acme zone
        if self.conf.acme_zone:
            logger.debug(f"Attempting DNS-01 with zone {self.conf.acme_zone} ...")
            env = os.environ.copy()
            env.update({"ACMEZONE": self.conf.acme_zone})
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
        if self.conf.web_root:
            logger.debug(f"Attempting HTTP-01 with webroot {self.conf.web_root} ...")
            env = os.environ.copy()
            env.update({"WEBROOT": str(self.conf.web_root)})
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

    def run_certbot(self, command: list[str], env: dict[str, str], fullchainpath: Path) -> bool:
        """Call certbot, check exitcode, output cert, return bool success.

        Args:
            command: A list of certbot command elements
            env: A dictionary of the environment to pass to subprocess.run()
            fullchainpath(Path): The path to read the certificate+chain from after Certbot runs

        Returns:
            True if Certbot command exitcode was 0, False otherwise
        """
        # call certbot
        logger.debug(f"Running certbot command with env {env}: {command}")
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)  # noqa: S603

        certbot_stdout, certbot_stderr = p.communicate()

        if p.returncode == 0:
            # success, read chain from disk
            with fullchainpath.open() as f:
                chainbytes = f.read()
            self.parse_certificate_chain(fullchainpath, expected_length=self.conf.expected_chain_length)
            # output chain to stdout
            print(chainbytes)  # noqa: T201
            return True
        logger.error("certbot command returned non-zero exit code")
        logger.error("certbot stderr:")
        for line in certbot_stderr.strip().decode("utf-8").split("\n"):
            logger.error(line)
        return False

    @staticmethod
    def split_pem_chain(pem_chain_bytes: bytes) -> list[bytes]:
        """Split a PEM chain into a list of bytes of the individual PEM certificates.

        Args:
            pem_chain_bytes: The bytes representing the PEM chain

        Returns:
            A list of 0 or more bytes chunks representing each certificate
        """
        logger.debug(f"Parsing certificates from {len(pem_chain_bytes)} bytes input")
        certificates = [
            ("-----BEGIN CERTIFICATE-----" + cert).encode("ASCII")
            for cert in pem_chain_bytes.decode("ASCII").split("-----BEGIN CERTIFICATE-----")[1:]
        ]
        logger.debug(f"Returning a list of {len(certificates)} chunks of bytes resembling PEM certificates")
        return certificates

    @classmethod
    def parse_certificate_chain(
        cls,
        certpath: Path | None,
        expected_length: int | None = None,
    ) -> list[cryptography.x509.Certificate]:
        """Parse certificate chain from path or stdin.

        Args:
            certpath(Path): The path of the certificate chain to parse (optional),
                      chainbytes are taken from stdin if not provided.
            expected_length(int | None): The number of certificates to expect. Optional.

        Returns:
            A list of cryptography.x509.Certificate objects in the order they appear
            in the input.
        """
        if certpath:
            logger.debug(f"Reading PEM cert chain from file {certpath} ...")
            with certpath.open("rb") as f:
                chainbytes = f.read()
        else:
            logger.debug("Reading PEM cert chain from stdin ...")
            chainbytes = sys.stdin.read().encode("ASCII")

        certs = cls.split_pem_chain(chainbytes)
        if expected_length and len(certs) != expected_length:
            logger.error(
                f"The input has {len(certs)} certificates, expected a chain with {expected_length} "
                "certificates, something is not right."
            )
            sys.exit(1)

        chain = []
        for certbytes in certs:
            cert = cls.parse_certificate(certbytes)
            chain.append(cert)
        return chain

    @classmethod
    def parse_certificate(cls, certificate_bytes: bytes) -> cryptography.x509.Certificate:
        """Parse and return individual certificate, or calls sys.exit(1) if something goes wrong.

        Args:
            certificate_bytes: A chunk of bytes representing a PEM certificate

        Returns:
            A cryptography.x509.Certificate object.
        """
        try:
            return cryptography.x509.load_pem_x509_certificate(certificate_bytes, default_backend())
        except Exception:  # noqa: BLE001
            logger.error("Parsing certificate failed.")  # noqa: TRY400
            sys.exit(1)

    # utility methods

    @staticmethod
    def verify_signature(
        pubkey: primitives.asymmetric.dsa.DSAPublicKey
        | primitives.asymmetric.ed25519.Ed25519PublicKey
        | primitives.asymmetric.ed448.Ed448PublicKey
        | primitives.asymmetric.ec.EllipticCurvePublicKey
        | primitives.asymmetric.rsa.RSAPublicKey,
        signature: bytes,
        payload: bytes,
        hashalgo: primitives.hashes.HashAlgorithm,
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
            elif isinstance(
                pubkey,
                primitives.asymmetric.ec.EllipticCurvePublicKey,
            ):
                pubkey.verify(
                    signature=signature,
                    data=payload,
                    signature_algorithm=primitives.asymmetric.ec.ECDSA(hashalgo),
                )
            else:
                logger.error("The public key type is not supported, unable to verify signature, returning False")
                return False
        except cryptography.exceptions.InvalidSignature:  # type: ignore[attr-defined]
            logger.error("Got exception while verifying signature")  # noqa: TRY400
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
        print("pong")  # noqa: T201

    def show_acmeaccount_command(self) -> None:
        """Reply to the 'show acmeaccount' command to stdout.

        Args: None
        Returns: None
        """
        command = self.get_certbot_command(
            subcommand="show_account",
            challengetype="dns",
            csrpath=Path("/dev/null"),
            fullchainpath=Path("/dev/null"),
            certpath=Path("/dev/null"),
            chainpath=Path("/dev/null"),
        )
        logger.debug(f"running certbot command: {command}")
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603

        certbot_stdout, certbot_stderr = p.communicate()
        logger.debug(
            f"certbot command returned exit code {p.returncode}, with {len(certbot_stdout)} bytes "
            f"stdout and {len(certbot_stderr)} bytes stderr output"
        )

        if p.returncode == 0:
            for line in certbot_stdout.strip().decode("utf-8").split("\n"):
                print(line)  # noqa: T201
            sys.exit(0)
        else:
            logger.error("certbot command returned non-zero exit code")
            logger.error("certbot stderr:")
            for line in certbot_stderr.strip().decode("utf-8").split("\n"):
                logger.error(line)
            sys.exit(1)


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description="certgrinderd version {__version__}. See the manpage certgrinderd(8) or ReadTheDocs for more info."
    )

    # add topmost subparser for main command
    subparsers = parser.add_subparsers(help="Command (required)", dest="command", required=True)

    # "get" command
    get_parser = subparsers.add_parser("get", help='Use the "get" command to get certificates')
    get_subparsers = get_parser.add_subparsers(
        help="Specify what to get using one of the available get sub-commands",
        dest="subcommand",
        required=True,
    )

    # "get certificate" subcommand
    get_cert_parser = get_subparsers.add_parser("certificate", help="Get a new certificate. Requires a CSR.")
    get_cert_parser.set_defaults(method="get_certificate_command")

    # "show" command
    show_parser = subparsers.add_parser(
        "show",
        help='Use the "show" command to show configuration and ACME account info.',
    )
    show_subparsers = show_parser.add_subparsers(
        help="Specify what to show using one of the available show sub-commands",
        dest="subcommand",
        required=True,
    )

    # "show configuration" subcommand
    show_subparsers.add_parser("configuration", help="Tell certgrinderd to output the current configuration")

    # "show acmeaccount" subcommand
    show_acmeaccount_parser = show_subparsers.add_parser(
        "acmeaccount",
        help="Tell certgrinderd to output the ACME account URI (for example for use in CAA records)",
    )
    show_acmeaccount_parser.set_defaults(method="show_acmeaccount_command")

    # "help" command
    subparsers.add_parser("help", help='The "help" command just outputs the usage help')

    # "ping" command
    ping_parser = subparsers.add_parser(
        "ping",
        help='The "ping" command is used by the certgrinder client to verify connectivity to the server. '
        'It just outputs the word "pong" to stdout.',
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
        help="The preferred chain to use. Adds --preferred-chain to the Certbot command. Use to pick preferred "
        "signing chain when alternatives are available. Replace spaces with underscores in the chain name, "
        "so ISRG_Root_X1 for prod or Fake_LE_Root_X2 for staging.",
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
    mockargs: list[str] | None = None,
) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parse and return command-line args."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: list[str] | None = None) -> None:
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
        with Path(getattr(args, "config-file")).open() as f:
            try:
                config = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out.")
                sys.exit(1)
    else:
        # we have no config file
        config = {}

    # command line arguments override config file settings
    config.update(vars(args))

    # remove command, subcommand, and method from config (part of argparse internals)
    for key in ["command", "subcommand", "method"]:
        if key in config:
            del config[key]

    # create tempfile directory if needed
    kwargs = {"prefix": "certgrinderd-temp-"}
    if config.get("temp-dir"):
        kwargs["dir"] = config["temp-dir"]
    tempdir = tempfile.TemporaryDirectory(**kwargs)  # type: ignore[call-overload]
    config["temp-dir"] = tempdir.name

    # instantiate Certgrinderd class
    certgrinderd = Certgrinderd(userconfig=config)

    # if the command is "show configuration" just output certgrinder.conf and exit now
    if args.command == "show" and args.subcommand == "configuration":
        logger.info("Current certgrinderd configuration:")
        pprint(certgrinderd.conf)  # noqa: T203
        sys.exit(0)

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
