#!/usr/bin/env python
"""Certgrinderd v0.13.2 module.

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

import cryptography.x509
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import x509  # type: ignore

logger = logging.getLogger("certgrinderd.%s" % __name__)
__version__ = "0.13.2"


class Certgrinderd:
    """The Certgrinderd server class."""

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
        self.conf: typing.Dict[str, typing.Union[str, bool, None]] = {
            "acme-email": None,
            "acme-server-url": "https://acme-v02.api.letsencrypt.org/directory",
            "acme-zone": None,
            "auth-hook": "manual-auth-hook.sh",
            "certbot-command": "/usr/local/bin/sudo /usr/local/bin/certbot",
            "certbot-config-dir": None,
            "certbot-logs-dir": None,
            "certbot-work-dir": None,
            "cleanup-hook": "manual-cleanup-hook.sh",
            "config-file": None,
            "debug": False,
            "log-level": "INFO",
            "pid-dir": "/tmp",
            "skip-acme-server-cert-verify": False,
            "syslog-facility": None,
            "syslog-socket": None,
            "temp-dir": None,
            "web-root": None,
        }

        if userconfig:
            self.conf.update(userconfig)

        # define the log format used for stdout depending on the requested loglevel
        if self.conf["log-level"] == "DEBUG":
            console_logformat = "%(asctime)s certgrinderd %(levelname)s Certgrinderd.%(funcName)s():%(lineno)i:  %(message)s"
        else:
            console_logformat = "%(asctime)s certgrinderd %(levelname)s: %(message)s"

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
        logger.debug("Running with config: %s" % self.conf)

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
            csrstring = sys.stdin.read()

        # parse and return the csr
        return cryptography.x509.load_pem_x509_csr(
            csrstring.encode("ascii"), default_backend()
        )

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

        # domainsets is a semicolon-seperated list of comma-seperated domainsets.
        # loop over domainsets until we find a match and break out, or hit the else
        # if we never find a domainset covering all names in the CSR
        for domainset in allowed_names.split(";"):
            if cn not in domainset.split(","):
                # cert CN is not in this domainset
                continue
            # loop over SubjectAltNames and check if each is present in domainset,
            # break out of the loop if a name is not in the domainset
            for san in san_list:
                if san not in domainset.split(","):
                    # this name is not in this domainset, no need to keep checking
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
                f"CSR contains one or more names which are not permitted for this client. Permitted names: {allowed_names}"
            )
            return False

        # all good
        return True

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
            fullchainpath: The path to save the certificate+intermediate
            certpath: The path to save the certificate (without intermediate)
            chainpath: The path to save the intermediate (without certificate)

        Returns:
            The certbot command as a list
        """
        command: typing.List[str] = str(self.conf["certbot-command"]).split(" ") + [
            "certonly",
            "--non-interactive",
            "--quiet",
            "--rsa-key-size",
            "4096",
            "--authenticator",
            "manual",
            "--preferred-challenges",
            challengetype,
            "--manual-auth-hook",
            str(self.conf["auth-hook"]),
            "--manual-cleanup-hook",
            str(self.conf["cleanup-hook"]),
            "--manual-public-ip-logging-ok",
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
            logger.debug(f"Attempting HTTP-01 with zone {self.conf['web-root']} ...")
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

        Do not log an error message regardless of Certbot exitcode. The calling method
        will take care of that.

        Args:
            command: A list of certbot command elements
            env: A dictionary of the environment to pass to subprocess.run()
            fullchainpath: The path to read the certificate+chain from after Certbot runs

        Returns:
            True if Certbot command exitcode was 0, False otherwise
        """
        # call certbot
        logger.debug(f"Running certbot command with env {env}: {command}")
        p = subprocess.run(command, capture_output=True, env=env)
        if p.returncode == 0:
            # success, output chain to stdout
            with open(str(fullchainpath)) as f:
                print(f.read())
            return True
        else:
            logger.error("certbot command returned non-zero exit code")
            return False

    def grind(self) -> None:
        """Load the CSR, use it to get a certificate, and cleanup.

        Calls ``self.parse_csr()`` followed by ``self.check_csr()``, and then exists if any
        problems are found with the CSR.

        Then ``self.get_certificate()`` is called, which in turn calls Certbot, which writes
        the certificate to stdout.

        Finally the CSR is deleted.

        Returns:
            None
        """
        # get the CSR from stdin
        csr = self.parse_csr()

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


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description="certgrinderd version %s. See the README.md file for more info."
        % __version__
    )
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
        "-f",
        "--config-file",
        dest="config-file",
        help="The path to the certgrinderd config file to use, in YML format.",
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
    mockargs: typing.Optional[typing.List[str]] = None
) -> argparse.Namespace:
    """Parse and return command-line args."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return args


def main(mockargs: typing.Optional[typing.List[str]] = None) -> None:
    """Make the neccesary preparations before calling Certgrinderd.grind().

    - Read config from file and/or commandline args
    - Configure temporary paths
    - Configure logging

    Finally instantiate the Certgrinderd class with the config and grind()

    Args:
        None

    Returns:
        None
    """
    # get commandline arguments
    args = parse_args(mockargs)

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

    # create tempfile directory if needed
    kwargs = {"prefix": "certgrinderd-temp-"}
    if "temp-dir" in config and config["temp-dir"]:
        kwargs["dir"] = config["temp-dir"]
    tempdir = tempfile.TemporaryDirectory(**kwargs)
    config["temp-dir"] = tempdir.name

    # all good
    try:
        # instantiate Certgrinderd class
        certgrinderd = Certgrinderd(userconfig=config)
        certgrinderd.grind()
    finally:
        tempdir.cleanup()

    # we are done here
    logger.info("All done, certgrinderd exiting cleanly.")


if __name__ == "__main__":
    main()
