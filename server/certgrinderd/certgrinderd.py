#!/usr/bin/env python
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import x509  # type: ignore

logger = logging.getLogger("certgrinderd.%s" % __name__)
__version__ = "0.13.0-alpha7"


class Certgrinderd:
    """
    The main Certgrinder server class.
    """

    # default config
    conf: typing.Dict[str, typing.Union[str, bool, None]] = {
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
        "staging": False,
        "syslog-facility": None,
        "syslog-socket": None,
        "temp-dir": None,
        "web-root": None,
    }

    def __init__(
        self, userconfig: typing.Dict[str, typing.Union[str, bool, None]]
    ) -> None:
        """
        Merge userconfig with defaults and configure logging
        """
        self.conf.update(userconfig)

        # define the log format used for stdout depending on the requested loglevel
        if self.conf["log-level"] == "DEBUG":
            console_logformat = "%(asctime)s %(levelname)s %(name)s:%(funcName)s():%(lineno)i:  %(message)s"
        else:
            console_logformat = "%(asctime)s %(levelname)s: %(message)s"

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
            try:
                logger.addHandler(syslog_handler)
            except Exception:
                logger.exception(
                    f"Unable to connect to syslog socket {self.conf['syslog-socket']} - syslog not enabled. Exception info below:"
                )
                sys.exit(1)
        else:
            logger.debug("Not configuring syslog")

        logger.info(f"certgrinderd {__version__} running")
        logger.debug("Running with config: %s" % self.conf)

    def load_csr(self, csrstring: str = "") -> None:
        """ Parses the CSR using cryptography.x509.load_pem_x509_csr(), write to disk, returns the object """
        if not csrstring:
            # get the CSR from stdin
            csrstring = sys.stdin.read()

        # get temp path for the csr so we can save it to disk
        csrfd, self.csrpath = tempfile.mkstemp(
            suffix=".csr", prefix="certgrinderd-", dir=str(self.conf["temp-dir"])
        )
        # save the csr to disk
        with os.fdopen(csrfd, "w") as csrfh:
            csrfh.write(csrstring)

        # parse the csr
        self.csr = cryptography.x509.load_pem_x509_csr(
            csrstring.encode("ascii"), default_backend()
        )

    def check_csr(self, csr: x509._CertificateSigningRequest) -> None:
        """ Check that this CSR is valid, all things considered """
        # get the list of allowed names from env
        allowed_names = os.environ.get("CERTGRINDERD_DOMAINSETS", None)
        if not allowed_names:
            logger.error(
                "Environment var CERTGRINDERD_DOMAINSETS not found, bailing out"
            )
            sys.exit(1)

        # get CommonName from CSR
        cn_list = csr.subject.get_attributes_for_oid(
            cryptography.x509.oid.NameOID.COMMON_NAME
        )
        if len(cn_list) != 1:
            # we have more or less than one CN, fuckery is afoot
            logger.error("CSR is not valid (has more or less than 1 CN), bailing out")
            sys.exit(1)
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
            sys.exit(1)

        # loop over domainsets until we find a match
        for domainset in allowed_names.split(";"):
            if cn not in domainset.split(","):
                # cert CN is not in this domainset
                continue
            for san in san_list:
                if san not in domainset.split(","):
                    # this name is not in this domainset
                    continue
            # all names in the CSR are permitted for this client
            break
        else:
            # this CSR contains names which are not permitted for this client
            logger.error(
                f"CSR contains one or more names which are not permitted for this client. Permitted names: {allowed_names}"
            )
            sys.exit(1)

    def process_csr(self, csrpath: str) -> None:
        """ Loop over challenge types and run Certbot for each until we get a cert """
        # put the certbot env together
        env = os.environ.copy()
        if self.conf["acme-zone"]:
            env.update({"ACMEZONE": str(self.conf["acme-zone"])})
        if self.conf["web-root"]:
            env.update({"WEBROOT": str(self.conf["web-root"])})

        # get temp paths for certbot
        fullchainpath = os.path.join(str(self.conf["temp-dir"]), "fullchain.pem")
        certpath = os.path.join(str(self.conf["temp-dir"]), "certificate.pem")
        chainpath = os.path.join(str(self.conf["temp-dir"]), "chain.pem")

        # loop over challengetypes and run certbot for each
        for challengetype in ["dns", "http"]:
            # put the certbot command together
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
                str(csrpath),
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

            if self.conf["staging"]:
                command.append("--staging")

            logger.debug(f"Running Certbot command: {' '.join(command)}")

            # call certbot
            p = subprocess.run(command, capture_output=True, env=env)

            if p.returncode == 0:
                logger.info(
                    f"Success. Certbot wrote {os.path.getsize(str(fullchainpath))} bytes chain to {fullchainpath} - sending to stdout and cleaning up temp files"
                )
                with open(str(fullchainpath)) as f:
                    print(f.read())
                # no need to try more challenges, we have a cert
                break
            else:
                logger.error(
                    f"Failed to get a certificate using challenge type {challengetype}. Certbot exit code was {p.returncode}. Certbot output was:"
                )
                logger.error(p.stderr.strip().decode("utf-8"))

    def grind(self) -> None:
        """ Primary method, load the CSR, process it, and cleanup """
        # get the CSR
        self.load_csr()

        # check CSR creaminess
        self.check_csr(self.csr)

        # alright, get the cert for this CSR
        self.process_csr(self.csrpath)

        # clean up temp files
        if os.path.exists(self.csrpath):
            os.remove(self.csrpath)


def main() -> None:
    """
    Main function. Read config from file and/or commandline args.
    Configure temporary path and configure logging.
    Then instantiate the Certgrinderd class with the config and grind()
    """
    # parse commandline arguments
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
        help="The url for the ACME server to use",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--acme-zone",
        dest="acme-zone",
        help="The DNS zone to pass to the auth hook script as env. var. ACMEZONE. For DNS-01 challenges.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
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
        "-S",
        "--staging",
        dest="staging",
        action="store_true",
        help="Staging mode. Make Certbot use LetsEncrypt staging servers",
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
        "--temp-dir",
        dest="temp-dir",
        help="The directory to store temporary files in",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--web-root",
        dest="web-root",
        help="The path to pass to the auth hook script as env WEBROOT to use for HTTP-01 challenges.",
        default=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    # read and parse the config file
    if hasattr(args, "config-file"):
        with open(getattr(args, "config-file"), "r") as f:
            try:
                config = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(
                    f"Unable to read config file {getattr(args, 'config-file')} - bailing out."
                )
                sys.exit(1)
    else:
        # we have no config file
        config = {}

    # command line arguments override config file settings
    config.update(vars(args))

    # create tempfile directory if needed
    if hasattr(config, "temp-dir") and config["temp-dir"]:
        tempdir = tempfile.TemporaryDirectory(
            prefix="certgrinderd-temp-", dir=config["temp-dir"]
        )
    else:
        tempdir = tempfile.TemporaryDirectory(prefix="certgrinderd-temp-")
    config["temp-dir"] = tempdir.name

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
