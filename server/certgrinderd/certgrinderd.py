#!/usr/bin/env python
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
__version__ = "0.13.0-alpha2"


class Certgrinderd:
    """
    The main Certgrinder server class.
    """

    # default config
    conf: typing.Dict[str, typing.Union[str, bool, None]] = {
        "configfile": "~/certgrinderd.yml",
        "acmezone": "acme.example.com",
        "authhook": "manual-auth-hook",
        "certbot_command": "/usr/local/bin/sudo /usr/local/bin/certbot",
        "cleanuphook": "manual-cleanup-hook",
        "debug": False,
        "pidpath": "/tmp",
        "syslog_socket": None,
        "syslog_facility": None,
        "tempdir": "/tmp",
        "test": False,
        "webroot": "/usr/local/www/wwwroot",
        "acmeserver_url": None,
        "verify_acmeserver_cert": True,
        "certbot_configdir": None,
        "certbot_workdir": None,
        "certbot_logsdir": None,
    }

    def __init__(self, config: typing.Dict[str, typing.Union[str, bool, None]]) -> None:
        """
        Merge config with defaults and connect to syslog
        """
        self.conf.update(config)

        # connect to syslog?
        if self.conf["syslog_socket"] and self.conf["syslog_facility"]:
            facility: int = getattr(
                logging.handlers.SysLogHandler, str(self.conf["syslog_facility"])
            )
            syslog_handler = logging.handlers.SysLogHandler(
                address=str(self.conf["syslog_socket"]), facility=facility
            )
            syslog_format = logging.Formatter("certgrinderd: %(message)s")
            syslog_handler.setFormatter(syslog_format)
            try:
                logger.addHandler(syslog_handler)
            except Exception:
                logger.exception(
                    f"Unable to connect to syslog socket {self.conf['syslog_socket']} - syslog not enabled. Exception info below:"
                )
                sys.exit(1)

        logger.info(f"certgrinderd {__version__} running")
        logger.debug("Running with config: %s" % self.conf)

    def load_csr(self, csrstring: str = "") -> None:
        """ Parses the CSR using cryptography.x509.load_pem_x509_csr(), write to disk, returns the object """
        if not csrstring:
            # get the CSR from stdin
            csrstring = sys.stdin.read()

        # get temp path for the csr so we can save it to disk
        csrfd, self.csrpath = tempfile.mkstemp(
            suffix=".csr", prefix="certgrinderd-", dir=str(self.conf["tempdir"])
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
        env.update(
            {
                "ACMEZONE": str(self.conf["acmezone"]),
                "WEBROOT": str(self.conf["webroot"]),
            }
        )

        # loop over challengetypes and run certbot for each
        for challengetype in ["dns", "http"]:
            if challengetype == "dns" and not self.conf["acmezone"]:
                logger.info(
                    "Not attempting challenge type DNS-01 because self.conf['acmezone'] is unset"
                )
                continue

            # Create a temp file for the signed certificate
            kwargs = {
                "suffix": ".crt",
                "prefix": "certgrinderd-",
                "dir": str(self.conf["tempdir"]),
            }
            # ignore in mypy for now https://github.com/python/typeshed/issues/3449
            # get a temp path for the full chain (meaning intermediate+cert)
            fullchainfh, fullchainpath = tempfile.mkstemp(**kwargs)  # type: ignore
            os.unlink(fullchainpath)
            # get a temp path for the chain (meaning intermediate only)
            chainfh, chainpath = tempfile.mkstemp(**kwargs)  # type: ignore
            os.unlink(chainpath)
            # get a temp path for the cert
            certfh, certpath = tempfile.mkstemp(**kwargs)  # type: ignore
            os.unlink(certpath)

            # put the command together
            command: typing.List[str] = [
                str(self.conf["certbot_command"]),
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
                str(self.conf["authhook"]),
                "--manual-cleanup-hook",
                str(self.conf["cleanuphook"]),
                "--manual-public-ip-logging-ok",
                "--csr",
                str(csrpath),
                "--fullchain-path",
                str(fullchainpath),
                "--cert-path",
                str(certpath),
                "--chain-path",
                str(chainpath),
                "--agree-tos",
                "--email",
                str(self.conf["acme_email"]),
            ]

            if self.conf["acmeserver_url"]:
                command.append("--server")
                command.append(str(self.conf["acmeserver_url"]))

            if not self.conf["verify_acmeserver_cert"]:
                command.append("--no-verify-ssl")

            if self.conf["certbot_configdir"]:
                command.append("--config-dir")
                command.append(str(self.conf["certbot_configdir"]))

            if self.conf["certbot_workdir"]:
                command.append("--work-dir")
                command.append(str(self.conf["certbot_workdir"]))

            if self.conf["certbot_logsdir"]:
                command.append("--logs-dir")
                command.append(str(self.conf["certbot_logsdir"]))

            logger.debug(f"Running Certbot command: {' '.join(command)}")

            # call certbot
            p = subprocess.run(command, capture_output=True, env=env)

            if p.returncode == 0:
                logger.info(
                    f"Success. Certbot wrote {os.path.getsize(fullchainpath)} bytes chain to {fullchainpath} - sending to stdout and cleaning up temp files"
                )
                with open(fullchainpath) as f:
                    print(f.read())
                os.unlink(certpath)
                os.unlink(chainpath)
                os.unlink(fullchainpath)
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
    Main function. Read config and configure logging.
    Then get CSR from stdin and call Certbot once for each challenge type.
    """
    # get config path from commandline or use default
    if len(sys.argv) == 2:
        configpath = sys.argv[1]
    else:
        configpath = "~/certgrinderd.yml"

    # read and parse the config
    with open(configpath, "r") as f:
        try:
            config = yaml.load(f, Loader=yaml.SafeLoader)
            logger.debug("Loaded config from file: %s" % config)
        except Exception:
            logger.exception(f"Unable to read config file {configpath} - bailing out.")
            sys.exit(1)

    # instantiate Certgrinderd class
    certgrinderd = Certgrinderd(config=config)
    certgrinderd.grind()

    # we are done here
    logger.info("All done, certgrinderd exiting cleanly.")


if __name__ == "__main__":
    main()
