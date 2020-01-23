#!/usr/bin/env python
import yaml
import logging
import logging.handlers
import os
import sys
import subprocess
import tempfile
import typing
from pid import PidFile  # type: ignore

logger = logging.getLogger("certgrinderd.%s" % __name__)
__version__ = "0.13.0"


class Certgrinderd:
    """
    The main Certgrinder server class.
    """

    # default config
    conf: typing.Dict[str, typing.Union[str, bool, None]] = {
        "configfile": "~/certgrinderd.yml",
        "acmezone": "acme.example.com",
        "authhook": "manual-auth-hook",
        "certbotpath": "/usr/local/bin/certbot",
        "cleanuphook": "manual-cleanup-hook",
        "debug": False,
        "pidpath": "/tmp",
        "sudopath": "/usr/local/bin/sudo",
        "syslog_socket": "/var/run/log",
        "syslog_facility": "LOG_USER",
        "tempdir": "/tmp",
        "test": False,
        "webroot": "/usr/local/www/wwwroot",
    }

    def __init__(self, config: typing.Dict[str, typing.Union[str, bool, None]]) -> None:
        """
        Merge config with defaults
        """
        self.conf.update(config)
        logger.debug("Running with config: %s" % self.conf)

    def process_csr(self) -> None:
        """
        Loop over challenge types and run Certbot for each until we get a cert.
        """
        # put the certbot env together
        env = {
            "ACMEZONE": str(self.conf["acmezone"]),
            "WEBROOT": str(self.conf["webroot"]),
        }

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
            certfh, certpath = tempfile.mkstemp(**kwargs)  # type: ignore

            # put the command together
            command: typing.List[str] = [
                str(self.conf["sudopath"]),
                str(self.conf["certbotpath"]),
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
                str(certpath),
            ]
            logger.debug("Running Certbot command: {command.join(' ')}")

            # call certbot
            p = subprocess.run(command, capture_output=True, env=env)

            if p.returncode == 0:
                logger.info(
                    f"Success. Certbot wrote {os.path.getsize(certpath)} bytes chain to {certpath} - sending to stdout and cleaning up temp files"
                )
                with open(certpath) as f:
                    print(f.read())
                # no need to try more challenges, we have a cert
                break
            else:
                logger.error(
                    f"Failed to get a certificate using challenge type {challengetype}. Certbot exit code was {p.returncode}. Certbot output was:"
                )
                logger.error(p.stderr)


if __name__ == "__main__":
    """
    Main method. Read config and configure logging.
    Then get CSR from stdin and call Certbot once for each challenge type.
    """
    with open("~/certgrinderd.yml", "r") as f:
        try:
            config = yaml.load(f, Loader=yaml.SafeLoader)
            logger.debug("Loaded config from file: %s" % config)
        except Exception:
            logger.exception(
                "Unable to read config file ~/certgrinderd.yml, bailing out."
            )
            sys.exit(1)

    # instantiate Certgrinderd class
    certgrinderd = Certgrinderd(config=config)

    # connect to syslog?
    if certgrinderd.conf["syslog_socket"] and certgrinderd.conf["syslog_facility"]:
        facility: int = getattr(
            logging.handlers.SysLogHandler, str(certgrinderd.conf["syslog_facility"])
        )
        syslog_handler = logging.handlers.SysLogHandler(
            address=str(certgrinderd.conf["syslog_socket"]), facility=facility
        )
        syslog_format = logging.Formatter("certgrinderd: %(message)s")
        syslog_handler.setFormatter(syslog_format)
        try:
            logger.addHandler(syslog_handler)
        except Exception:
            logger.exception(
                f"Unable to connect to syslog socket {certgrinderd.conf['syslog_socket']} - syslog not enabled. Exception info below:"
            )
            sys.exit(1)

    # write pidfile in context
    with PidFile(piddir=certgrinderd.conf["pidpath"]) as pidfile:
        logger.info(f"certgrinderd {__version__} running with pid {pidfile}")

        stdin = sys.stdin.read()
        csrfd, csrpath = tempfile.mkstemp(
            suffix=".csr", prefix="certgrinderd-", dir=str(certgrinderd.conf["tempdir"])
        )
        with os.fdopen(csrfd) as csrfh:
            csrfh.write(stdin)
        logger.info(
            f"Got {len(stdin)} bytes CSR from client {os.environ['SSH_CLIENT']} saved to {csrpath} (debug mode: {certgrinderd.conf['test']})"
        )

        # TODO: use cryptography or openssl to check if the CSR is valid before calling certbot

        # TODO: check if the list of names are permitted for this SSH key

        # alright, get the cert for this CSR
        certgrinderd.process_csr()

        # clean up temp files
        if os.path.exists(str(certgrinderd.conf["csrpath"])):
            os.remove(str(certgrinderd.conf["csrpath"]))
        # TODO: this might fail since certbot runs as root..
        if os.path.exists(str(certgrinderd.conf["certpath"])):
            os.remove(str(certgrinderd.conf["certpath"]))

        logger.info("All done, certgrinderd exiting cleanly.")
