#!/usr/bin/env python
import yaml
import logging
import logging.handlers
import os
import sys
import subprocess
import tempfile
import typing

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
        Merge config with defaults
        """
        self.conf.update(config)
        logger.debug("Running with config: %s" % self.conf)

    def process_csr(self, csrpath: str) -> None:
        """
        Loop over challenge types and run Certbot for each until we get a cert.
        """
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
                str(certpath),
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
                    f"Success. Certbot wrote {os.path.getsize(certpath)} bytes chain to {certpath} - sending to stdout and cleaning up temp files"
                )
                with open(certpath) as f:
                    print(f.read())
                # TODO: this might fail since certbot runs as root..
                os.remove(certpath)
                # no need to try more challenges, we have a cert
                break
            else:
                logger.error(
                    f"Failed to get a certificate using challenge type {challengetype}. Certbot exit code was {p.returncode}. Certbot output was:"
                )
                logger.error(p.stderr.strip().decode("utf-8"))


def main(configpath: str) -> None:
    """
    Main function. Read config and configure logging.
    Then get CSR from stdin and call Certbot once for each challenge type.
    """
    with open(configpath, "r") as f:
        try:
            config = yaml.load(f, Loader=yaml.SafeLoader)
            logger.debug("Loaded config from file: %s" % config)
        except Exception:
            logger.exception(f"Unable to read config file {configpath} - bailing out.")
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

    logger.info(f"certgrinderd {__version__} running")

    stdin = sys.stdin.read()
    csrfd, csrpath = tempfile.mkstemp(
        suffix=".csr", prefix="certgrinderd-", dir=str(certgrinderd.conf["tempdir"])
    )
    with os.fdopen(csrfd, "w") as csrfh:
        csrfh.write(stdin)

    # logger.info(f"Got {len(stdin)} bytes CSR from client {os.environ['SSH_CLIENT']} saved to {csrpath} (debug mode: {certgrinderd.conf['test']})")

    # TODO: use cryptography or openssl to check if the CSR is valid before calling certbot

    # TODO: check if the list of names are permitted for this SSH key

    # alright, get the cert for this CSR
    certgrinderd.process_csr(csrpath)

    # clean up temp files
    if os.path.exists(csrpath):
        os.remove(csrpath)

    logger.info("All done, certgrinderd exiting cleanly.")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        configpath = sys.argv[1]
    else:
        configpath = "~/certgrinderd.yml"

    # call the main method
    main(configpath=configpath)
