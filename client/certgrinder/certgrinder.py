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
import typing
from datetime import datetime

import cryptography.x509
import dns.resolver  # type: ignore
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.backends.openssl import x509  # type: ignore

logger = logging.getLogger("certgrinder.%s" % __name__)
__version__ = "0.13.0-alpha3"


class Certgrinder:
    """
    The main Certgrinder client class.
    """

    def __init__(
        self,
        configfile: str,
        staging: bool,
        showtlsa: str,
        checktlsa: str,
        nameserver: str,
        showspki: bool,
        debug: bool,
        check: bool,
    ) -> None:
        """
        The __init__ method just reads the config file and checks a few things
        """
        if not self.read_config(configfile):
            sys.exit(1)

        if "domainlist" not in self.conf:
            logger.error("domainlist not found in conf")
            sys.exit(1)

        # syslog related defaults
        if "syslog_facility" not in self.conf:
            self.conf["syslog_facility"] = "user"
        if "syslog_socket" not in self.conf:
            self.conf["syslog_socket"] = "/var/run/log"

        # initialise variables
        self.hook_needed: bool = False
        self.staging = staging
        self.showtlsa = showtlsa
        self.checktlsa = checktlsa
        self.nameserver = nameserver
        self.showspki = showspki
        self.debug = debug
        self.check: bool = check
        self.tlsatypes: typing.List[typing.Tuple[int, int, int]] = [
            (3, 1, 0),
            (3, 1, 1),
            (3, 1, 2),
        ]
        self.__version__ = __version__

    def read_config(self, configfile: str) -> bool:
        """
        Actually reads and parses the yaml config file
        """
        with open(configfile, "r") as f:
            try:
                self.conf = yaml.load(f, Loader=yaml.SafeLoader)
                logger.debug("Running with config: %s" % self.conf)
                return True
            except Exception:
                logger.exception("Unable to read config")
                return False

    # RSA KEY METHODS

    def load_keypair(self) -> openssl.rsa._RSAPrivateKey:
        """
        Checks if the keypair file exists on disk, and calls self.create_keypair() if not
        """
        if os.path.exists(self.keypair_path):
            # check permissions for self.keypair_path
            if oct(os.stat(self.keypair_path).st_mode)[4:] != "640":
                logger.debug(
                    "keypair %s has incorrect permissions, fixing to 640..."
                    % self.keypair_path
                )
                os.chmod(self.keypair_path, 0o640)

            # read keypair
            keypair_bytes = open(self.keypair_path, "rb").read()

            # parse keypair
            self.keypair = primitives.serialization.load_pem_private_key(
                keypair_bytes, password=None, backend=default_backend()
            )
        else:
            logger.debug(
                "keypair %s not found, creating new keypair..." % self.keypair_path
            )
            self.create_keypair()
        return self.keypair

    def create_keypair(self) -> None:
        """
        Generates an RSA keypair in self.keypair and calls self.save_keypair() to write it to disk
        """
        self.keypair = primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        self.save_keypair()

    def save_keypair(self) -> None:
        """
        Saves RSA keypair in self.keypair to disk in self.keypair_path
        """
        with open(self.keypair_path, "wb") as f:
            f.write(
                self.keypair.private_bytes(
                    encoding=primitives.serialization.Encoding.PEM,
                    format=primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=primitives.serialization.NoEncryption(),
                )
            )
        os.chmod(self.keypair_path, 0o640)
        logger.debug("saved keypair to %s" % self.keypair_path)

    def get_der_pubkey(self) -> bytes:
        """
        Returns the DER format public key
        """
        return self.keypair.public_key().public_bytes(  # type: ignore
            encoding=primitives.serialization.Encoding.DER,
            format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # CSR METHODS

    def generate_csr(
        self, domains: typing.List[str]
    ) -> x509._CertificateSigningRequest:
        """
        Generates a new CSR in self.csr based on the public key in self.keypair.
        Only sets CN since everything else is removed by LetsEncrypt in the certificate anyway.
        Add all domains in subjectAltName, including the one put into CN.
        Finally call self.save_csr() to write it to disk.
        """
        domainlist = []
        # build list of cryptography.x509.DNSName objects for SAN
        for domain in domains:
            domain = domain.encode("idna").decode("utf-8")
            logger.debug("Adding %s to CSR..." % domain)
            domainlist.append(cryptography.x509.DNSName(domain))

        # build the CSR
        self.csr = (
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
                cryptography.x509.SubjectAlternativeName(domainlist),  # type: ignore
                critical=False,
            )
            .sign(self.keypair, primitives.hashes.SHA256(), default_backend())
        )

        # write the csr to disk
        self.save_csr()
        return self.csr

    def save_csr(self) -> None:
        """
        Save the PEM version of the CSR to the path in self.csr_path
        """
        with open(self.csr_path, "wb") as f:
            f.write(self.csr.public_bytes(primitives.serialization.Encoding.PEM))
        os.chmod(self.csr_path, 0o644)
        logger.debug("saved CSR to %s" % self.csr_path)

    # CERTIFICATE METHODS

    def load_certificate(self) -> typing.Any:
        """
        Reads PEM certificate from the path in self.certificate_path
        """
        self.certificate: typing.Any
        if os.path.exists(self.certificate_path):
            pem_data = open(self.certificate_path, "rb").read()
            self.certificate = cryptography.x509.load_pem_x509_certificate(
                pem_data, default_backend()
            )
        else:
            logger.debug("certificate %s not found" % self.certificate_path)
            self.certificate = False
        return self.certificate

    def check_certificate_validity(self) -> bool:
        """
        Checks the validity of the certificate.
        Returns a simpe True or False based on self.conf['cert_renew_threshold_days'],
        and whether the certificate is valid (ie. not selfsigned)
        """
        if self.certificate is False:
            return False

        # check if selfsigned
        if self.certificate.issuer == self.certificate.subject:
            logger.debug(
                "This certificate is selfsigned, check_certificate_validity() returning False"
            )
            return False

        # check if issued by staging
        for x in self.certificate.issuer:
            if (
                x.oid == cryptography.x509.oid.NameOID.COMMON_NAME
                and x.value == "Fake LE Intermediate X1"
            ):
                logger.debug(
                    "This certificate was issued by LE staging CA, check_certificate_validity() returning False"
                )
                return False

        # check expiration, find the timedelta between now and the expire_date
        expiredelta = self.certificate.not_valid_after - datetime.now()
        if expiredelta.days < self.conf["cert_renew_threshold_days"]:
            logger.debug(
                "Less than %s days to expiry of certificate, check_certificate_validity() returning False"
                % self.conf["cert_renew_threshold_days"]
            )
            return False
        else:
            logger.debug(
                "More than %s days to expiry of certificate, check_certificate_validity() returning True"
                % self.conf["cert_renew_threshold_days"]
            )
            return True

    def get_new_certificate(self) -> bool:
        """
        cat the csr over ssh to the certgrinder server.
        """
        logger.info("ready to get signed certificate using csr %s" % self.csr_path)

        command = self.conf["certgrinderd"]
        if self.staging:
            command += " staging"

        # make command a list
        logger.debug("running ssh command: %s" % command)
        commandlist = [x for x in command.split(" ") if x]
        p = subprocess.Popen(
            commandlist,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # send the CSR to stdin and save stdout+stderr
        stdout, stderr = p.communicate(
            input=self.csr.public_bytes(primitives.serialization.Encoding.PEM)
        )

        # parse stdout (which should now contain a valid signed PEM certificate)
        try:
            self.certificate = cryptography.x509.load_pem_x509_certificate(
                stdout, default_backend()
            )
        except Exception as E:
            logger.error(
                "The Certgrinder server did not return a valid certificate. Exception: %s"
                % E
            )

            # output some more if we are in debug mode
            if self.debug:
                logger.debug(
                    "This was the exception encountered while trying to parse the certificate:"
                )
                logger.debug(E, exc_info=True)
                # output stdout (if any)
                if stdout:
                    logger.debug("This is stdout from the ssh call:")
                    logger.debug(stdout.strip().decode("utf-8"))
                # output stderr (if any)
                if stderr:
                    logger.debug("this is stderr from the ssh call:")
                    logger.debug(stderr.strip().decode("utf-8"))
            else:
                logger.error(
                    "Rerun in debug mode (-d / --debug) to see more information, or check the log on the Certgrinder server"
                )

            # we dont have a certificate
            return False

        # a few sanity checks of the certificate seems like a good idea
        if not self.check_certificate_sanity():
            return False

        # save cert to disk, pass stdout to maintain chain,
        # as self.certificate only contains the server cert,
        # not LE intermediate
        self.save_certificate(stdout)

        # make a concat'ed version of the key+cert for applications that want that
        if self.concat_certkey():
            logger.debug("saved concat'ed privkey+chain to %s" % self.concat_path)
        else:
            logger.error(
                "was unable to save concat'ed version of privkey+chain to %s"
                % self.concat_path
            )

        # we have saved a new certificate, so we will need to run the post renew hook later
        self.hook_needed = True

        return True

    def check_certificate_sanity(self) -> bool:
        """
        Performs a few sanity checks of the certificate obtained from the certgrinder server:
        - checks that the public key is correct
        - checks that the subject is correct
        - checks that the SubjectAltName data is correct (TODO)
        Return False if a problem is found, True if all is well
        """
        # check self.certificate has the same pubkey as the CSR
        if self.keypair.public_key().public_bytes(
            encoding=primitives.serialization.Encoding.PEM,
            format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != self.certificate.public_key().public_bytes(
            encoding=primitives.serialization.Encoding.PEM,
            format=primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            logger.error(
                "The certificate returned from the certgrinder server does not have the public key we expected"
            )
            return False

        # check if certificate has the same subject as our CSR (which is CN only)
        if self.certificate.subject != self.csr.subject:
            logger.error(
                "The certificate returned from the certgrinder server does not have the same subject (%s) as our CSR has (%s)"
                % (self.certificate.subject, self.csr.subject)
            )
            return False

        # TODO: check if the certificates SubjectAltName contains all the domains our CSR has,
        # we cannot just compare the extension data because letsencrypt may change the order of the domains,
        # so we have to parse the ASN.1 data and loop over both sets of domains and compare.. sigh

        # all good
        return True

    def save_certificate(self, stdout: bytes) -> None:
        """
        Save the PEM certificate in stdout to the path self.certificate_path
        """
        # save the file
        with open(self.certificate_path, "wb") as f:
            f.write(stdout)
        os.chmod(self.certificate_path, 0o644)
        logger.info("saved new certificate chain to %s" % self.certificate_path)

    def concat_certkey(self) -> bool:
        """
        Creates a single file with the private key and the cert chain, in that order
        Maybe catch some errors and return False somewhere here
        """
        with open(self.concat_path, "wb") as concat:
            with open(self.keypair_path, "rb") as infile:
                concat.write(infile.read())
            with open(self.certificate_path, "rb") as infile:
                concat.write(infile.read())
        os.chmod(self.concat_path, 0o640)
        return True

    # POST RENEW HOOK METHOD

    def run_post_renew_hooks(self) -> bool:
        """
        Loops over configured post_renew_hooks and runs them with sudo.
        The path for sudo defaults to /usr/local/bin/sudo but can be set in the config file
        """
        if "post_renew_hooks" not in self.conf or not self.conf["post_renew_hooks"]:
            logger.debug("no self.conf['post_renew_hooks'] found, not doing anything")
            return True

        for hook in self.conf["post_renew_hooks"]:
            logger.debug("Running post renew hook (with sudo): %s" % hook)
            if "sudo_path" in self.conf:
                sudo_path = self.conf["sudo_path"]
            else:
                # default sudo path
                sudo_path = "/usr/local/bin/sudo"

            # run with sudo
            p = subprocess.Popen([sudo_path] + hook.split(" "))
            exitcode = p.wait()

            if exitcode != 0:
                logger.error(
                    "Got exit code %s when running post_renew_hook %s"
                    % (exitcode, hook)
                )
            else:
                logger.debug("Post renew hook %s ended with exit code 0, good." % hook)

        # all done
        return True

    # SPKI METHODS

    def generate_spki(self, derkey: bytes) -> str:
        """
        Generates and returns an pin-sha256 spki hpkp style pin for the provided public key.
        OpenSSL equivalent command is:
        openssl x509 -in example.com.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64
        """
        return base64.b64encode(hashlib.sha256(derkey).digest()).decode("ASCII")

    def show_spki(self) -> None:
        """
        Get and print the spki pin for the public key
        """
        spki = self.generate_spki(self.get_der_pubkey())
        logger.info('pin-sha256="%s"' % spki)

    # TLSA METHODS

    def generate_tlsa(
        self, derkey: bytes, tlsatype: typing.Tuple[int, int, int]
    ) -> typing.Union[str, bool]:
        """
        Generates and returns the data part of a TLSA record of the requested type,
        based on the DER format public key supplied.
        """
        if tlsatype == (3, 1, 0):
            # Generate DANE-EE Publickey Full (3 1 0) TLSA Record
            return binascii.hexlify(derkey).decode("ASCII").upper()
        elif tlsatype == (3, 1, 1):
            # Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record
            return hashlib.sha256(derkey).hexdigest().upper()
        elif tlsatype == (3, 1, 2):
            # Generate DANE-EE Publickey SHA512 (3 1 2) TLSA Record
            return hashlib.sha512(derkey).hexdigest().upper()
        else:
            logger.error("Unsupported TLSA type: %s %s %s" % tlsatype)
        return False

    def lookup_tlsa(
        self, tlsatype: typing.Tuple[int, int, int], service: str, domain: str
    ) -> typing.Union[typing.List[str], bool]:
        """
        Lookup TLSA records in DNS for the given service and domain.
        loop over the responses and look for the requested tlsatype.
        Return a list of matching results or False if none were found.
        """
        try:
            if self.nameserver:
                logger.debug(
                    "Looking up TLSA record in DNS using DNS server %s: %s.%s %s"
                    % (self.nameserver, service, domain, tlsatype)
                )
                res = dns.resolver.Resolver(configure=False)
                res.nameservers = [self.nameserver]
            else:
                logger.debug(
                    "Looking up TLSA record in DNS using system resolver: %s.%s %s"
                    % (service, domain, tlsatype)
                )
                res = dns.resolver
            dnsresponse = res.query("%s.%s" % (service, domain), "TLSA")
        except dns.resolver.NXDOMAIN:
            logger.debug(
                "NXDOMAIN returned, no TLSA records found in DNS for: %s.%s"
                % (service, domain)
            )
            return False
        except dns.resolver.NoAnswer:
            logger.error(
                "Empty answer returned. No TLSA records found in DNS for: %s.%s"
                % (service, domain)
            )
            return False
        except dns.exception.SyntaxError:
            logger.error("Error parsing DNS server. Only IP addresses are supported.")
            exit(1)
        except dns.exception.Timeout:
            logger.error("Timeout while waiting for DNS server. Error.")
            exit(1)
        except Exception as E:
            logger.error("Exception received during DNS lookup: %s" % E)
            return False

        # loop over the responses
        result = []
        for reply in dnsresponse:
            # is this reply of the right type?
            replytype = "%s %s %s" % (reply.usage, reply.selector, reply.mtype)
            logger.debug("Found TLSA record type %s" % replytype)
            if " ".join(map(str, tlsatype)) == replytype:
                result.append(binascii.hexlify(reply.cert).decode("ASCII"))
        if result:
            logger.debug(
                "Returning %s TLSA records of type %s" % (len(result), tlsatype)
            )
        else:
            logger.debug(
                "TLSA records found, but none of the type %s %s %s were found"
                % tlsatype
            )
        return result

    def print_tlsa(self, service: str, domains: typing.List[str]) -> None:
        """
        Outputs the TLSA records for the given service and domain,
        as returned by self.generate_tlsa()
        """
        # get the public key in DER format
        derkey = self.get_der_pubkey()

        # loop over the domains and print the TLSA record values
        for domain in domains:
            logger.info("TLSA records for %s.%s:" % (service, domain))
            for tlsatype in self.tlsatypes:
                tlsadata = self.generate_tlsa(derkey, tlsatype)
                logger.info(
                    "%s.%s %s %s"
                    % (service, domain, " ".join(map(str, tlsatype)), tlsadata)
                )

    def check_tlsa(self, service: str, domains: typing.List[str]) -> None:
        """
        Loops over domains and checks the TLSA records in DNS.
        Outputs the data needed to add/fix records when errors are found.
        """
        # get the public key in DER format
        derkey = self.get_der_pubkey()

        # loop over the domains and fetch the TLSA records from the DNS,
        # and compare them to locally generated values
        for domain in domains:
            logger.info("Looking up TLSA records for %s.%s" % (service, domain))
            for tlsatype in self.tlsatypes:
                tlsastr = " ".join(map(str, tlsatype))
                dns_reply = self.lookup_tlsa(tlsatype, service, domain)
                if not isinstance(dns_reply, bool):
                    logger.debug(
                        "Received DNS response for TLSA type %s: %s answers - checking data..."
                        % (tlsastr, len(dns_reply))
                    )
                    # reply for this tlsatype found, check data
                    generated = self.generate_tlsa(derkey, tlsatype)
                    found = False
                    for reply in dns_reply:
                        if reply.upper() == generated:
                            logger.info(
                                "TLSA record for name %s.%s type %s found in DNS matches the local key, good."
                                % (service, domain, tlsastr)
                            )
                            found = True
                            break
                    if not found:
                        logger.warning(
                            "None of the TLSA records found in DNS for the name %s.%s of type %s match the local key. DNS needs to be updated:"
                            % (service, domain, tlsastr)
                        )
                        logger.warning(
                            "%s.%s %s %s"
                            % (
                                service,
                                domain,
                                tlsastr,
                                self.generate_tlsa(derkey, tlsatype),
                            )
                        )
                else:
                    logger.warning(
                        "No TLSA records for name %s.%s of type %s was found in DNS. This record needs to be added:"
                        % (service, domain, tlsastr)
                    )
                    logger.warning(
                        "%s.%s %s %s"
                        % (
                            service,
                            domain,
                            tlsastr,
                            self.generate_tlsa(derkey, tlsatype),
                        )
                    )

    # MAIN METHODS
    def main(self) -> None:
        """
        Loop over sets of domains in the config and call self.grind() for each.
        """
        # loop over domains
        logger.info("Certgrinder %s running" % __version__)
        counter = 0
        error = False
        for domains in self.conf["domainlist"]:
            counter += 1
            domainlist = domains.split(",")
            logger.info(
                "-- Processing domainset %s of %s: %s"
                % (counter, len(self.conf["domainlist"]), domains)
            )
            if self.grind(domainlist):
                logger.info(
                    "-- Done processing domainset %s of %s: %s"
                    % (counter, len(self.conf["domainlist"]), domains)
                )
            else:
                logger.error(
                    "-- Error processing domainset %s of %s: %s"
                    % (counter, len(self.conf["domainlist"]), domains)
                )
                error = True

        if self.hook_needed:
            logger.info(
                "At least one certificate was renewed, running post renew hook..."
            )
            self.run_post_renew_hooks()

        if error and self.check:
            logger.error(
                "One or more certificates are missing, not valid, or have less than 30 days validity left, exiting with code 1"
            )
            sys.exit(1)

        logger.info("All done, exiting cleanly")

    def grind(self, domains: typing.List[str]) -> bool:
        """
        The main engine of Certgrinder. Sets paths and loads the keypair (or generates one if needed).
        Runs showtlsa and checktlsa mode if requested. If not, the certificate is loaded.
        If it is time to get a new certificate a CSR is generated and used to get a new certificate.
        """
        # set paths
        filenamedomain = domains[0].encode("idna").decode("ascii")
        self.keypair_path = os.path.join(self.conf["path"], "%s.key" % filenamedomain)
        logger.debug("key path: %s" % self.keypair_path)

        self.certificate_path = os.path.join(
            self.conf["path"], "%s.crt" % filenamedomain
        )
        logger.debug("cert path: %s" % self.certificate_path)

        self.csr_path = os.path.join(self.conf["path"], "%s.csr" % filenamedomain)
        logger.debug("csr path: %s" % self.csr_path)

        self.concat_path = os.path.join(
            self.conf["path"], "%s-concat.pem" % filenamedomain
        )
        logger.debug("concat path: %s" % self.concat_path)

        # attempt to load/generate keypair for this set of domains
        if self.load_keypair():
            logger.debug("Loaded key %s" % self.keypair_path)
        else:
            logger.error("Unable to load or generate keypair %s" % self.keypair_path)
            return False

        # are we running in showtlsa mode?
        if self.showtlsa:
            self.print_tlsa(service=self.showtlsa, domains=domains)
            return True

        # are we running in checktlsa mode?
        if self.checktlsa:
            self.check_tlsa(service=self.checktlsa, domains=domains)
            return True

        # are we running in showspki mode?
        if self.showspki:
            self.show_spki()
            return True

        # are we running in check mode?
        if self.check:
            self.load_certificate()
            return self.check_certificate_validity()

        # attempt to load certificate (if we even have one)
        if self.load_certificate():
            logger.debug(
                "Loaded certificate %s, checking validity..." % self.certificate_path
            )
            if self.check_certificate_validity():
                logger.info(
                    "The certificate %s is valid for at least another %s days, skipping"
                    % (self.certificate_path, self.conf["cert_renew_threshold_days"])
                )
                return True
            else:
                logger.info(
                    "The certificate %s is not valid, or expires in less than %s days, renewing..."
                    % (self.certificate_path, self.conf["cert_renew_threshold_days"])
                )
        else:
            logger.debug("Unable to load certificate %s" % self.certificate_path)

        # generate new CSR
        logger.info("Generating new CSR for domains %s" % domains)
        if self.generate_csr(domains):
            logger.info("Generated new CSR, getting certificate...")
        else:
            logger.error("Unable to generate new CSR for domains: %s" % domains)
            return False

        # use CSR to get signed certificate
        if self.get_new_certificate():
            logger.info("Successfully got new certificate for domains: %s" % domains)
            return True
        else:
            logger.error("Unable to get certificate for domains: %s" % domains)
            return False


def main() -> None:
    """
    Initialise script. Parse arguments, configure logging, and then call main() function
    """
    # parse commandline arguments
    parser = argparse.ArgumentParser(
        description="Certgrinder version %s. See the README.md file for more info."
        % __version__
    )
    parser.add_argument(
        "configfile",
        help="The path to the certgrinder.yml config file to use, default ~/certgrinder.yml",
        default="~/certgrinder.yml",
    )
    parser.add_argument(
        "-c",
        "--checktlsa",
        dest="checktlsa",
        default=False,
        help="Tell certgrinder to lookup TLSA records for the given service in the DNS and compare with what we have locally, for example: --checktlsa _853._tcp",
    )
    parser.add_argument(
        "-C",
        "--check",
        dest="check",
        default=False,
        action="store_true",
        help="Tell certgrinder check certificate validity and exit. If any certificates are missing or have less than 30 days validity the exit code will be 1.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        dest="log_level",
        const=logging.DEBUG,
        default=logging.INFO,
        help="Debug output. Lots of output about the internal workings of certgrinder.",
    )
    parser.add_argument(
        "-n",
        "--nameserver",
        dest="nameserver",
        default=False,
        help="Tell certgrinder to use this DNS server IP to lookup TLSA records. Only relevant with -c / --checktlsa. Only v4/v6 IPs, no hostnames.",
    )
    parser.add_argument(
        "-p",
        "--showspki",
        dest="showspki",
        default=False,
        action="store_true",
        help="Tell certgrinder to generate and print the pin-sha256 spki pins for the public keys it manages.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="log_level",
        const=logging.WARNING,
        help="Quiet mode. No output at all if there is nothing to do.",
    )
    parser.add_argument(
        "-s",
        "--showtlsa",
        dest="showtlsa",
        default=False,
        help="Tell certgrinder to generate and print TLSA records for the given service, for example: --showtlsa _853._tcp",
    )
    parser.add_argument(
        "-S",
        "--staging",
        dest="staging",
        default=False,
        action="store_true",
        help="Tell the certgrinder server to use LetsEncrypt staging servers, for testing purposes.",
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        default=False,
        action="store_true",
        help="Show version and exit.",
    )
    args = parser.parse_args()

    # define the log format used for stdout depending on the requested loglevel
    if args.log_level == logging.DEBUG:
        console_logformat = (
            "%(asctime)s %(levelname)s %(name)s:%(funcName)s():%(lineno)i:  %(message)s"
        )
        debug = True
    else:
        console_logformat = "%(asctime)s %(levelname)s: %(message)s"
        debug = False
    # configure the log format used for stdout
    logging.basicConfig(
        level=args.log_level, format=console_logformat, datefmt="%Y-%m-%d %H:%M:%S %z"
    )

    # show version and exit?
    if args.version:
        logger.info("certgrinder version %s" % __version__)
        sys.exit(0)

    # instantiate Certgrinder object
    certgrinder = Certgrinder(
        configfile=args.configfile,
        staging=args.staging,
        showtlsa=args.showtlsa,
        checktlsa=args.checktlsa,
        nameserver=args.nameserver,
        showspki=args.showspki,
        debug=debug,
        check=args.check,
    )

    # connect to syslog
    syslog_handler = logging.handlers.SysLogHandler(
        address=certgrinder.conf["syslog_socket"],
        facility=certgrinder.conf["syslog_facility"],
    )
    syslog_format = logging.Formatter("Certgrinder: %(message)s")
    syslog_handler.setFormatter(syslog_format)
    try:
        logger.addHandler(syslog_handler)
    except Exception:
        logger.exception(
            "Unable to connect to syslog socket %s - syslog not enabled. Exception info:"
            % certgrinder.conf["syslog_socket"]
        )

    # call main method
    certgrinder.main()


if __name__ == "__main__":
    main()
