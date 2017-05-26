import yaml, os, subprocess, tempfile, shutil, OpenSSL, logging, logging.handlers, textwrap, time, sys, argparse
from datetime import datetime
from pid import PidFile

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
try:
    logger.addHandler(logging.handlers.SysLogHandler(address='/var/run/log'))
except Exception as E:
    logger.exception("Unable to connect to syslog socket /var/run/log - syslog not enabled")


class Certgrinder:
    def __init__(self, configfile, test):
        """
        The __init__ method just reads the config file and checks a few things
        """
        if not self.read_config(configfile):
            sys.exit(1)

        if 'domainlist' not in self.conf:
            logger.error("domainlist not found in conf")
            sys.exit(1)

        # initialise variable
        self.hook_needed = False
        self.test = test


    def read_config(self, configfile):
        """
        Actually reads and parses the yaml config file
        """
        with open(configfile, "r") as f:
            try:
                self.conf = yaml.load(f)
                return True
            except Exception as E:
                logger.exception("Unable to read config")
                return False


############# RSA KEY METHODS ################################################


    def load_keypair(self):
        """
        Checks if the keypair file exists on disk, and calls self.create_keypair() if not
        """
        if os.path.exists(self.keypair_path):
            keypair_string=open(self.keypair_path, 'r').read()
            self.keypair=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keypair_string)
        else:
            logger.debug("keypair %s not found, creating new keypair..." % self.keypair_path)
            self.create_keypair()

        return self.keypair


    def create_keypair(self):
        """
        Generates an RSA keypair
        """
        self.keypair = OpenSSL.crypto.PKey()
        self.keypair.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
        self.save_keypair()


    def save_keypair(self):
        """
        Saves RSA keypair to disk
        """
        with open(self.keypair_path, 'w') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.keypair))
        logger.debug("saved keypair to %s" % self.keypair_path)


############# CSR METHODS ################################################


    def generate_csr(self, domains):
        """
        Generates a new CSR
        """
        logger.info("Generating CSR for domains: %s" % domains)
        self.csr = OpenSSL.crypto.X509Req()

        # set public key 
        self.csr.set_pubkey(self.keypair)

        # set only CN in subject, since everything else is removed by letsencrypt
        setattr(self.csr.get_subject(), 'CN', domains[0])

        # add subjectAltName x598 extension
        altnames = ','.join(['DNS:%s' % domain for domain in domains])
        logger.debug("Adding subjectAltName extension with value %s" % altnames)
        self.csr.add_extensions([
            OpenSSL.crypto.X509Extension(
                type_name="subjectAltName",
                critical=False, # TODO: should this be critical=True?!
                value=altnames
            )
        ])

        # sign the CSR
        self.csr.sign(self.keypair, 'sha256')

        # write the csr to disk
        self.save_csr()
        return self.csr


    def save_csr(self):
        """
        Save the PEM version of the CSR to the path in self.csr_path
        """
        with open(self.csr_path, 'w') as f:
            f.write(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, self.csr))
        logger.debug("saved CSR to %s" % self.csr_path)



############# CERTIFICATE METHODS ################################################


    def load_certificate(self):
        """
        Reads PEM certificate from the path in self.certificate_path
        """
        if os.path.exists(self.certificate_path):
            certificate_string=open(self.certificate_path, 'r').read()
            try:
                self.certificate=OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_string)
            except OpenSSL.crypto.Error:
                logger.exception("Got an exception while reading the certificate %s" % self.certificate_path)
                self.certificate = False
        else:
            logger.debug("certificate %s not found" % self.certificate_path)
            self.certificate = False

        return self.certificate


    def check_certificate_validity(self):
        """
        Checks the validity of the certificate.
        Returns a simpe True or False based on self.conf['cert_renew_threshold_days'],
        and whether the certificate is valid (not selfsigned)
        """
        # check if selfsigned
        if self.certificate.get_issuer() == self.certificate.get_subject():
            logger.debug("This certificate is selfsigned, check_certificate_validity() returning False")
            return False

        # check if issued by staging
        if self.certificate.get_issuer().CN == u'Fake LE Intermediate X1':
            logger.debug("This certificate was issued by LE staging CA, check_certificate_validity() returning False")
            return False

        # check expiration
        notafter = self.certificate.get_notAfter()
        try:
            expiration = datetime.strptime(notafter, "%Y%m%d%H%M%SZ")
        except Exception as E:
            logger.exception("Got exception while parsing notAfter from x509: %s" % notafter)
            return False

        # find the timedelta between now and the expire_date
        expiredelta = expiration - datetime.now()
        if expiredelta.days < self.conf['cert_renew_threshold_days']:
            logger.debug("Less than %s days to expiry of certificate, check_certificate_validity() returning False" % self.conf['cert_renew_threshold_days'])
            return False
        else:
            logger.debug("More than %s days to expiry of certificate, check_certificate_validity() returning True" % self.conf['cert_renew_threshold_days'])
            return True


    def get_new_selfsigned_certificate(self):
        """
        Create a selfsigned certificate
        """
        if not self.conf['selfsigned_fallback']:
            logger.info("selfsigned_fallback is disabled in config")
            return False

        logger.info("generating selfsigned certificate using csr %s" % self.csr_path)
        self.certificate = OpenSSL.crypto.X509()
        self.certificate.set_serial_number(int(time.time()))
        self.certificate.gmtime_adj_notBefore(0)
        # make it last 90 days like the real LE certificates
        self.certificate.gmtime_adj_notAfter(90*24*60*60)
        self.certificate.set_subject(self.csr.get_subject())
        self.certificate.set_issuer(self.certificate.get_subject())

        # set public key and sign
        self.certificate.set_pubkey(self.keypair)
        self.certificate.sign(self.keypair, "sha256")

        # all good
        return True


    def get_new_certificate(self):
        """
        cat the csr over ssh to the certgrinder server.
        """
        logger.info("ready to get signed certificate using csr %s" % self.csr_path)

        # put the ssh command together
        command = 'ssh %(server)s %(csrgrinder)s' % {
            'server': self.conf['server'],
            'csrgrinder': self.conf['csrgrinder_path']
        }
        if self.test:
            command += ' test'

        logger.debug("running ssh command: %s" % command)
        p = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # send the CSR to stdin and save stdout+stderr
        stdout, stderr = p.communicate(input=OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, self.csr))

        # parse the certificate in stdout (which should contains a valid PEM certificate)
        try:
            self.certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, stdout)
        except Exception as E:
            logger.exception("Got an exception while parsing cert, something went wrong while getting the certificate from the certgrinder server. Exception %s and this was stdout:" % E)
            logger.error(stdout)
            logger.error("this was in stderr:")
            logger.error(stderr)
            if not self.get_new_selfsigned_certificate():
                # we dont have a certificate
                return False

        # a few sanity checks of the certificate seems like a good idea
        if not self.check_certificate_sanity():
            if not self.get_new_selfsigned_certificate():
                # we dont have a certificate
                return False

        # save cert to disk, pass stdout to maintain chain,
        # as self.certificate only contains the server cert,
        # not LE intermediate
        self.save_certificate(stdout)

        # we have saved a new certificate, so we will need to run the post renew hook later
        self.hook_needed = True

        return True


    def check_certificate_sanity(self):
        """
        Performs a few sanity checks of the certificate obtained from the certgrinder server:
        - checks that the public key is correct
        - checks that the subject is correct
        - checks that the SubjectAltName data is correct
        Return False if a problem is found, True if all is well
        """
        # check self.certificate has the same pubkey as the CSR
        if OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.certificate.get_pubkey()) != OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.keypair):
            logger.error("The certificate returned from the certgrinder server does not have the public key we expected")
            return False

        # check if certificate has the same subject as our CSR (which is CN only)
        if self.certificate.get_subject() != self.csr.get_subject():
            logger.error("The certificate returned from the certgrinder server does not have the same subject as our CSR")
            return False

        # check if the certificates SubjectAltName contains all the domains our CSR has,
        # loop over extensions until we find the subjectAltName one
        found = False
        for i in range(self.certificate.get_extension_count()):
            if self.certificate.get_extension(i).get_short_name() == "subjectAltName":
                found = True
                # .get_data() returns ASN.1 encoded data, compare with data from the CSR
                if self.certificate.get_extension(i).get_data() != self.csr.get_extensions()[0].get_data():
                    logger.error("The certificate returned from the certgrinder server does not have the same data in SubjectAltName as our CSR")
                    return False
        if not found:
            # subjectAltName extension not found
            return False

        # all good
        return True


    def save_certificate(self, stdout=None):
        """
        Save the PEM certificate to the path self.certificate_path
        """
        # TODO: make this use self.certificate for regular as well as selfsigned certs, 
        # if it is possible to make OpenSSL.crypto.load_certificate() get the full chain including intermediate
        if not stdout:
            # stdout is empty, must be a selfsigned certificate
            stdout = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate)

        # save the file
        with open(self.certificate_path, 'w') as f:
            f.write(stdout)
        logger.info("saved new certificate chain to %s" % self.certificate_path)


############# POST RENEW HOOK METHOD #######################################


    def run_post_renew_hooks(self):
        if 'post_renew_hooks' not in self.conf or not self.conf['post_renew_hooks']:
            logger.debug("no self.conf['post_renew_hooks'] found, not doing anything")
            return True

        for hook in self.conf['post_renew_hooks']:
            logger.debug("Running post renew hook (with sudo): %s" % hook)
            # run with sudo
            p = subprocess.Popen(['sudo']+hook.split(" "))
            exitcode = p.wait()

            if exitcode != 0:
                logger.error("Got exit code %s when running post_renew_hook %s" % (exitcode, hook))
            else:
                logger.debug("Post renew hook %s ended with exit code 0, good." % hook)

        # all done
        return


############# MAIN METHOD ################################################


    def grind(self, domains):
        # set paths
        self.keypair_path = os.path.join(self.conf['path'], '%s.key' % domains[0])
        logger.debug("key path: %s" % self.keypair_path)

        self.certificate_path = os.path.join(self.conf['path'], '%s.crt' % domains[0])
        logger.debug("cert path: %s" % self.certificate_path)

        self.csr_path = os.path.join(self.conf['path'], '%s.csr' % domains[0])
        logger.debug("csr path: %s" % self.csr_path)

        # attempt to load/generate keypair for this set of domains
        if self.load_keypair():
            logger.debug("Loaded key %s" % self.keypair_path)
        else:
            logger.error("Unable to load or generate keypair %s" % self.keypair_path)
            return False

        # attempt to load certificate (if we even have one)
        if self.load_certificate():
            logger.debug("Loaded certificate %s, checking validity..." % self.certificate_path)
            if self.check_certificate_validity():
                logger.debug("The certificate %s is valid for at least another %s days, skipping" % (self.certificate_path, self.conf['cert_renew_threshold_days']))
                return True
            else:
                logger.info("The certificate %s is valid for less than %s days, renewing..." % (self.certificate_path, self.conf['cert_renew_threshold_days']))
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


if __name__ == '__main__':
        """
        Main method. Simply loops over sets of domains in the config and
        calls certgrinder.grind() for each
        """
        # parse commandline arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("configfile", help="The path to the certgrinder.yml config file to use")
        parser.add_argument('--test', dest='test', default=False, action='store_true', help="Tell the certgrinder server to use LetsEncrypt staging servers, for test purposes.")
        args = parser.parse_args()

        # instatiate Certgrinder object
        certgrinder = Certgrinder(args.configfile, test=args.test)

        # write pidfile and loop over domaintest
        with PidFile(piddir=certgrinder.conf['path']):
            for domains in certgrinder.conf['domainlist']:
                domains = domains.split(",")
                logger.info("------ processing domains: %s" % domains)
                if certgrinder.grind(domains):
                    logger.info("----- successfully processed domains: %s" % domains)
                else:
                    logger.error("----- error processing domains: %s" % domains)

            if certgrinder.hook_needed:
                logger.info("at least one certificate was renewed, running post renew hook...")
                certgrinder.run_post_renew_hooks()

            logger.debug("All done, exiting.")

