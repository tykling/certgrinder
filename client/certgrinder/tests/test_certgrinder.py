import logging
from certgrinder.certgrinder import Certgrinder

logger = logging.getLogger("certgrinder.%s" % __name__)
logging.basicConfig(level=logging.DEBUG)


def test_certgrinder(pebble_server, pebble_ca_certs, certgrinder_configfile):
    """
    Get a certificate
    """
    certgrinder = Certgrinder(
        configfile=certgrinder_configfile,
        staging=False,
        showtlsa=False,
        checktlsa=False,
        nameserver=False,
        showspki=False,
        debug=True,
        check=False,
    )
    certgrinder.main()
    # check that the certificates were issued correctly
    logger.info("root cert:")
    logger.info(pebble_ca_certs[0])
    logger.info("intermediate cert:")
    logger.info(pebble_ca_certs[1])
    # get pebbles root and intermediate
    logger.info(certgrinder.conf)
