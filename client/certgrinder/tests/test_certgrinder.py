import logging
import urllib.request
import pathlib
import ssl
from certgrinder.certgrinder import Certgrinder

logger = logging.getLogger("certgrinder.%s" % __name__)
logging.basicConfig(level=logging.DEBUG)


def test_certgrinder(pebble_server, certgrinder_configfile, tmp_path_factory):
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

    # Pebble regenerates the CA root and intermediate on each run
    print("downloading root cert ...")
    tls_context = ssl.create_default_context(
        cafile=pathlib.Path.home()
        / "go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem"
    )
    with urllib.request.urlopen(
        "https://127.0.0.1:15000/roots/0", context=tls_context
    ) as u:
        root = u.read()

    with urllib.request.urlopen(
        "https://127.0.0.1:15000/roots/0", context=tls_context
    ) as u:
        intermediate = u.read()

    # check that the certificates were issued correctly

    # get pebbles root and intermediate
    logger.info("root cert:")
    logger.info(root)
    logger.info("intermediate cert:")
    logger.info(intermediate)

    # show certgrinder config
    logger.info(certgrinder.conf)
