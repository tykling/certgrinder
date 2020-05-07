Certgrinder Client
==================
The ``certgrinder`` client is responsible for generating a keypair and a CSR, which it uses to contact the Certgrinder server ``certgrinderd`` over SSH to get a signed certificate. The following section explains how to install and configure it to get certificates from the Certgrinder server.


Installing Certgrinder Clients
------------------------------
This section explains the steps to install a Certgrinder client. Repeat these steps on each server in need of certificates!


Install certgrinder
~~~~~~~~~~~~~~~~~~~~~~~~~~
You can install certgrinder from pip with ``pip install certgrinder``. This will install the latest ``certgrinder`` release. It will pull in the dependencies it needs automatically.

You can also checkout the Github repo and install the deps from requirements.txt by hand if you prefer. If you want to install with pip directly from Git the following may help:
``pip install "git+https://github.com/tykling/certgrinder/#egg=certgrinder&subdirectory=client"``


Create Certgrinder User
~~~~~~~~~~~~~~~~~~~~~~~
Since ``certgrinder`` is designed to be run under a seperate system user one should be created. The user needs sudo access if (and only if) it is to be able to reload/restart services after renewing certificates. Sometimes it is also neccesary to add some system users to the certgrinder group so they can read certificates. More on that later.

The user also needs to run ``ssh-keygen`` and the SSH key needs to be added to the ``authorized_keys`` file on the Certgrinder server. Make sure to test the SSH access works (hint: check firewalls, v4 vs v6 etc).


Config File
~~~~~~~~~~~
The config file for ``certgrinder`` is in ``YAML`` format. ``certgrinder`` comes with a sample ``certgrinder.yml.dist`` file which should be fairly self-explanatory.


Challenges
~~~~~~~~~~
Finally you need to choose which challenge type to use for this ``certgrinder`` client. If ``DNS-01`` you need to create one or more ``CNAME`` record pointing somewhere. If ``HTTP-01`` you need to create an HTTP redirect. See the section on challenge types.


Testing
~~~~~~~
At this point you should be ready to test! Start by checking with SSH manually to see that the SSH key is installed properly on the Certgrinder server, and firewalls are open. Certgrinder has a ``--test`` switch which makes ``certgrinderd`` use the LetsEncrypt staging environment. Use this until everything works! ``certgrinder`` outputs some info on what happens, and can output more with ``-d / --debug``, but often you need to check syslog on the Certgrinder server.


Crontab job
~~~~~~~~~~~
I run Certgrinder daily, although it only attempts renewal when less than 30 days validity remains. When everything above works it is time to automate it by adding it to crontab. The following line works for me (I vary the times between servers)::

    48 2 * * * certgrinder /usr/home/certgrinder/virtualenv/bin/certgrinder /usr/home/certgrinder/certgrinder.yml

Note that I call it inside the virtualenv directly to make sure the correct environment is used!


Additional Client Features
--------------------------
Apart from the primary purpose of getting signed certificates the ``certgrinder`` script has a few other features that may be of use.


TLSA Pin Generation
~~~~~~~~~~~~~~~~~~~
The ``-s`` / ``--showtlsa`` switch suspends normal operation and instead loops over the configured domainsets and generates ``TLSA`` records for the public keys. The result is printed to the terminal in a format suitable for putting in the ``DNS``. It looks like this::

    [certgrinder@znc ~]$ ./virtualenv/bin/certgrinder -s _443._tcp -n 109.238.48.13 certgrinder.yml
    2018-02-16 08:42:18 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 08:42:18 +0000 INFO: TLSA records for _443._tcp.znc.tyknet.dk:
    2018-02-16 08:42:18 +0000 INFO: _443._tcp.znc.tyknet.dk 3 1 0 30820222300d06092a864886f70d01010105000382020f003082020a0282020100bb852c1035ee7ce08d69a13f5cca95374dc872b2028e65ee34600478076c9185e79ff373d3acfc4aa29f152b9abcb515e449417ce7768f7f91915ff2d6e75d732e863021240ce4b24475220306e6ffd3f963dc4a8eafb4077f635d8a0d655b5921df2bcb2e6e610aa8db1d79b6da14d1fc7d842c1e5d4cbfa6697617aa9d2251be1a386fd7c14eccef21151c35d336ebba8f97d3160b35775c57079d2594b1d2a9d593bc408ccf2a01b171f4a3e65005b07df7efd77bac3d5f430b0aab5f161b7d7ebc40b600064ec3a4c59d64a1ec1f27c234a08a473aa0fcdf6008492161af6a1d9179a432622776e675f4d3dafb3d1d00b3189c4cdcd6de250721f012fc5f34426d06cb4b045b04ba2bd7ac2fcedce429dfde3dffcbb8b2df50cade99458c954de157b88751c26b79413d6eef5e26ab008e7aa7c69be3d6163f80f5d565b87f9030b54a23cf4c704e509cc84e618a446c75684893d65bd5fd38ef6b839d316b5616b06bbafbb7c2aa6f3db217b4df6e5f02b85d8685be14a9d480ee56c1b4454a88fc01a4532a55e926929fea70822088054f5ddf957e8c5ca2c3808c8a09b70c7eeda4883aaf6f1092033beeb0ff5621a8b8ddf3455f1d30d2398fe786038a39e0825bb6bac9865500de33eff67e3984a73b7592bde5897681b52da06c93447a0efa4d1fb52bc151811776ef501ca818c68fd1d4fe3d73c5e5526b4bf47f0203010001
    2018-02-16 08:42:18 +0000 INFO: _443._tcp.znc.tyknet.dk 3 1 1 5b95cb6ea387570f1f3dc4508794ca13a17a665733bab5f76b1e330f2fa13361
    2018-02-16 08:42:18 +0000 INFO: _443._tcp.znc.tyknet.dk 3 1 2 24d49f3c974129b9c28b5e6213892a404d8e9777c5a2e977333b88442d4e16ac0bc732001ec783df795c194704149bd18bbca21087111b33fa79e84dab05e760
    [certgrinder@znc ~]$

Shown above is the ``--showtlsa`` feature in action. The value supplied should be the port and protocol of the service, in the example above it is a ``HTTPS`` service, so the ``TLSA`` record is the service hostname prefixed with ``_443._tcp.``


TLSA Pin Checking
~~~~~~~~~~~~~~~~~
The ``-c`` / ``--checktlsa`` switch is like the ``--showtlsa`` switch but it goes one step further and actually checks in the ``DNS`` if the records could be found, and prints some output accordingly. This also requires ``-n`` / ``--nameserver`` IP to be specified. The following example shows two runs of ``checktlsa`` mode. The first run finds no TLSA records and outputs what needs to be added::

    [certgrinder@znc ~]$ /usr/home/certgrinder/virtualenv/bin/python /usr/home/certgrinder/certgrinder/certgrinder.py -c _443._tcp -n 109.238.48.13 /usr/home/certgrinder/certgrinder.yml
    2018-02-16 08:59:39 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 08:59:39 +0000 INFO: Looking up TLSA records for _443._tcp.znc.tyknet.dk
    2018-02-16 08:59:39 +0000 WARNING: No TLSA records for name _443._tcp.znc.tyknet.dk of type 3 1 0 was found in DNS. This record needs to be added:
    2018-02-16 08:59:39 +0000 WARNING: _443._tcp.znc.tyknet.dk 3 1 0 30820222300d06092a864886f70d01010105000382020f003082020a0282020100bb852c1035ee7ce08d69a13f5cca95374dc872b2028e65ee34600478076c9185e79ff373d3acfc4aa29f152b9abcb515e449417ce7768f7f91915ff2d6e75d732e863021240ce4b24475220306e6ffd3f963dc4a8eafb4077f635d8a0d655b5921df2bcb2e6e610aa8db1d79b6da14d1fc7d842c1e5d4cbfa6697617aa9d2251be1a386fd7c14eccef21151c35d336ebba8f97d3160b35775c57079d2594b1d2a9d593bc408ccf2a01b171f4a3e65005b07df7efd77bac3d5f430b0aab5f161b7d7ebc40b600064ec3a4c59d64a1ec1f27c234a08a473aa0fcdf6008492161af6a1d9179a432622776e675f4d3dafb3d1d00b3189c4cdcd6de250721f012fc5f34426d06cb4b045b04ba2bd7ac2fcedce429dfde3dffcbb8b2df50cade99458c954de157b88751c26b79413d6eef5e26ab008e7aa7c69be3d6163f80f5d565b87f9030b54a23cf4c704e509cc84e618a446c75684893d65bd5fd38ef6b839d316b5616b06bbafbb7c2aa6f3db217b4df6e5f02b85d8685be14a9d480ee56c1b4454a88fc01a4532a55e926929fea70822088054f5ddf957e8c5ca2c3808c8a09b70c7eeda4883aaf6f1092033beeb0ff5621a8b8ddf3455f1d30d2398fe786038a39e0825bb6bac9865500de33eff67e3984a73b7592bde5897681b52da06c93447a0efa4d1fb52bc151811776ef501ca818c68fd1d4fe3d73c5e5526b4bf47f0203010001
    2018-02-16 08:59:39 +0000 WARNING: No TLSA records for name _443._tcp.znc.tyknet.dk of type 3 1 1 was found in DNS. This record needs to be added:
    2018-02-16 08:59:39 +0000 WARNING: _443._tcp.znc.tyknet.dk 3 1 1 5b95cb6ea387570f1f3dc4508794ca13a17a665733bab5f76b1e330f2fa13361
    2018-02-16 08:59:39 +0000 WARNING: No TLSA records for name _443._tcp.znc.tyknet.dk of type 3 1 2 was found in DNS. This record needs to be added:
    2018-02-16 08:59:39 +0000 WARNING: _443._tcp.znc.tyknet.dk 3 1 2 24d49f3c974129b9c28b5e6213892a404d8e9777c5a2e977333b88442d4e16ac0bc732001ec783df795c194704149bd18bbca21087111b33fa79e84dab05e760
    2018-02-16 08:59:39 +0000 INFO: Done processing domains: znc.tyknet.dk
    [certgrinder@znc ~]$

The second run is after adding the suggested records to ``DNS``::

    [certgrinder@znc ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -c _443._tcp -n 109.238.48.13 certgrinder.yml
    2018-02-16 09:16:27 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 09:16:27 +0000 INFO: Looking up TLSA records for _443._tcp.znc.tyknet.dk
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 0 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 1 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 2 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: Done processing domains: znc.tyknet.dk
    [certgrinder@znc ~]$

All ``TLSA`` records for this public key can now be found in the ``DNS``.

`NOTE`: As there might be additional records for the same name which do not belong to this server/key, no attempts are made to warn about wrong/old/superflous ``TLSA`` records. This might be added in a future version as a switch to tell Certgrinder that the local public key is the only one in existence for this service.


SPKI Pin Generation
~~~~~~~~~~~~~~~~~~~
The ``-p`` / ``--showspki`` switch tells Certgrinder to suspend normal operation and generate and print pin-sha256 spki pins for the public keys instead. The ``HPKP`` standard https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning defined the ``pin-sha256`` format for public key pins. While the ``HPKP`` standard didn't get much traction the pinning format is used in various places now, so ``certgrinder`` can generate them. 

The operation is pretty simple::

    [certgrinder@znc ~]$ ./virtualenv/bin/certgrinder -p certgrinder.yml
    2018-02-16 09:28:37 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 09:28:37 +0000 INFO: pin-sha256="W5XLbqOHVw8fPcRQh5TKE6F6ZlczurX3ax4zDy+hM2E="
    2018-02-16 09:28:37 +0000 INFO: Done processing domains: znc.tyknet.dk
    [certgrinder@znc ~]$


Command-line Options
--------------------
The client has a few different commandline options which are shown below::
   usage: certgrinder.py [-h] [-c CHECKTLSA] [-C] [-d] [-f CONFIGFILE]
                         [-n NAMESERVER] [-p] [-q] [-s SHOWTLSA] [-S] [-v]

   Certgrinder version 0.13.0-beta2-dev. See the README.md file for more info.

   optional arguments:
     -h, --help            show this help message and exit
     -c CHECKTLSA, --checktlsa CHECKTLSA
                           Tell certgrinder to lookup TLSA records for the given
                           service in the DNS and compare with what we have
                           locally, for example: --checktlsa _853._tcp
     -C, --check           Tell certgrinder check certificate validity and exit.
                           If any certificates are missing or have less than 30
                           days validity the exit code will be 1.
     -d, --debug           Debug output. Lots of output about the internal
                           workings of certgrinder.
     -f CONFIGFILE, --configfile CONFIGFILE
                           The path to the certgrinder.yml config file to use,
                           default ~/certgrinder.yml
     -n NAMESERVER, --nameserver NAMESERVER
                           Tell certgrinder to use this DNS server IP to lookup
                           TLSA records. Only relevant with -c / --checktlsa.
                           Only v4/v6 IPs, no hostnames.
     -p, --showspki        Tell certgrinder to generate and print the pin-sha256
                           spki pins for the public keys it manages.
     -q, --quiet           Quiet mode. No output at all if there is nothing to
                           do.
     -s SHOWTLSA, --showtlsa SHOWTLSA
                           Tell certgrinder to generate and print TLSA records
                           for the given service, for example: --showtlsa
                           _853._tcp
     -S, --staging         Tell the certgrinder server to use LetsEncrypt staging
                           servers, for testing purposes.
     -v, --version         Show version and exit.

