Certgrinder (Client)
====================
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


Configuration
~~~~~~~~~~~~~
Configuration of ``certgrinder`` can be done using command-line options, or a configuration file, or a combination of the two.

The ``certgrinder`` configuration file is in YAML format. An example config named ``certgrinder.conf.dist`` can be found in the distribution. use ``--config-file`` or ``-f`` to specify the config file location.

Each config item can be specified either in the YAML config file as a ``key: value`` pair, or on the commandline as ``--key value`` - the latter overriding the former if both are present. For example, if the configfile has ``log-level: INFO`` and the command-line has ``--log-level: DEBUG`` then the effective log-level would be ``DEBUG``.

This is an alphabetical list of the configurable options:

   `certgrinderd`
     The command to run as ``certgrinderd``. Usually this will be something like ``ssh certgrinderd@certgrinder.example.com -T``, possibly also with a ``--config-file`` for ``certgrinderd`` if needed.

     Default: ``None``

   `cert-renew-threshold-days`
     A certificate will be renewed when it has less than this many days of lifetime left.

     Default: ``30``

   `domain-list`
     Comma-seperated lists of domains for the certificates. Can be specified multiple times on the command-line, ``--domain-list example.com,www.example.com --domain-list example.net`` means two certificates, the first with two names, the second with one name.

     Default: ``None``

   `invalid-ca-cn-list`
     List of CommonName of certificate issuers to consider invalid. This is not a regular CA certificate validity check, it is used to detect certificates issued by LetsEncrypt staging servers as invalid.

     Default: ``["Fake LE Intermediate X1", "Fake LE Intermediate X2"]``

   `log-level`
     Sets the verbosity level for console and syslog logging. One of DEBUG, INFO, WARNING, ERROR, CRITICAL.

     Default: ``INFO``

   `name-server`
     Set this to a DNS server IP (v4 or v6, no hostnames) to use that DNS server instead of the system resolver.

     Default: ``None``

   `path`
     The directory used for keys, CSRs and certificates. Must exist and be writable by the user running Certgrinder.

     Default: ``None``

   `pid-dir`
     The directory to place the certgrinderd PID file in.

     Default: ``/tmp``

   `post-renew-hooks`
     A list of commands which ``certgrinder`` must run after renewing one or more certificates. Use this to reload/restart services which need to be poked after the certificate changes. Can be specified multiple times on the command-line. Remember to include sudo or whatever if needed.

     Default: ``None``

   `staging`
     Enable staging mode. Adds ``--staging`` to the ``certgrinderd`` command, and sees certificates issued by LE staging servers as valid.

     Default: ``False``

   `syslog-facility`
     Set this and syslog-socket to enable logging to syslog.

     Default: ``None``

   `syslog-socket`
     Set this and syslog-facility to enable logging to syslog.

     Default: ``None``

   `tlsa-port`
     Set this to the port (like ``443``) when using ``show tlsa`` or ``check tlsa`` subcommands.

     Default: ``None``

   `tlsa-protocol`
     Set this to the protocol (like ``tcp``) when using ``show tlsa`` or ``check tlsa`` subcommands.

     Default: ``None``

   `tlsa-type-list`
     Set this to enable a TLSA type (can be specified multiple times). The TLSA type must be specified as three integers, one of: ``310``, ``311`` or ``312``. Default: is all three pubkey types.

     Default: ``["310", "311", "312"]``

Challenges
~~~~~~~~~~
Finally you need to choose which challenge type to use for this ``certgrinder`` client. If ``DNS-01`` you need to create one or more ``CNAME`` record pointing somewhere. If ``HTTP-01`` you need to create an HTTP redirect. See the section on challenge types.


Testing
~~~~~~~
At this point you should be ready to test! Start by checking with SSH manually to see that the SSH key is installed properly on the Certgrinder server, and firewalls are open. Certgrinder has a ``--staging`` switch which makes ``certgrinderd`` use the LetsEncrypt staging environment. Use this until everything works! ``certgrinder`` outputs some info on what happens, and can output more with ``-d / --debug``, but sometimes you need to check syslog on the Certgrinder server.


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

   $ certgrinder help
   usage: certgrinder.py [-h] [--certgrinderd CERTGRINDERD]
                         [--cert-renew-threshold-days CERT-RENEW-THRESHOLD-DAYS]
                         [-d] [-D DOMAIN-LIST]
                         [--invalid-ca-cn-list INVALID-CA-CN-LIST]
                         [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-f CONFIGFILE]
                         [-n NAME-SERVER] [--path PATH] [-p PID-DIR]
                         [--post-renew-hooks POST-RENEW-HOOKS] [-q] [-s]
                         [--syslog-facility SYSLOG-FACILITY]
                         [--syslog-socket SYSLOG-SOCKET] [--tlsa-port TLSA-PORT]
                         [--tlsa-protocol TLSA-PROTOCOL]
                         [--tlsa-type-list {310,311,312}]
                         {check,show,get,version,help,periodic} ...

   Certgrinder version 0.13.0-beta2-dev. See the manpage or ReadTheDocs for more
   info.

   positional arguments:
     {check,show,get,version,help,periodic}
                           Command (required)
       check               Use the "check" command to check certificates, OCSP
                           responses and TLSA records. Returns exit code 0 if all
                           is well, and 1 if something needs attention.
       show                Use the "show" command to show certificates, TLSA
                           records, SPKI pins or configuration.
       get                 Use the "get" command to get certificates and OCSP
                           responses
       version             The "version" command just outputs the version of
                           Certgrinder
       help                The "help" command just outputs the usage help
       periodic            The "periodic" command checks certificates and renews
                           them as needed. It is meant to be run daily.

   optional arguments:
     -h, --help            show this help message and exit
     --certgrinderd CERTGRINDERD
                           The command to reach the certgrinderd server, will get
                           the CSR on stdin. Usually something like 'ssh
                           certgrinderd@server -T'
     --cert-renew-threshold-days CERT-RENEW-THRESHOLD-DAYS
                           A certificate is renewed when it has less than this
                           many days of lifetime left. Default: `30`
     -d, --debug           Debug mode. Equal to setting --log-level=DEBUG.
     -D DOMAIN-LIST, --domain-list DOMAIN-LIST
                           Comma seperated list of domains for a certificate. Can
                           be specified multiple times.
     --invalid-ca-cn-list INVALID-CA-CN-LIST
                           The CommonName of an issuer (CA intermediate) to
                           consider invalid. Can be specified multiple times.
     -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                           Logging level. One of DEBUG, INFO, WARNING, ERROR,
                           CRITICAL. Defaults to INFO.
     -f CONFIGFILE, --config-file CONFIGFILE
                           The path to the certgrinder.yml config file to use,
                           default ~/certgrinder.yml
     -n NAME-SERVER, --name-server NAME-SERVER
                           Tell certgrinder to use this DNS server IP to lookup
                           TLSA records. Only relevant with -c / --checktlsa.
                           Only v4/v6 IPs, no hostnames.
     --path PATH           Tell certgrinder to use the specified directory for
                           keys, CSRs and certificates. The directory must exist
                           and be writeable by the user running certgrinder.
     -p PID-DIR, --pid-dir PID-DIR
                           The directory to store the PID file in
     --post-renew-hooks POST-RENEW-HOOKS
                           The list of commands to run after one or more
                           certificates are renewed. Most such commands will need
                           root access to run, remember to prefix the command
                           with 'sudo' as needed. Can be specified multiple
                           times. Default: `None`
     -q, --quiet           Quiet mode. No output at all if there is nothing to
                           do, and no errors are encountered. Equal to setting
                           --log-level=WARNING.
     -s, --staging         Pass --staging to the certgrinderd command to tell the
                           Certgrinder server to use LetsEncrypt staging servers
                           (use for testing purposes).
     --syslog-facility SYSLOG-FACILITY
                           The syslog facility to use. Set this and syslog-socket
                           to enable logging to syslog.
     --syslog-socket SYSLOG-SOCKET
                           The syslog socket to connect to. Set this and syslog-
                           facility to enable logging to syslog.
     --tlsa-port TLSA-PORT
                           The service port number (like 443) for TLSA
                           operations.
     --tlsa-protocol TLSA-PROTOCOL
                           The service protocol (like tcp) for TLSA operations.
     --tlsa-type-list {310,311,312}
                           Enables a TLSA type for TLSA operations. Can be
                           specified multiple times.


See Also
--------
:manpage:`certgrinderd(8)`
