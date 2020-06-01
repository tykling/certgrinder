Certgrinderd (Server)
=====================
The Certgrinder server ``certgrinderd`` takes care of receiving the ``CSR``, running Certbot, serving challenges, and finally outputs a certificate. It never acts on its own, it only does something when a Certgrinder client calls it with a CSR on stdin, usually over SSH.

The following sections explain the steps you need to setup a Certgrinder server.


Install Certgrinder Server
--------------------------
Create a VM or Jail or Docker thing or whatever somewhere. This will be your Certgrinder server. Give it a hostname like ``certgrinder.example.com``.

This will be the hostname your Certgrinder clients use to SSH into (if you use SSH), and the hostname you use to serve HTTP challenges (if you use HTTP challenges).

Create DNS records (A+AAAA, and if you use SSH then an SSHFP record wouldn't hurt) for the new hostname and you should be ready to begin the install.

Create User
-----------
Create a dedicated user to run the Certgrinder server, usually the username is just ``certgrinderd``. The user needs ``sudo`` access to run the ``certbot`` binary, and to set a couple of environment variables. This works::

    certgrinderd ALL=(ALL) NOPASSWD: /usr/local/bin/certbot
    Defaults env_keep += "ACMEZONE WEBROOT"

Install certgrinderd
--------------------
You can install ``certgrinderd`` from pip with ``pip install certgrinderd``. It will pull in the dependencies it needs automatically. Create a venv for it if you don't want to pollute the global Python env.

You can also checkout the Github repo and install the deps from ``requirements.txt`` by hand if you prefer. If you want to install with pip directly from Github the following may help:
``pip install "git+https://github.com/tykling/certgrinder/#egg=certgrinderd&subdirectory=server"``

The Certgrinder server needs to be reachable from the outside world on port 53/80 if you plan to serve DNS/HTTP challenges locally. It also needs to be accessible over SSH from all your Certgrinder clients if you plan to use SSH.

Configuration
-------------
Configuration of ``certgrinderd`` can be done using command-line options, or a configuration file, or a combination of the two.

The ``certgrinderd`` configuration file is in YAML format. An example config named ``certgrinderd.conf.dist`` can be found in the distribution. use ``--config-file`` or ``-f`` to specify the config file location.

Each config item can be specified either in the YAML config file as a ``key: value`` pair, or on the commandline as ``--key value`` - the latter overriding the former if both are present. For example, if the configfile has ``log-level: INFO`` and the command-line has ``log-level: DEBUG`` then the effective log-level would be ``DEBUG``.

This is an alphabetical list of the configurable options:

   `acme-email`
     The email to use for the ACME account creation. Only required for the first run.

     Default: ``None``

   `acme-server-url`
     The URL for the ACME server.

     Default: ``https://acme-v02.api.letsencrypt.org/directory``

   `acme-zone`
     The DNS zone to pass to auth-hook script as environment variable ACMEZONE. Leave this unset to disable DNS-01 challenges.

     Default: ``None``

   `auth-hook`
     The script to run to prepare challenges before running Certbot.

     Default: ``manual-auth-hook.sh``

   `certbot-command`
     The Certbot command to run between the auth hook and the cleanup hook.

     Default: ``/usr/local/bin/sudo /usr/local/bin/certbot``

   `certbot-config-dir`
     The path to pass to Certbot as ``--config-dir``.

     Default: ``None``

   `certbot-logs-dir`
     The path to pass to Certbot as ``--logs-dir``.

     Default: ``None``

   `certbot-work-dir`
     The path to pass to Certbot as ``--logs-dir``.

     Default: ``None``

   `cleanup-hook`
     The script to run to cleanup challenges after running Certbot.

     Default: ``manual-cleanup-hook.sh``

   `config-file`
     The path to the configuration file. The file is in YAML format.

     Default: ``None``

   `debug`
     Enables debug mode. This is the same as setting --log-level to DEBUG. Outputs lots info about the internal workings of certgrinderd.

     Default: ``False``

   `log-level`
     Sets the verbosity level for console and syslog logging. One of DEBUG, INFO, WARNING, ERROR, CRITICAL.

     Default: ``INFO``

   `pid-dir`
     The directory to place the certgrinderd PID file in.

     Default: ``/tmp``

   `skip-acme-server-cert-verify`
     Set to skip verification of the ACME servers TLS certificate. Used for testing, do not use in real world.

     Default: ``False``

   `staging`
     Enable staging mode. To make Certbot use the LetsEncrypt staging servers.

     Default: ``False``

   `syslog-facility`
     Set this and syslog-socket to enable logging to syslog. Must be a value supported by ``logging.handlers.SysLogHandler`` like ``LOG_USER`` or ``LOG_LOCAL0``.

     Default: ``None``

   `syslog-socket`
     Set this and syslog-facility to enable logging to syslog.

     Default: ``None``

   `temp-dir`
     Set this to the directory to use for temporary files (CSR and certificates). Directory should be owned by the user running ``certgrinderd``. A directory will be created and deleted inside this temp-dir for each run. Leave blank to create one automatically.

     Default: ``None``

   `web-root`
     The path to pass to the auth-hook script as environment variable WEBROOT. Leave this blank to disable HTTP-01 challenges.

     Default: ``None``

Finally the permitted domains for the current client must be specified as an environment variable (see next section).


Restricting Client Hostnames
----------------------------
To determine whether a Certgrinder client is authorised to get a certificate for a given list of hostnames ``certgrinderd`` checks the environment variable named ``CERTGRINDERD_DOMAINSETS`` which must contain a semicolon-seperated list of comma-seperated lists of hostnames permitted for the current client.

For example, if the Certgrinder client was a webserver with two vhosts, one with the name ``example.net`` and another vhost with the two names ``example.com`` and ``www.example.com``. In this case the environment variable ``CERTGRINDERD_DOMAINSETS="example.net;example.com,www.example.com"`` would permit the client to get the two certificates it needs, and nothing else.

The list of hostnames is case insensitive. IDNA names need to be in ascii format, meaning ``xn--plse-gra.example`` rather than ``pølse.example``. The order of the hostnames in the list does not matter.


Configure SSH Access
--------------------
Usually Certgrinder clients connect to the Certgrinder server using SSH, but other connection methods can be used if needed. The rest of this section is about configuring SSH access for clients.

Each Certgrinder client must generate an SSH key which is to be added to ``~/.ssh/authorized_keys`` on the Certgrinder server. Each entry must be restricted with:

* A ``from=`` specifying the IP the Certgrinder client connects from (optional but recommended).
* An ``environment=`` restricting which names it may ask for, see above (required).
* ``command=`` to restrict the command it can run (optional but recommended).
* The ``restrict`` keyword to limit tunneling and forwarding and such (optional but recommended). The ``restrict`` option was added to OpenSSH in version 7.4, it might not be available everywhere.

Something like this works::

    from="2001:DB8::15",environment="CERTGRINDERD_DOMAINSETS=example.com,www.example.com;example.net",command="/path/to/certgrinderd",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOegnR+qnK2FEoaSrVwHgCIxjFkVEbW4VO31/Hd2mAwk ansible-generated on webproxy2.example.com

To make the ``environment=`` foo work the option ``PermitUserEnvironment=CERTGRINDERD_DOMAINSETS`` needs to be added to ``sshd_config``.


Challenge Types
---------------
Finally you need to decide which challenge types to use, and how to handle them. This section describes how Certgrinder handles ``DNS-01`` and ``HTTP-01`` challenges. 

Certgrinder supports the two ``ACME`` challenge types ``DNS-01`` and ``HTTP-01``. The author prefers to use ``DNS-01`` for most things, but if the Certgrinder client happens to be a webserver, then the ``HTTP-01`` challenge is very easy to get up and running.

Certgrinder will try both challenge types (``DNS-01`` first, then ``HTTP-01``), so your clients can use whatever is the best fit. Usually my webservers use ``HTTP-01`` and everything else uses ``DNS-01``. YMMV.

The following sections describes how Certgrinder these two challenge types.

DNS-01
~~~~~~
With the ``DNS-01`` challenge the Certgrinder server serves the challenge over DNS, which means you need to run an authoritative DNS server on the Certgrinder server. You can also use an external DNS server or provider, as long as you can make a hook script to add and delete records from the Certgrinder server as needed.

To prepare the Certgrinder server for serving ``DNS-01`` challenges you first need a zone to serve the challenges. Invent and delegate a new zone (like ``acme.example.com``) to your Certgrinder server or DNS provider. Use an ``NS`` record to delegate, or follow your providers instructions. The zone name then needs to be configured in ``certgrinderd.conf``. This zone will be used to serve all ``DNS-01`` challenges, it will be updated automatically by ``certgrinderd`` as needed.

The default ``manual-auth-hook`` script is made for the ``bind`` DNS server. It creates and deletes the DNS record using ``nsupdate`` and an ``rndc.key`` file in the path ``/usr/local/etc/namedb/rndc.key``. If you want to use other paths or another script for a local or external DNS provider you can configure it in ``certgrinderd.conf``. The same goes for the cleanup script ``manual-cleanup-hook``.

Note:
   Since ``certbot`` is responsible for calling the hooks they are run as root, just like ``certbot``.

This concludes the server part of the ``DNS-01`` configuration.

A client wanting a certificate must now create a ``CNAME`` record called ``_acme-challenge.${DOMAIN}`` pointing at ``${DOMAIN}.${ACMEZONE}`` for each domain in the ``CSR``.

For example, to get a certificate for ``smtp.example.org`` you would create ``_acme-challenge.smtp.example.org CNAME smtp.example.org.acme.example.com`` if your acme challenge zone was ``acme.example.com``. certgrinderd will create the ``smtp.example.org.acme.example.com TXT`` record containing the validation string, and delete if afterwards.


HTTP-01
~~~~~~~
With the ``HTTP-01`` challenge the Certgrinder server serves the challenge over HTTP, which means it needs a webserver somewhere to serve the challenges. It can be on the Certgrinder server or it can be an external webserver or provider, as long as you can make a hook script to add and delete files in the webroot from the Certgrinder server as needed. The hostname of this webserver will be the target of the Certgrinder clients HTTP redirects.

Each Certgrinder client then implements an HTTP redirect from ``/.well-known/acme-challenge/`` to the Certgrinder server like so (nginx syntax)::

    location /.well-known/acme-challenge/ {
        return 301 http://acme.example.com$request_uri;
    }

When requesting a certificate the Certgrinder server receives the challenge and path from Certbot (which in turn gets it from LetsEncrypt of course). The challenge is then passed to the ``manual-auth-hook`` script which writes it in the webroot under ``/.well-known/acme-challenge/``.

In another datacenter somewhere LetsEncrypts challenge checker then loops over the domains in the ``CSR`` and does a HTTP request to each for ``/.well-known/acme-challenge/${path}`` and expects the response to contain the challenge.

Auth and Cleanup Hooks
----------------------
The configured ``auth-hook`` and ``cleanup-hook`` scripts can be adapted as needed to update whatever local or remote web- or DNS-server you decide to use to serve challenges.

Both scripts get the same environment variables to work with:

   `$CERTBOT_DOMAIN`
      The domain being authenticated, like www.example.com

   `$CERTBOT_VALIDATION`
      The validation string (the secret which LE looks for)

   `$CERTBOT_TOKEN`
      The filename containing the secret (only relevant for HTTP-01)

   `$ACMEZONE`
      The DNS zone used for challenges (only relevant for DNS-01)

   `$WEBROOT`
      The path to the webroot used for challenges (only relevant for HTTP-01)

Both scripts must be able to handle the challenge type(s) you use. The same script will be called first for DNS-01 (if enabled), then for HTTP-01 (if enabled).

Testing
-------
When the server has been configured with hooks you can test from a client using just SSH and a manually generated CSR, with something like: ``cat mail4.example.com.csr | ssh certgrinderd@certgrinder.example.org -T -- --staging`` where ``-T`` is to prevent SSH from allocating a TTY on the server, ``--`` is to mark the end of the SSH args, and ``--staging`` is to make ``certgrinderd`` use the LetsEncrypt staging servers. If all goes well it should output some logging and a certificate chain.
