LetsEncrypt Challenge Types
===========================
Certgrinder supports two challenge types, ``DNS-01`` and ``HTTP-01``. ``DNS-01`` is recommended, but if the Certgrinder client happens to be a webserver, then the ``HTTP-01`` challenge is very easy to get up and running. Certgrinder will try both challenge types (``DNS-01`` first, then ``HTTP-01``), so your clients can use whatever is the best fit. Usually my webservers use ``HTTP-01`` and everything else uses ``DNS-01``. YMMV.

Certgrinder and DNS-01
----------------------
With the ``DNS-01`` challenge the Certgrinder server serves the challenge over DNS, which means you need to run an authoritative DNS server on the Certgrinder server yourself. You can also use an external DNS provider, as long as you can make a hook script to add and delete records from the Certgrinder server as needed. Finally you will need to add a ``CNAME`` record called ``_acme-challenge`` in the DNS under each hostname included in the ``CSR``.

To prepare, you first need to invent and delegate a zone to your DNS server or provider, say, ``acme.example.com``. If you are running your own authoritative DNS server you need to create an ``NS`` record in the ``example.com`` zone to delegate the ``acme.example.com`` zone to it. Otherwise follow your providers instructions. The zone name then needs to be configured in ``certgrinderd.yml``. This zone will be used to serve the challenges, it will be updated automatically by ``certgrinderd`` as needed.

Then you create a ``CNAME`` record called ``_acme-challenge.${DOMAIN}`` pointing at ``${DOMAIN}.${CERTGRINDERZONE}`` for each domain in the ``CSR``. For example, to get a certificate for ``smtp.example.org`` you would create ``_acme-challenge.smtp.example.org CNAME smtp.example.org.acme.example.com`` if your acme challenge zone was ``acme.example.com``. certgrinderd will create the ``smtp.example.org.acme.example.com TXT`` record containing the validation string, and delete if afterwards.

The default ``manual-auth-hook`` script creates the DNS record using ``nsupdate`` and an ``rndc.key`` file in the path ``/usr/local/etc/namedb/rndc.key``. If you want to use another script for an external provider you can configure it in ``certgrinderd.yml``. The same goes for the cleanup script ``manual-cleanup-hook``.

Certgrinder and HTTP-01
-----------------------
With the HTTP-01 challenge the Certgrinder server serves the challenge over plain unencrypted HTTP, which means you need a running webserver to serve it - either on the Certgrinder server itself, or on a remote webserver where you can write a script to create and delete files in the webroot.

To prepare, you first need to invent a hostname you will use to serve the challenges, say, ``acme.example.com``. This hostname should be configured as a virtual host on a webserver somewhere, either locally on the Certgrinder server, or on some remote webserver.

Each Certgrinder client then implements an HTTP redirect from ``/.well-known/acme-challenge/`` to the Certgrinder server like so (nginx syntax)::

    location /.well-known/acme-challenge/ {
        return 301 http://acme.example.com$request_uri;
    }

When requesting a certificate the Certgrinder server receives the challenge and path from Certbot (which in turn gets it from LetsEncrypt of course). The challenge is then passed to the ``manual-auth-hook`` script which saves it in the local webroot path (configured in ``certgrinderd.yml``) under ``/.well-known/acme-challenge/``. LetsEncrypts challenge checker then loops over the domains in the ``CSR`` and does a HTTP request to each for ``/.well-known/acme-challenge/${path}`` and expects the response to contain the challenge.

The script that writes the challenge file to the webroot is called ``manual-auth-hook`` but if you want to use another hook script the path can be configured in ``certgrinderd.yml``. The script that deletes the challenge from the webroot is called ``manual-cleanup-hook``, but if you want to use another that can also be configured in ``certgrinderd.yml``. The scripts are simple and the comments explain which environment variables are made available to them for each challenge type.

Certbot Documentation
---------------------
The ``HTTP-01`` and ``DNS-01`` hooks are documented here: https://certbot.eff.org/docs/using.html#hooks

