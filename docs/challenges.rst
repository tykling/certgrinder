Challenges
==========
Certgrinder supports the two ``ACME`` challenge types ``DNS-01`` and ``HTTP-01``. Certgrinderd will try both challenge types (``DNS-01`` first, then ``HTTP-01``), so your clients can use whatever is the best fit. Usually my webservers use ``HTTP-01`` and everything else uses ``DNS-01``. YMMV.

The following sections describes how Certgrinder handles these two challenge types.

DNS-01
------
With the ``DNS-01`` challenge type the Certgrinder server serves the challenge over DNS, which means you need to run an authoritative DNS server on the Certgrinder server. You can also use an external DNS server or provider, as long as you can make a hook script to add and delete records from the Certgrinder server as needed.

To prepare the Certgrinder server for serving ``DNS-01`` challenges you first need a zone to serve the challenges. Invent and delegate a new zone (like ``acme.example.com``) to your Certgrinder server or DNS provider. Use an ``NS`` record to delegate, or follow your providers instructions. The zone name then needs to be configured in ``certgrinderd.conf``. This zone will be used to serve all ``DNS-01`` challenges, it will be updated automatically by ``certgrinderd`` as needed.

The default ``manual-auth-hook`` script is made for the ``bind`` DNS server. It creates and deletes the DNS record using ``nsupdate`` and an ``rndc.key`` file in the path ``/usr/local/etc/namedb/rndc.key``. If you want to use other paths or another script for a local or external DNS provider you can configure it in ``certgrinderd.conf``. The same goes for the cleanup script ``manual-cleanup-hook``.

Note:
   Since ``certbot`` is responsible for calling the hooks they are run as root, just like ``certbot``.

This concludes the server part of the ``DNS-01`` configuration.

A client wanting a certificate must now create a ``CNAME`` record called ``_acme-challenge.${DOMAIN}`` pointing at ``${DOMAIN}.${ACMEZONE}`` for each domain in the ``CSR``.

For example, to get a certificate for ``smtp.example.org`` you would create ``_acme-challenge.smtp.example.org CNAME smtp.example.org.acme.example.com`` if your acme challenge zone was ``acme.example.com``. certgrinderd will create the ``smtp.example.org.acme.example.com TXT`` record containing the validation string, and delete if afterwards.


HTTP-01
-------
With the ``HTTP-01`` challenge type the Certgrinder server serves the challenge over HTTP, which means it needs a webserver somewhere to serve the challenges. It can be on the Certgrinder server or it can be an external webserver or provider, as long as you can make a hook script to add and delete files in the webroot from the Certgrinder server as needed. The hostname of this webserver will be the target of the Certgrinder clients HTTP redirects.

Each Certgrinder client then implements an HTTP redirect from ``/.well-known/acme-challenge/`` to the Certgrinder server like so (nginx syntax)::

    location /.well-known/acme-challenge/ {
        return 301 http://acme.example.com$request_uri;
    }

When requesting a certificate the Certgrinder server receives the challenge and path from Certbot (which in turn gets it from LetsEncrypt of course). The challenge is then passed to the ``manual-auth-hook`` script which writes it in the webroot under ``/.well-known/acme-challenge/``.

In another datacenter somewhere LetsEncrypts challenge checker then loops over the domains in the ``CSR`` and does a HTTP request to each for ``/.well-known/acme-challenge/${path}`` and expects the response to contain the challenge.

