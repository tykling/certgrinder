Introduction
============
Certgrinder is a client/server system written in Python to handle Letsencrypt certificate issuing on a central host (the Certgrinder server), rather than on the machines which need the certificates (the Certgrinder clients). This is accomplished by redirecting the LetsEncrypt challenges to the Certgrinder server. For ``DNS-01`` challenges this is done with a ``CNAME record`` and for ``HTTP-01`` challenges it is done with a ``HTTP 301 redirect``.

To get a certificate the Certgrinder client calls the Certgrinder server (typically over ``SSH``) with a ``CSR`` on ``stdin`` and (if all goes well) get a signed certificate in return on ``stdout``.

Certgrinder support both ``RSA`` and ``ECDSA`` keys and certificates, and defaults to getting both kinds.

Advantages
==========
- The approach with a central host serving all challenges simplifies getting certificates for stuff like loadbalanced or anycast services, where it can be impossible to predict which cluster node the LetsEncrypt challenge checker will hit when using ``HTTP-01``.

- Using ``DNS-01`` with a seperate delegated zone dedicated to serve the challenges is safer than opening up dynamic updates of your primary zone(s) with your provider.

- Migrating services to new infrastructure becomes simpler because the new infrastructure can get real certificates before changing DNS to point to the new infrastructure.

- Certgrinder makes it trivial to get certificates for infrastructure behind firewalls or even on networks with no Internet connection. As long as the Certgrinder client can reach the Certgrinder server it is possible to use ``DNS-01`` to issue certificates for the client.


- Certgrinder does not rotate the RSA/ECDSA keypair on each certificate renewal, which makes ``TLSA`` and similar public key pinning easy. The Certgrinder client can output and check such ``TLSA`` and ``SPKI`` pins for the keypairs it manages, as well as checking correctness of ``TLSA`` records in the DNS.

- Certgrinder supports fetching OCSP responses via the Certgrinder server. Prefetching the OCSP response makes it possible to do OCSP stapling without relying on the various TLS servers own OCSP-fetching implementation. It also means that OCSP stapling can be done on servers behind firewalls or with no Internet connection, as the communication with CA is done via the Certgrinder server.


Terminology
===========
The central host with the LetsEncrypt signing stack is called the "Certgrinder server". The individual servers (the ones that need the certificates) are called "Certgrinder clients". These match the two Python packages ``certgrinderd`` and ``certgrinder``, respectively.

