Introduction
============
Certgrinder is a set of Python scripts to handle Letsencrypt certificate signing on a central host, rather than on the servers which need the certificates. This is accomplished by redirecting the LetsEncrypt challenge to the Certgrinder server.

For ``DNS-01`` challenges this is done with a ``CNAME record`` and for ``HTTP-01`` challenges this is done with a ``301 redirect``.

Certgrinder clients connect to the Certgrinder server over ``SSH`` to provide a ``CSR`` and get a signed certificate in return.

This approach simplifies getting certificates for stuff like loadbalanced hosts, where it can be difficult to predict which cluster node the LetsEncrypt challenge checker will hit when using ``HTTP-01``.

It can also simplify certain operations like migrating some system to new servers, by making it possible to get real valid certificates for the new infrastructure before changing DNS to point to the new infrastructure.

Additionally, Certgrinder does not rotate the RSA keypair on each certificate renewal, which can be an advantage since it makes ``TLSA`` and similar pinning easy. The Certgrinder client can output and check such ``TLSA`` and ``SPKI`` pins for the keypairs it manages, as well as checking ``TLSA`` records in the DNS.

Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/


Terminology
===========
The central host with the LetsEncrypt signing stack is called the "Certgrinder server". The individual servers (the ones that need the certificates) are called "Certgrinder clients". These match the two Python packages ``certgrinderd`` and ``certgrinder``, respectively.

