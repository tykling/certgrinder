Certgrinder Server
==================
The Certgrinder server ``certgrinderd`` takes care of receiving the ``CSR``, running Certbot, serving challenges, and finally outputs a certificate. It never acts on its own, it only does something when a Certgrinder client calls it with a CSR on stdin, usually over SSH.


Installing the Certgrinder Server
---------------------------------
This section explains the steps to install the Certgrinder server ``certgrinderd``.


Install Certgrinderd
~~~~~~~~~~~~~~~~~~~~
Create a VM or Jail or Docker thing or whatever somewhere. This will be your Certgrinder server. Give it a hostname like ``certgrinder.example.com``. This will be the hostname your Certgrinder clients use to SSH into (if you use SSH), and the hostname you use to serve HTTP challenges (if you use HTTP challenges). Create DNS records (A+AAAA and if you use SSH then an SSHFP record wouldn't hurt) for the new hostname and you should be ready to begin the install.

You can install ``certgrinderd`` from pip with ``pip install certgrinderd``. It will pull in the dependencies it needs automatically. Create a venv for it if you don't want to pollute the global Python env.

You can also checkout the Github repo and install the deps from requirements.txt by hand if you prefer. If you want to install with pip directly from Git the following may help:
``pip install "git+https://github.com/tykling/certgrinder/#egg=certgrinderd&subdirectory=server"``

The Certgrinder server needs to be reachable from the outside world on port 53/80 if you plan to serve DNS/HTTP challenges locally. It also needs to be accessible over SSH from all your Certgrinder clients if you plan to use SSH.


Create User
~~~~~~~~~~~
Create a dedicated user to run the Certgrinder server, usually the username is just ``certgrinderd``. The user needs ``sudo`` access to run the ``certbot`` binary, and to set a couple of environment variables. This works::

    certgrinderd ALL=(ALL) NOPASSWD: /usr/local/bin/certbot
    Defaults env_keep += "ACMEZONE WEBROOT"


Configuration File
~~~~~~~~~~~~~~~~~~
The ``certgrinderd`` configuration file is in YAML format. An example config named ``certgrinderd.conf.dist`` can be found in the distribution. Only changes to the defaults need to be specified.


Restricting Client Hostnames
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To determine whether a Certgrinder client is authorised to get a certificate for a given list of hostnames ``certgrinderd`` checks the environment variable named ``CERTGRINDERD_DOMAINSETS`` which must contain a semicolon-seperated list of comma-seperated lists of hostnames permitted for the current client.

For example, if the Certgrinder client was a webserver with two vhosts, one with the name ``example.net`` and another vhost with the two names ``example.com`` and ``www.example.com``. In this case the environment variable ``CERTGRINDERD_DOMAINSETS="example.net;example.com,www.example.com"`` would permit the client to get the two certificates it needs, and nothing else.

The list of hostnames is case insensitive. IDNA names need to be in ascii format, meaning ``xn--plse-gra.example`` rather than ``pølse.example``. The order of the hostnames in the list does not matter.


Configure SSH Access
~~~~~~~~~~~~~~~~~~~~
Usually Certgrinder clients connect to the Certgrinder server using SSH, but other connection methods can be used if needed. The rest of this section is about configuring SSH access for clients.

Each Certgrinder client must generate an SSH key which is to be added to ``~/.ssh/authorized_keys`` on the Certgrinder server. Each entry must be restricted with:

* A ``from=`` specifying the IP the Certgrinder client connects from (optional but recommended).
* An ``environment=`` restricting which names it may ask for, see above (required).
* ``command=`` to restrict the command it can run (optional but recommended).
* The ``restrict`` keyword to limit tunneling and forwarding and such (optional but recommended). The ``restrict`` option was added to OpenSSH in version 7.4, it might not be available everywhere.

Something like this works::

    from="2001:DB8::15",environment="CERTGRINDERD_DOMAINSETS=example.com,www.example.com;example.net",command="/path/to/certgrinderd",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOegnR+qnK2FEoaSrVwHgCIxjFkVEbW4VO31/Hd2mAwk ansible-generated on webproxy2.example.com

To make the ``environment=`` foo work the option ``PermitUserEnvironment=CERTGRINDERD_DOMAINSETS`` needs to be added to ``sshd_config``.


Install Webserver/DNS Server or Hook Scripts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Finally you need to decide which challenge types to use, and how to handle them. Read the section on challenge types above, and if you decide to use a local web/dns server then you need to install and configure it now. If you want to use a remote server instead, you need to create the hook scripts to handle creating and deleting challenges.
