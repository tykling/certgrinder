Certgrinder Server
==================
The Certgrinder server takes care of running Certbot serving challenges. It never acts on its own, it only does something when a Certgrinder client connects over SSH with a CSR.

Installing the Certgrinder Server
---------------------------------
This section explains the steps to install a Certgrinder server.


Install Server
~~~~~~~~~~~~~~
Create a VM or Jail or Docker thing or whatever somewhere. This will be your Certgrinder server. It will need to have ``Certbot`` installed and ``sshd`` running. It also needs to be accessible over SSH from all your Certgrinder clients. Furthermore, if you intend to serve the challenges locally you also need port 53 and/or 80 open from the outside world (a portforward will work).


Create User
~~~~~~~~~~~
Create a dedicated user, usually the username is just ``certgrinder``. The user needs ``sudo`` access to run the ``certbot`` binary, and to set a couple of environment variables. This works::

    certgrinder ALL=(ALL) NOPASSWD: /usr/local/bin/certbot
    Defaults env_keep += "ACMEZONE WEBROOT"


Get Certgrinder Code
~~~~~~~~~~~~~~~~~~~~
Get the code from Git, usually in a ``certgrinder`` folder in the Certgrinder users homedir. Get the latest release from https://github.com/tykling/certgrinder/releases since ``master`` is not always in a usable state::

    git clone -b 'v0.13.0' --single-branch --depth 1 https://github.com/tykling/certgrinder ~/certgrinder


Configure SSH Access
~~~~~~~~~~~~~~~~~~~~
Certgrinder works using SSH. Each Certgrinder client must now generate an SSH key which is to be added to ``~/.ssh/authorized_keys`` on the Certgrinder server. Something like this works::

    from="2a01:3a0:1:1900:85:235:250:91",command="~/certgrinder/csrgrinder",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOegnR+qnK2FEoaSrVwHgCIxjFkVEbW4VO31/Hd2mAwk ansible-generated on webproxy2.servers.bornhack.org

The ``restrict`` option to OpenSSH was added recently, might not be available everywhere.


Install Certbot
~~~~~~~~~~~~~~~
Certbot needs to be installed, and an account needs to be created. TODO: Document how to do this, but basically it happens automatically the first time Certbot is run. On FreeBSD the account info lives under ``/usr/local/etc/letsencrypt/accounts``.


Install Webserver/DNS Server or Hook Scripts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Finally you need to decide which challenge types to use, and how to handle them. Read the section on challenge types above, and if you decide to use a local web/dns server then you need to install and configure it now. If you want to use a remote server instead, you need to create the hook scripts to handle creating and deleting challenges.

