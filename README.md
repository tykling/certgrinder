# Certgrinder

## Background
Certgrinder is a pair scripts to handle Letsencrypt certificate signing on a central host rather than on the servers which need the certificates. Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

### Advantages
The primary advantage of this design is that the signing stack and credentials are never exposed on servers with untrusted users on them. Not rotating the RSA keypair is also an advantage since it makes TLSA and other pinning easy.

### Terminology
The central host with the signing stack is called the "Certgrinder server". The individual servers (the ones that need certificates) are called "Certgrinder clients".

## Files
Certgrinder primarily consists of two scripts. Most of the functionality is in a Python script called `certgrinder.py` which runs on all the Certgrinder clients. The other one is written in Bourne sh, runs on the Certgrinder server (called over SSH by the clients), and is called "csrgrinder". A typical homedir for a Certgrinder user looks like this:

    [certgrinder@znc ~]$ ls -l
    total 43
    drwxr-xr-x  3 root         certgrinder   11 Jan 17 11:59 certgrinder
    -rw-r--r--  1 certgrinder  wheel        649 Jan 17 12:31 certgrinder.yml
    drwxr-x---  2 certgrinder  certgrinder    6 Jan 17 12:31 certificates
    drwxr-xr-x  5 root         certgrinder    6 Oct  9 09:31 virtualenv
    [certgrinder@znc ~]$ ls -l certificates/
    total 32
    -rw-r-----  1 certgrinder  certgrinder  7058 Dec  9 02:49 znc.tyknet.dk-concat.pem
    -rw-r--r--  1 certgrinder  certgrinder  3786 Dec  9 02:49 znc.tyknet.dk.crt
    -rw-r--r--  1 certgrinder  certgrinder  1647 Dec  9 02:49 znc.tyknet.dk.csr
    -rw-r-----  1 certgrinder  certgrinder  3272 Oct  9 09:32 znc.tyknet.dk.key
    [certgrinder@znc ~]$

The `certgrinder` folder contains the code from Github, `certificates` contains all the key material, and `virtualenv` contains the environment to run it.

### certgrinder.py
The certgrinder.py Python script is meant to be run under a dedicated user and has two primary tasks:

1. Generate one RSA keypair per set of domains. Each certificate can have multiple domains, but the filename of keypair and certificates will/should be based on the first domain in the list. The RSA keypair can also be generated manually if you prefer:
`openssl genrsa -out example.com.key 4096`

2. Generate a CSR and use it to get a signed certificate from the Certgrinder server.

It comes with a requirements.txt which can be used to install the needed Python packages from pip. It has a few different commandline options which are shown here:

    [certgrinder@myserver ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -h
    usage: certgrinder.py [-h] [-t] [-s SHOWTLSA] [-c CHECKTLSA] [-n NAMESERVER] [-p] [-d] [-q] [-v] configfile

    Certgrinder version 0.9.5. See the README.md file for more info.

    positional arguments:
      configfile            The path to the certgrinder.yml config file to use, default ~/certgrinder.yml

    optional arguments:
      -h, --help            show this help message and exit
      -t, --test            Tell the certgrinder server to use LetsEncrypt staging servers, for test purposes.
      -s SHOWTLSA, --showtlsa SHOWTLSA
                            Tell certgrinder to generate and print TLSA records for the given service, for example: --showtlsa _853._tcp
      -c CHECKTLSA, --checktlsa CHECKTLSA
                            Tell certgrinder to lookup TLSA records for the given service in the DNS and compare with what we have locally, for example: --checktlsa _853._tcp
      -n NAMESERVER, --nameserver NAMESERVER
                            Tell certgrinder to use this DNS server IP to lookup TLSA records. Only relevant with -c / --checktlsa. Only v4/v6 IPs, no hostnames.
      -p, --showspki        Tell certgrinder to generate and print the pin-sha256 spki pins for the public keys it manages.
      -d, --debug           Debug output. Lots of output about the internal workings of certgrinder.
      -q, --quiet           Quiet mode. No output at all if there is nothing to do.
      -v, --version         Show version and exit.

### csrgrinder
The csrgrinder script lives on the Certgrinder server. It is very simple, just a couple of lines sh, and it is called over SSH by the Certgrinder clients. It takes a PEM formatted CSR on stdin as input, and outputs a signed PEM formatted certificate on stdout.

## Operation
The theory behind this system is simple. Each Certgrinder client does the following:

0. Configure http redirect from /.well-known/acme-challenge/ to the Certgrinder server. The redirect must be functional for all domains you intend to put in the CSR.
1. Generate an RSA keypair
2. Generate a new CSR
3. Cat the CSR over SSH to the Certgrinder server, Certgrinder server returns the signed certicate on stdout.
4. Run post-renew hook (to reload services with the new cert)
5. Repeat 2-4 daily (but skip if cert has more than 30 days validity).

The Certgrinder server does the following:

0. Has Certbot installed and configured
1. Waits for SSH connections
2. When clients connect they run the `csrgrinder` script, which receives the CSR from the client on stdin, runs Certbot, and outputs the signed certificate on stdout

Each clients SSH key and IP must be configured on the Certgrinder server in .ssh/authorized_keys, for example:
`from="192.0.2.134",command="/usr/local/bin/csrgrinder",no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3........ user@hostname`

## More info
Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

