# certgrinder
certgrinder


## Background
Certgrinder is a pair scripts to handle Letsencrypt certificate signing on a central host rather than on the servers which need the certificates. Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

### Advantages
The primary advantage of this design is that the signing stack and credentials are never exposed on servers with untrusted users on them. Not rotating the RSA keypair is also an advantage since it makes TLSA and other pinning easy.

### Terminology
The central host with the signing stack is called the "certgrinder server". The individual servers (the ones that need certificates) are called "certgrinder clients".

## Files
Certgrinder primarily consists of two scripts. Most of the functionality is in a Python script called "certgrinder" which runs on all the Certgrinder clients. The other one is written in Bourne sh, runs on the Certgrinder server (called over SSH by the clients), and is called "csrgrinder". A typical homedir for a Certgrinder user looks like this:

### certgrinder
The Certgrinder Python script is meant to be run under a dedicated user and has two primary tasks:

1. Generate one RSA keypair per set of domains. Each certificate can have multiple domains, but the filename of keypair and certificates will/should be based on the first domain in the list. The RSA keypair can also be generated manually if you prefer:
`openssl genrsa -out example.com.key 4096`

2. Generate a CSR and use it to get a signed certificate from the certgrinder server.

It comes with a requirements.txt which can be used to install the needed Python packages from pip. It has a few different commandline options which are shown here:

    [certgrinder@bornfiber ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -h
    usage: certgrinder.py [-h] [-t] [-s SHOWTLSA] [-c CHECKTLSA] [-n NAMESERVER]
                          [-d] [-q]
                          configfile

    positional arguments:
      configfile            The path to the certgrinder.yml config file to use,
                            default ~/certgrinder.yml

    optional arguments:
      -h, --help            show this help message and exit
      -t, --test            Tell the certgrinder server to use LetsEncrypt staging servers, for test purposes.
      -s SHOWTLSA, --showtlsa SHOWTLSA
                            Tell certgrinder to generate and print TLSA records for the given service, for example: --showtlsa _853._tcp
      -c CHECKTLSA, --checktlsa CHECKTLSA
                            Tell certgrinder to lookup TLSA records for the given service in the DNS and compare with what we have locally, for example: --checktlsa _853._tcp
      -n NAMESERVER, --nameserver NAMESERVER
                            Tell certgrinder to use this DNS server to lookup TLSA records. Only relevant with -c / --checktlsa
      -d, --debug           Debug output. Lots of output about the internal workings of certgrinder.
      -q, --quiet           Quiet mode. No output at all if there is nothing to do.


### csrgrinder
The csrgrinder script lives on the certgrinder server. It is very simple, just a couple of lines sh, and it is called over SSH by the certgrinder clients. It takes a PEM formatted CSR on stdin as input, and outputs a signed PEM formatted certificate on stdout.

## Operation
The theory behind this system is simple. Each Certgrinder client does the following:

0. Configure http redirect from /.well-known/acme-challenge/ to the certgrinder server. The redirect must be functional for all domains you intend to put in the CSR.
1. Generate an RSA keypair
2. Generate a new CSR
3. Cat the CSR over SSH to the certgrinder server, certgrinder server returns the signed certicate on stdout.
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

