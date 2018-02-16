# Certgrinder

## Background
Certgrinder is a set of scripts to handle Letsencrypt certificate signing on a central host, rather than on the servers which need the certificates. Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

### Advantages
The primary advantage of this approach is that the signing stack and LetsEncrypt credentials are never exposed on servers with untrusted users on them. Not rotating the RSA keypair is also an advantage since it makes TLSA and other pinning easy. It also simplifies geting certificates for stuff like loadbalanced hosts, where it can be difficult to predict which node the LetsEncrypt challenge checker will hit.

### Terminology
The central host with the signing stack is called the "Certgrinder server". The individual servers (the ones that need certificates) are called "Certgrinder clients".

## Features
Apart from the primary purpose of getting signed certificates the `certgrinder.py` script has a few other features that may be of use.

### TLSA Generation
The `-s` / `--showtlsa` switch suspends normal operation and instead loops over the configured domainsets and generates TLSA records for the public keys. The result is printed to the terminal in a format suitable for putting in the DNS. It looks like this:

    [certgrinder@znc ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -s _443._tcp -n 109.238.48.13 certgrinder.yml
    2018-02-16 08:42:18 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 08:42:18 +0000 INFO: TLSA records for _443._tcp.znc.tyknet.dk:
    2018-02-16 08:42:18 +0000 INFO:  _443._tcp.znc.tyknet.dk 3 1 0 30820222300d06092a864886f70d01010105000382020f003082020a0282020100bb852c1035ee7ce08d69a13f5cca95374dc872b2028e65ee34600478076c9185e79ff373d3acfc4aa29f152b9abcb515e449417ce7768f7f91915ff2d6e75d732e863021240ce4b24475220306e6ffd3f963dc4a8eafb4077f635d8a0d655b5921df2bcb2e6e610aa8db1d79b6da14d1fc7d842c1e5d4cbfa6697617aa9d2251be1a386fd7c14eccef21151c35d336ebba8f97d3160b35775c57079d2594b1d2a9d593bc408ccf2a01b171f4a3e65005b07df7efd77bac3d5f430b0aab5f161b7d7ebc40b600064ec3a4c59d64a1ec1f27c234a08a473aa0fcdf6008492161af6a1d9179a432622776e675f4d3dafb3d1d00b3189c4cdcd6de250721f012fc5f34426d06cb4b045b04ba2bd7ac2fcedce429dfde3dffcbb8b2df50cade99458c954de157b88751c26b79413d6eef5e26ab008e7aa7c69be3d6163f80f5d565b87f9030b54a23cf4c704e509cc84e618a446c75684893d65bd5fd38ef6b839d316b5616b06bbafbb7c2aa6f3db217b4df6e5f02b85d8685be14a9d480ee56c1b4454a88fc01a4532a55e926929fea70822088054f5ddf957e8c5ca2c3808c8a09b70c7eeda4883aaf6f1092033beeb0ff5621a8b8ddf3455f1d30d2398fe786038a39e0825bb6bac9865500de33eff67e3984a73b7592bde5897681b52da06c93447a0efa4d1fb52bc151811776ef501ca818c68fd1d4fe3d73c5e5526b4bf47f0203010001
    2018-02-16 08:42:18 +0000 INFO:  _443._tcp.znc.tyknet.dk 3 1 1 5b95cb6ea387570f1f3dc4508794ca13a17a665733bab5f76b1e330f2fa13361
    2018-02-16 08:42:18 +0000 INFO:  _443._tcp.znc.tyknet.dk 3 1 2 24d49f3c974129b9c28b5e6213892a404d8e9777c5a2e977333b88442d4e16ac0bc732001ec783df795c194704149bd18bbca21087111b33fa79e84dab05e760

Shown above is the showtlsa feature in action. The value supplied should be the port and protocol of the service, in the example above it is a HTTPS service, so the TLSA record is the service hostname prefixed with `_443._tcp.`.

### TLSA Checking
The `-c` / `--checktlsa` switch suspends normal operation and like the `--showtlsa` switch it generates TLSA records for the specified service, but it goes one step further and actually checks in the DNS if the records could be found, and prints some output accordingly. This also requires `-n` / `--nameserver` IP to be specified.
The following example shows two runs of `checktlsa` mode. The first run finds no TLSA records and outputs what needs to be added.

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

The second run is after adding the records to DNS:

    [certgrinder@znc ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -c _443._tcp -n 109.238.48.13 certgrinder.yml
    2018-02-16 09:16:27 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 09:16:27 +0000 INFO: Looking up TLSA records for _443._tcp.znc.tyknet.dk
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 0 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 1 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: TLSA record for name _443._tcp.znc.tyknet.dk type 3 1 2 found in DNS matches the local key, good.
    2018-02-16 09:16:27 +0000 INFO: Done processing domains: znc.tyknet.dk
    [certgrinder@znc ~]$

All TLSA records for this public key can now be found in the DNS. As there might be additional records for the same name which do not belong to this server/key, no attempts are made to warn about wrong/old/superflous TLSA records. This might be added in a future version as a switch to tell Certgrinder that the local public key is the only one in existence for this service.

### SPKI Generation
The `-p` / `--showspki` switch tells Certgrinder to suspend normal operation and generate and print pin-sha256 spki pins for the public keys instead. The [HPKP standard](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) defined the pin-sha256 format for public key pins. While the HPKP standard didn't get much traction the pinning format is used in various places now, so Certgrinder can generate them. 

The operation is pretty simple:

    [certgrinder@znc ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -p certgrinder.yml
    2018-02-16 09:28:37 +0000 INFO: Processing domains: znc.tyknet.dk
    2018-02-16 09:28:37 +0000 INFO: pin-sha256="W5XLbqOHVw8fPcRQh5TKE6F6ZlczurX3ax4zDy+hM2E="
    2018-02-16 09:28:37 +0000 INFO: Done processing domains: znc.tyknet.dk
    [certgrinder@znc ~]$

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

`certgrinder.py` comes with a `requirements.txt` file which can be used to install the needed Python packages from pip. The script has a few different commandline options which are shown below:

    [certgrinder@myserver ~]$ ./virtualenv/bin/python certgrinder/certgrinder.py -h
    usage: certgrinder.py [-h] [-t] [-s SHOWTLSA] [-c CHECKTLSA] [-n NAMESERVER]
                          [-p] [-d] [-q] [-v]
                          configfile

    Certgrinder version 0.9.6. See the README.md file for more info.

    positional arguments:
      configfile            The path to the certgrinder.yml config file to use,
                            usually ~/certgrinder.yml. Required argument.

    optional arguments:
      -h, --help            show this help message and exit
      -t, --test            Tell the certgrinder server to use LetsEncrypt staging
                            servers, for test purposes.
      -s SHOWTLSA, --showtlsa SHOWTLSA
                            Tell certgrinder to generate and print TLSA records
                            for the given service, for example: --showtlsa
                            _853._tcp
      -c CHECKTLSA, --checktlsa CHECKTLSA
                            Tell certgrinder to lookup TLSA records for the given
                            service in the DNS and compare with what we have
                            locally, for example: --checktlsa _853._tcp
      -n NAMESERVER, --nameserver NAMESERVER
                            Tell certgrinder to use this DNS server IP to lookup
                            TLSA records. Only relevant with -c / --checktlsa.
                            Only v4/v6 IPs, no hostnames.
      -p, --showspki        Tell certgrinder to generate and print the pin-sha256
                            spki pins for the public keys it manages.
      -d, --debug           Debug output. Lots of output about the internal
                            workings of certgrinder.
      -q, --quiet           Quiet mode. No output at all if there is nothing to
                            do.
      -v, --version         Show version and exit.

### csrgrinder
The csrgrinder script lives on the Certgrinder server. It is very simple, just a couple of lines sh, and it is called over SSH by the Certgrinder clients. It takes a PEM formatted CSR on stdin as input, and outputs a signed PEM formatted certificate on stdout.

## Theory of Operation
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

