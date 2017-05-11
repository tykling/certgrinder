# certgrinder
certgrinder


## Background
Certgrinder is a set of scripts to handle Letsencrypt cert signing on a central host rather than on the servers which need the certificates. Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

### Advantages
The primary advantage of this design is that the signing stack and credentials are never exposed on servers with untrusted users on them.

### Terminology
The central host with the signing stack is called the "certgrinder server". The individual servers (the ones that need certificates) are called "certgrinder clients".

### Operation
The theory behind this is simple. Each Certgrinder client (the certificate consumers, like webservers) does the following:

0. Configure http redirect from /.well-known/acme-challenge/ to the certgrinder server. The redirect must be functional for all domains you intend to put in the CSR.
1. Generate an RSA keypair
2. Generate a new CSR.
3. Cat the CSR over SSH to the certgrinder server, certgrinder server returns the signed certicate on stdout.
4. Run post-renew hook (to reload services with the new cert)
5. Repeat 2-4 daily (but skip if cert has more than 30 days validity).

This is easy to do from crontab with a small script. If you want some inspiration I've included mine in this repo, it is called "certgrinder."

## Files
Certgrinder primarily consists of two files. One is a script that runs on the certgrinder clients, simply called "certgrinder". The other runs on the Certgrinder server and is called "csrgrinder".

### certgrinder
Two flavours of the certgrinder script exists. The bash version of the script can be configured near the top of the script. The Python script comes with a yaml config file. Use whichever suits you, but note that only the Python version supports multiple keys/certificates.

The certgrinder script is meant to be run under a dedicated user and has two primary tasks:

1. Create an RSA keypair. This can also be done manually if you prefer:
`openssl genrsa -out example.com.key 4096`

2. Create CSR and use it to get a signed certificate from the certgrinder server. If you want to do this manually you first you need to add a [SAN] section to openssl.cnf file, since openssl doesn't support doing it on the command line. The [SAN] section should contain one line with all the domains in the following format `subjectAltName=DNS:example.com,DNS:www.example.com,DNS:example.org`. Then run the following command:
`openssl req -new -sha256 -key example.com.key -subj "/C=DK/O=MyExampleOrg/CN=example.com" -reqexts SAN -extensions SAN -config /path/to/openssl.cnf

It is possible to do this with a rather unpleasant looking oneliner, which only works in bash. If you are interested you can find it in certgrinder.sh.

### csrgrinder
The csrgrinder script lives on the certgrinder server. It is very simple, just a couple of lines, and it is called over SSH by the certgrinder clients. It takes a PEM formatted CSR on stdin as input, and outputs a signed PEM formatted certificate on stdout.

## More info
Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

