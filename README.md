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

0. Configure http redirect from /.well-known/acme-challenge/ to the certgrinder server.
1. Generate an RSA keypair
2. Generate a new CSR.
3. Cat the CSR over SSH to the certgrinder server, certgrinder server returns the signed certicate on stdout.
4. Run post-renew hook (to reload services with the new cert)
5. Repeat 2-4 daily (but skip if cert has more than 30 days validity).

This is easy to do from crontab with a small script. If you want some inspiration I've included mine in this repo, it is called "certgrinder."

## Files
Certgrinder primarily consists of two files. One is a script that runs on the certgrinder clients, simply called "certgrinder". The other runs on the Certgrinder server and is called "csrgrinder".

### certgrinder
The certgrinder script is meant to be run under a dedicated user and has two tasks.

1. Create an RSA key if one isn't found.
2. Create CSR and use it to get a signed certificate using the certgrinder server

A few things need to be configured near the top of the script, primarily the domain names.

### csrgrinder
The csrgrinder script sits on the certgrinder server and is called over ssh by the certgrinder clients. It takes a CSR on stdin as input and outputs a signed certificate on stdout.

## More info
Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

