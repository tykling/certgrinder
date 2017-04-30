# certgrinder
certgrinder


## Background
Certgrinder is a set of scripts to handle Letsencrypt cert signing on a central host rather than on the servers which need the certificates. Read more at https://blog.tyk.nu/blog/introducing-certgrinder-a-letsencrypt-ssh-proxy/

### Advantages
The primary advantage of this design is that the signing stack and credentials are never exposed on servers with untrusted users on them.

### Terminology
The central host with the signing stack is called the "certgrinder server". The individual servers (the ones that need certificates) are called "certgrinder clients".

### Operation
The theory behind this is simple. Each server (certgrinder client) does the following:

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


## Installation Details

### Certgrinder server
The certgrinder server needs to have the Letsencrypt (or whatever) software signing stack installed and configured. It also needs a dedicated certgrinder user with sudo access to run the certbot binary.

1. Install certbot or other signing software stack
2. Configure credentials for certbot (or whatever)
3. Add a "certgrinder" user
4. Add something like this to sudoers: `certgrinder ALL=(ALL) NOPASSWD: /usr/local/bin/certbot`
5. Add the ssh public key for each certgrinder client (see next section) to .ssh/authorized_keys with appropriate restrictions: `from=2a01:3a0:1:1900:85:235:250:85,command=/usr/local/bin/csrgrinder,no-port-forwarding,no-x11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAX6ArpY9CLqV4H1BmlikEcFVp9geDSeRNNdaEB57jL certgrinder@ircd.tyknet.dk`
6. Install the csrgrinder script to /usr/local/bin/csrgrinder

### Certgrinder clients
The certgrinder clients just need to create a keypair and use that to create the CSR needed to get the certificate. Then cat the CSR over ssh to the certgrinder server and you'll get a signed cert on stdout. This can be done by hand or by the certgrinder script in this repository.

