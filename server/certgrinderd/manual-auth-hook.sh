#!/bin/sh

# $CERTBOT_DOMAIN is the domain being authenticated.
# $CERTBOT_VALIDATION is the validation string
# $CERTBOT_TOKEN is the requested filename (for http-01 only)
# $ACMEZONE is set by Certgrinder and contains the zone we are working with (only for DNS-01)
# $WEBROOT is set by Certgrinder and contains the path to the webroot (only for HTTP-01)

logger "Running $0 - CERTBOT_DOMAIN: ${CERTBOT_DOMAIN} - CERTBOT_VALIDATION: ${CERTBOT_VALIDATION} - CERTBOT_TOKEN: ${CERTBOT_TOKEN} - ACMEZONE: ${ACMEZONE} - WEBROOT: ${WEBROOT}"

if [ -z "$CERTBOT_TOKEN" ]; then
        # This is a DNS-01 challenge
        (echo "update add ${CERTBOT_DOMAIN}.${ACMEZONE}. 3600 TXT \"${CERTBOT_VALIDATION}\""; echo "send") | /usr/local/bin/nsupdate -k /usr/local/etc/namedb/rndc.key
else
        # This is a HTTP-01 challenge
        if [ -z "${WEBROOT}" -o -z "${CERTBOT_TOKEN}" ]; then
            logger "Either WEBROOT or CERTBOT_TOKEN are empty, manual-auth-hook bailing out"
            exit 1
        fi
        if [ ! -d "${WEBROOT}/.well-known/acme-challenge" ]; then
                mkdir -p "${WEBROOT}/.well-known/acme-challenge"
        fi
        echo "${CERTBOT_VALIDATION}" > "${WEBROOT}/.well-known/acme-challenge/${CERTBOT_TOKEN}"
fi

