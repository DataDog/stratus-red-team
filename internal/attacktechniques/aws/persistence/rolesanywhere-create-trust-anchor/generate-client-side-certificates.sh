#!/bin/bash
# Utility script to generate a client-side certificate properly signed by ca.key
set -x
set -e
openssl genrsa -out client.key 4096
cat > /tmp/ssl.conf <<EOF
[ req ]
distinguished_name       = req_distinguished_name

[ v3_ca ]
keyUsage                 = critical, digitalSignature
subjectKeyIdentifier     = hash
basicConstraints         = critical, CA:FALSE

[ req_distinguished_name ]
countryName              = CH
commonName 		           = sample-user
EOF
openssl req -new -sha256 -key client.key  -nodes -out /tmp/client.csr -config /tmp/ssl.conf
openssl x509 -sha256 -req -days 3650 -extensions v3_ca -extfile /tmp/ssl.conf -in /tmp/client.csr -CA ca.crt -CAkey ca.key -out client.crt -CAcreateserial