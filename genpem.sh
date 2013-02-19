#!/bin/bash

openssl genrsa -aes128 -out cakey.pem 1024
openssl req -x509 -newkey rsa:1024 -out cacert.pem -outform PEM -days 365 -key cakey.pem

openssl genrsa -aes128 -out key.pem 1024
openssl req -new -key key.pem -keyform PEM -out req.pem -outform PEM

openssl ca -in req.pem -out cert.pem -config ca.conf

openssl ca -selfsign -in req.pem -out cert.pem -config ca.conf

openssl verify -CAfile cacert.pem cert.pem

openssl genrsa -aes128 -out spri.pem 1024

openssl rsa -in spri.pem -pubout -out spub.pem