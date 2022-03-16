#!/bin/bash

set -xe

BASE="$(pwd)/openssl-enc"

mkdir -p ${BASE}/keys/rsa-4096
cd ${BASE}/keys/rsa-4096
echo "Generating 10 RSA 4096 key pairs.."
for i in $(seq 0 9); do
	i="$(printf "%03d" $i)"
	echo -n "."
	openssl req -x509 -newkey rsa:4096 -nodes -keyout private-key-$i.pem -out cert-$i.pem -days 365250 -subj "/O=Test Org/CN=Test Org Development $i" > /dev/null 2>&1
done

cat ${BASE}/keys/rsa-4096/cert-*.pem > ${BASE}/keys/rsa-4096/certs.pem

mkdir -p ${BASE}/keys/ecc
cd ${BASE}/keys/ecc
echo "Generating 10 ECC (prime256v1) key pairs.."
for i in $(seq 0 9); do
	i="$(printf "%03d" $i)"
	echo -n "."
	openssl ecparam -name prime256v1 -genkey -noout -out private-key-$i.pem > /dev/null
	openssl ec -in private-key-$i.pem -pubout -out public-key-$i.pem > /dev/null
	openssl req -new -x509 -key private-key-$i.pem -out cert-$i.pem -days 365250 -subj "/O=Test Org/CN=Test Org Development $i" > /dev/null
done

cat ${BASE}/keys/ecc/cert-*.pem > ${BASE}/keys/ecc/certs.pem
