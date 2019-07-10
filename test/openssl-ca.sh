#!/bin/bash

set -xe

ORG="Test Org"
CA="Provisioning CA"

# After the CRL expires, signatures cannot be verified anymore
CRL="-crldays 5000"

BASE="$(pwd)/openssl-ca"

if [ -e $BASE ]; then
  echo "$BASE already exists"
  exit 1
fi

mkdir -p $BASE/root/{private,certs}
touch $BASE/root/index.txt
echo 01 > $BASE/root/serial

mkdir -p $BASE/rel/{private,certs}
touch $BASE/rel/index.txt
echo 01 > $BASE/rel/serial

mkdir -p $BASE/dev/{private,certs}
touch $BASE/dev/index.txt
echo 01 > $BASE/dev/serial

mkdir -p $BASE/dir/{private,certs,hash}
touch $BASE/dir/index.txt
echo 01 > $BASE/dir/serial
mkdir -p $BASE/dir/hash/{a,ab}

cat > $BASE/openssl.cnf <<EOF
[ ca ]
default_ca      = CA_default            # The default ca section

[ CA_default ]

dir            = .                     # top dir
database       = \$dir/index.txt        # index file.
new_certs_dir  = \$dir/certs            # new certs dir

certificate    = \$dir/ca.cert.pem       # The CA cert
serial         = \$dir/serial           # serial no file
private_key    = \$dir/private/ca.key.pem# CA private key
RANDFILE       = \$dir/private/.rand    # random number file

default_startdate = 19700101000000Z
default_enddate = 99991231235959Z
default_crl_days= 30                   # how long before next CRL
default_md     = sha256                # md to use

policy         = policy_any            # default policy
email_in_dn    = no                    # Don't add the email into cert DN

name_opt       = ca_default            # Subject name display option
cert_opt       = ca_default            # Certificate display option
copy_extensions = none                 # Don't copy extensions from request

[ policy_any ]
organizationName       = match
commonName             = supplied

[ req ]
default_bits           = 2048
distinguished_name     = req_distinguished_name
x509_extensions        = v3_leaf
encrypt_key = no
default_md = sha256

[ req_distinguished_name ]
commonName                     = Common Name (eg, YOUR name)
commonName_max                 = 64

[ v3_ca ]

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:TRUE

[ v3_inter ]

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:TRUE,pathlen:0

[ v3_leaf ]

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:FALSE
EOF

export OPENSSL_CONF=$BASE/openssl.cnf

echo "Root CA"
cd $BASE/root
openssl req -newkey rsa -keyout private/ca.key.pem -out ca.csr.pem -subj "/O=$ORG/CN=$ORG $CA Root"
openssl ca -batch -selfsign -extensions v3_ca -in ca.csr.pem -out ca.cert.pem -keyfile private/ca.key.pem

echo "Release Intermediate CA"
cd $BASE/rel
openssl req -newkey rsa -keyout private/ca.key.pem -out ca.csr.pem -subj "/O=$ORG/CN=$ORG $CA Release"
cd $BASE/root
openssl ca -batch -extensions v3_inter -in $BASE/rel/ca.csr.pem -out $BASE/rel/ca.cert.pem

echo "Development Intermediate CA"
cd $BASE/dev
openssl req -newkey rsa -keyout private/ca.key.pem -out ca.csr.pem -subj "/O=$ORG/CN=$ORG $CA Development"
cd $BASE/root
openssl ca -batch -extensions v3_inter -in $BASE/dev/ca.csr.pem -out $BASE/dev/ca.cert.pem

echo "Autobuilder Signing Keys 1&2"
cd $BASE/dev
openssl req -newkey rsa -keyout private/autobuilder-1.pem -out autobuilder-1.csr.pem -subj "/O=$ORG/CN=$ORG Autobuilder-1"
openssl ca -batch -extensions v3_leaf -in autobuilder-1.csr.pem -out autobuilder-1.cert.pem
openssl req -newkey rsa -keyout private/autobuilder-2.pem -out autobuilder-2.csr.pem -subj "/O=$ORG/CN=$ORG Autobuilder-2"
openssl ca -batch -extensions v3_leaf -in autobuilder-2.csr.pem -out autobuilder-2.cert.pem

echo "Revoke Autobuilder 2"
openssl ca -revoke autobuilder-2.cert.pem 

echo "Release Signing Key"
cd $BASE/rel
openssl req -newkey rsa -keyout private/release-1.pem -out release-1.csr.pem -subj "/O=$ORG/CN=$ORG Release-1"
openssl ca -batch -extensions v3_leaf -in release-1.csr.pem -out release-1.cert.pem
openssl req -newkey rsa -keyout private/release-2018.pem -out release-2018.csr.pem -subj "/O=$ORG/CN=$ORG Release-2018"
openssl ca -batch -extensions v3_leaf -in release-2018.csr.pem -out release-2018.cert.pem -startdate 20180101000000Z -enddate 20190701000000Z

echo "Generate CRL"
cd $BASE/root
openssl ca -gencrl $CRL -out crl.pem
cd $BASE/rel
openssl ca -gencrl $CRL -out crl.pem
cd $BASE/dev
openssl ca -gencrl $CRL -out crl.pem

echo "Build CA PEM"
cd $BASE
cat root/ca.cert.pem root/crl.pem rel/crl.pem dev/crl.pem > provisioning-ca.pem
cat root/ca.cert.pem root/crl.pem rel/ca.cert.pem rel/crl.pem dev/ca.cert.pem dev/crl.pem > dev-ca.pem
cat root/ca.cert.pem root/crl.pem dev/ca.cert.pem dev/crl.pem > dev-only-ca.pem
cat root/ca.cert.pem root/crl.pem rel/ca.cert.pem rel/crl.pem > rel-ca.pem

echo "Build Directory Test Keys"
cd $BASE/dir
openssl req -newkey rsa -keyout private/a.key.pem -out a.csr.pem -subj "/O=$ORG/CN=$ORG $CA A"
openssl ca -batch -selfsign -extensions v3_ca -in a.csr.pem -out a.cert.pem -keyfile private/a.key.pem
openssl req -newkey rsa -keyout private/b.key.pem -out b.csr.pem -subj "/O=$ORG/CN=$ORG $CA B"
openssl ca -batch -selfsign -extensions v3_ca -in b.csr.pem -out b.cert.pem -keyfile private/b.key.pem

echo "Build Directory Hash Test Directories"
cd $BASE
DIRHASH_A="$BASE/dir/hash/a"
DIRHASH_AB="$BASE/dir/hash/ab"
mkdir -p $DIRHASH_A $DIRHASH_AB
cp dir/a.cert.pem $DIRHASH_A/$(openssl x509 -in dir/a.cert.pem -hash -noout).0
cp dir/a.cert.pem $DIRHASH_AB/$(openssl x509 -in dir/a.cert.pem -hash -noout).0
cp dir/b.cert.pem $DIRHASH_AB/$(openssl x509 -in dir/b.cert.pem -hash -noout).0

cd $BASE
cat > manifest <<EOF
# example update manifest

[update]
compatible=FooCorp Super BarBazzer
version=2015.04-1

[keyring]
archive=release.tar

[handler]
filename=custom_handler.sh

[image.rootfs]
sha256=b14c1457dc10469418b4154fef29a90e1ffb4dddd308bf0f2456d436963ef5b3
filename=rootfs.ext4

[image.appfs]
sha256=ecf4c031d01cb9bfa9aa5ecfce93efcf9149544bdbf91178d2c2d9d1d24076ca
filename=appfs.ext4
EOF

echo "Sign and check with Release-1"
openssl cms -sign -in manifest -out manifest-r1.sig -signer rel/release-1.cert.pem -inkey rel/private/release-1.pem -outform DER -nosmimecap -binary -certfile rel/ca.cert.pem
openssl cms -verify -in manifest-r1.sig -content manifest -inform DER -binary -crl_check -CAfile provisioning-ca.pem || echo FAILED

echo "Sign and check with Autobuilder-1"
openssl cms -sign -in manifest -out manifest-a1.sig -signer dev/autobuilder-1.cert.pem -inkey dev/private/autobuilder-1.pem -outform DER -nosmimecap -binary -certfile dev/ca.cert.pem
openssl cms -verify -in manifest-a1.sig -content manifest -inform DER -binary -crl_check -CAfile provisioning-ca.pem || echo FAILED

echo "Sign and check with Autobuilder-2 (revoked)"
openssl cms -sign -in manifest -out manifest-a2.sig -signer dev/autobuilder-2.cert.pem -inkey dev/private/autobuilder-2.pem -outform DER -nosmimecap -binary -certfile dev/ca.cert.pem
echo "  without CRL"
openssl cms -verify -in manifest-a2.sig -content manifest -inform DER -binary -CAfile root/ca.cert.pem || echo FAILED
echo "  with CRL"
openssl cms -verify -in manifest-a2.sig -content manifest -inform DER -binary -crl_check -CAfile provisioning-ca.pem && echo FAILED

echo "Encrypt and decrypt with Release-1"
openssl cms -encrypt -text -in manifest -aes256 -out manifest.mail rel/release-1.cert.pem
openssl cms -decrypt -text -in manifest.mail -recip rel/release-1.cert.pem -inkey rel/private/release-1.pem 
