#!/bin/bash

set -xe

BASE="$(pwd)/openssl-ca"

if [ ! -e $BASE ]; then
  echo "$BASE missing "
  exit 1
fi

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
