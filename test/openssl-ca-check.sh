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
if openssl cms -verify -in manifest-a2.sig -content manifest -inform DER -binary -crl_check -CAfile provisioning-ca.pem; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi

echo "Encrypt and decrypt with Release-1"
openssl cms -encrypt -text -in manifest -aes256 -out manifest.mail rel/release-1.cert.pem
openssl cms -decrypt -text -in manifest.mail -recip rel/release-1.cert.pem -inkey rel/private/release-1.pem 

echo "Sign and check with XKU timeStamping"
openssl cms -sign -in manifest -out manifest-ts1.sig -signer root/xku-timeStamping.cert.pem -inkey root/private/xku-timeStamping.pem -outform DER -nosmimecap -binary
if openssl cms -verify -in manifest-ts1.sig -content manifest -inform DER -binary -crl_check -CAfile root-ca.pem; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi
openssl cms -verify -in manifest-ts1.sig -content manifest -inform DER -binary -crl_check -CAfile root-ca.pem -purpose any || echo FAILED
openssl cms -verify -in manifest-ts1.sig -content manifest -inform DER -binary -crl_check -CAfile root-ca.pem -purpose timestampsign || echo FAILED
if openssl cms -verify -in manifest-ts1.sig -content manifest -inform DER -binary -crl_check -CAfile root-ca.pem -purpose sslserver; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi

echo "Sign and check with XKU emailProtection"
openssl cms -sign -in manifest -out manifest-ep1.sig -signer dev/xku-emailProtection.cert.pem -inkey dev/private/xku-emailProtection.pem -outform DER -nosmimecap -binary -certfile dev/ca.cert.pem
openssl cms -verify -in manifest-ep1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem || echo FAILED
openssl cms -verify -in manifest-ep1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem -purpose any || echo FAILED
openssl cms -verify -in manifest-ep1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem -purpose smimesign || echo FAILED
if openssl cms -verify -in manifest-ep1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem -purpose sslserver; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi

echo "Sign and check with XKU codeSigning"
openssl cms -sign -in manifest -out manifest-cs1.sig -signer dev/xku-codeSigning.cert.pem -inkey dev/private/xku-codeSigning.pem -outform DER -nosmimecap -binary -certfile dev/ca.cert.pem
if openssl cms -verify -in manifest-cs1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi
openssl cms -verify -in manifest-cs1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem -purpose any || echo FAILED
# testing for codesign using cms verify doesn't seem to be possible yet
if openssl cms -verify -in manifest-cs1.sig -content manifest -inform DER -binary -crl_check -CAfile dev-ca.pem -purpose smimesign; then
  echo UNEXPECTED; exit 1
else
  echo EXPECTED
fi
