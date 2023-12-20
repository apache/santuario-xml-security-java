Test artifacts for XML Encryption 1.1 Core Interoperability Test Suite  
==================================================

This folder contains test artifacts from the page Test cases for XML Encryption 1.1
https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement

Artefacts are used in the Test class org.apache.xml.security.test.dom.encryption.XMLEncryption11Test



### Script to regenerate the keystores 
Some of the keystores are not recognized by up-to-date java keytool and JCP keystore provider.
The following script can be used to regenerate with openssl so that it can be used with latest java security policy


```bash
#!/usr/bin/env bash

FILENAME=$1
PASSPHRASE="passwd"
# Regenerate a PKCS12 with up-to-date encryption algorithm so that it can be used with latest java security policy
echo "Regenerating PKCS12 file $FILENAME.p12 to $FILENAME-v02.p12"
openssl pkcs12 -in "${FILENAME}.p12" -passin pass:${PASSPHRASE} -out "${FILENAME}.pem"  -nodes -nokeys
openssl pkcs12 -in "${FILENAME}.p12" -passin pass:${PASSPHRASE} -out "${FILENAME}.key" -nodes -nocerts
openssl pkcs12 -export -out "${FILENAME}-v02.p12" -passin pass:${PASSPHRASE} -passout pass:${PASSPHRASE} -inkey "${FILENAME}.key" -in "${FILENAME}.pem" -name "test-certificate"
echo "Cleaning the temporary files ${FILENAME}.pem and ${FILENAME}.key"
rm "${FILENAME}.pem"
rm "${FILENAME}.key"
echo "Done"
```

