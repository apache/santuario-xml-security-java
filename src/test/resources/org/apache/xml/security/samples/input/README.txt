The file describes how keys for the test are generated. If you are adding new certificates
please document creation procedure or source here.

====
ecbrainpool.p12

Install latest OpenSSL 3.2.0 [23 Nov 2023], or just check the support brainpool EC.
(https://www.openssl.org/news/openssl-3.2-notes.html)

openssl ecparam -list_curves

To generate the certificate for the brainpool curves, use the following script:
create-brainpool-keystore.sh
-----
#!/bin/bash

ALL_CERTS="brainpoolP256r1 brainpoolP384r1 brainpoolP512r1"
KS_FILENAME="brainpool.p12"
PASSPHRASE="security"


for cert in ${ALL_CERTS}; \
do \
    echo "Generating certificate for ${cert}"; \
    openssl ecparam -name ${cert} -genkey -noout -out ${cert}.pem
    openssl ec -in ${cert}.pem -pubout -out ${cert}.pub
    openssl req -x509 -nodes -sha256 -days 3650 \
        -subj "/CN=${cert}/OU=eDeliveryAS4-2.0/OU=santuario/O=apache/C=EU" \
        -addext "keyUsage=digitalSignature,keyEncipherment,dataEncipherment,cRLSign,keyCertSign" \
        -addext "extendedKeyUsage=serverAuth,clientAuth" \
        -key ${cert}.pem -out ${cert}.crt

    echo "importing ${cert} to keystore";
    openssl pkcs12 -export -out ${cert}.pfx -name ${cert} \
            -inkey ${cert}.pem -in ${cert}.crt -passout pass:${PASSPHRASE}


   echo "Merge ${cert} to common keystore";
   /opt/java/jdk-17.0.9/bin/keytool -importkeystore -destkeystore ${KS_FILENAME} -deststoretype PKCS12 \
        -destkeypass ${PASSPHRASE} -deststorepass ${PASSPHRASE} \
        -srckeystore ${cert}.pfx -srcstoretype PKCS12  \
        -srcstorepass ${PASSPHRASE}  -srckeypass ${PASSPHRASE} \
        -destalias ${cert} -srcalias ${cert}

  echo "clean temp files for the ${cert}";
  rm -f ${cert}.pem ${cert}.pub ${cert}.crt ${cert}.pfx;
done
-----

====
ecdsa.jks

keytool -genkeypair -keystore ecdsa.jks -alias secp256r1 -keyalg EC -groupname secp256r1 \
        -storepass security -keypass security \
        -dname "CN=secp256r1,OU=ecdsa, OU=xmlsec,O=apache,C=EU" \
        -validity 3650
=====


