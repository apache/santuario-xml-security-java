The file describes how keys for the test are generated. If you are adding new certificates
please document creation procedure or source here.

====
ecbrainpool.p12

Following commands are used to generate self-signed certificates/keys for brainpool curves:
 brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
 To generate certificate used JDK 11 - 15  and remove curve from jdk.disabled.namedCurves property
 in the java.security file. (For generating ecbrainpool.p12 the jdk-11.0.22 was used)
To generated for brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 use the following command:

keytool -genkeypair -keystore ecbrainpool.p12 -alias brainpoolP256r1 -keyalg EC  -groupname brainpoolP256r1 \
    -storepass security -keypass security  \
    -dname "CN=brainpoolP256r1, OU=eDeliveryAS4-2.0,OU=wss4j,O=apache,C=EU" \
    -validity 3650

keytool -genkeypair -keystore ecbrainpool.p12 -alias brainpoolP384r1 -keyalg EC  -groupname brainpoolP384r1 \
    -storepass security -keypass security  \
    -dname "CN=brainpoolP384r1, OU=eDeliveryAS4-2.0,OU=wss4j,O=apache,C=EU" \
    -validity 3650

keytool -genkeypair -keystore ecbrainpool.p12 -alias brainpoolP512r1 -keyalg EC  -groupname brainpoolP512r1 \
    -storepass security -keypass security  \
    -dname "CN=brainpoolP512r1, OU=eDeliveryAS4-2.0,OU=wss4j,O=apache,C=EU" \
    -validity 3650

=====

