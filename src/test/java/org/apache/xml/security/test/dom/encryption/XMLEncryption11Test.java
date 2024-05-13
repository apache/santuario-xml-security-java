/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.dom.encryption;

import java.io.*;
import java.lang.System.Logger.Level;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;


/**
 * This is a set of tests that use the test vectors associated with the W3C XML Encryption 1.1 specification:
 *
 * http://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/
 *
 * Note: I had to convert the given .p12 file into a .jks as it could not be loaded with KeyStore.
 */
class XMLEncryption11Test extends XMLEncryption11TestAbstract {
    protected static final System.Logger LOG = System.getLogger(XMLEncryption11Test.class.getName());


    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA2048() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);
            Certificate cert = keyStore.getCertificate("importkey");
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            File file = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/"
                + "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml");

            Document dd = decryptElement(file, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA2048 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA2048EncryptDecrypt() throws Exception {

        assumeFalse(isIBMJdK);

        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes128-gcm");
            EncryptedKey encryptedKey =
                createEncryptedKey(
                    doc,
                    (X509Certificate)cert,
                    sessionKey,
                    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    null,
                    null
                );

            doc =
                encryptDocument(
                    doc,
                    encryptedKey,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#aes128-gcm"
                );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA2048 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA2048EncryptDecryptWithSecureRandom() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes128-gcm");
            EncryptedKey encryptedKey =
                createEncryptedKey(
                                   doc,
                                   (X509Certificate)cert,
                                   sessionKey,
                                   "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                                   "http://www.w3.org/2000/09/xmldsig#sha1",
                                   null,
                                   null,
                                   new SecureRandom()
                    );

            doc =
                encryptDocument(
                                doc,
                                encryptedKey,
                                sessionKey,
                                "http://www.w3.org/2009/xmlenc11#aes128-gcm"
                    );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA2048 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA3072() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            File filename = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/"
                + "cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml");
            Document dd = decryptElement(filename, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA3072 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA3072EncryptDecrypt() throws Exception {
        assumeFalse(isIBMJdK);

        if (haveISOPadding) {
            File keystore = resolveFile(
                "src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes192-gcm");
            EncryptedKey encryptedKey =
                createEncryptedKey(
                    doc,
                    (X509Certificate)cert,
                    sessionKey,
                    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                    "http://www.w3.org/2001/04/xmlenc#sha256",
                    null,
                    null
                );

            doc =
                encryptDocument(
                    doc,
                    encryptedKey,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#aes192-gcm"
                );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA3072 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA3072OAEP() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            File filename = resolveFile(
                "src/test/resources/org/w3c/www/interop/xmlenc-core-11/"
                + "cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml");
            Document dd = decryptElement(filename, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA307OAEP as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @Test
    void testKeyWrappingRSA3072OAEPEncryptDecrypt() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes256-gcm");
            EncryptedKey encryptedKey =
                createEncryptedKey(
                    doc,
                    (X509Certificate)cert,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                    "http://www.w3.org/2001/04/xmldsig-more#sha384",
                    "http://www.w3.org/2009/xmlenc11#mgf1sha1",
                    null
                );

            doc =
                encryptDocument(
                    doc,
                    encryptedKey,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#aes256-gcm"
                );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA2048 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */
    @Test
    void testKeyWrappingRSA4096() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            File filename = resolveFile(
                "src/test/resources/org/w3c/www/interop/xmlenc-core-11/"
                + "cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml");
            Document dd = decryptElement(filename, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA4096 as necessary crypto algorithms are not available");
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */
    @Test
    void testKeyWrappingRSA4096EncryptDecrypt() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes256-gcm");
            EncryptedKey encryptedKey =
                createEncryptedKey(
                    doc,
                    (X509Certificate)cert,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                    "http://www.w3.org/2001/04/xmlenc#sha512",
                    "http://www.w3.org/2009/xmlenc11#mgf1sha1",
                    XMLUtils.decode("ZHVtbXkxMjM=".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                );

            doc =
                encryptDocument(
                    doc,
                    encryptedKey,
                    sessionKey,
                    "http://www.w3.org/2009/xmlenc11#aes256-gcm"
                );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING, "Skipping testRSA2048 as necessary crypto algorithms are not available");
        }
    }

    @Test
    void testKeyWrappingRSA4096EncryptDecryptSHA224() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = loadKeyStore(keystore);

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(f, false);

            Key sessionKey = getSessionKey("http://www.w3.org/2009/xmlenc11#aes256-gcm");
            EncryptedKey encryptedKey =
                    createEncryptedKey(
                            doc,
                            (X509Certificate)cert,
                            sessionKey,
                            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                            Constants.MoreAlgorithmsSpecNS + "sha224",
                            "http://www.w3.org/2009/xmlenc11#mgf1sha224",
                            XMLUtils.decode("ZHVtbXkxMjM=".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    );

            doc =
                    encryptDocument(
                            doc,
                            encryptedKey,
                            sessionKey,
                            "http://www.w3.org/2009/xmlenc11#aes256-gcm"
                    );
            // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

            // Perform decryption
            Document dd = decryptElement(doc, rsaKey, (X509Certificate)cert);
            // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
            checkDecryptedDoc(dd, true);
        } else {
            LOG.log(Level.WARNING,
                    "Skipping testRSA2048 as necessary "
                            + "crypto algorithms are not available"
            );
        }
    }

    /**
     * The KeyAgreement test cases from the W3C test suite using XML as input.
     *
     * https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement
     */
    @ParameterizedTest
    @CsvSource({
            "AGRMNT.1, plaintext.xml, EC-P256_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate, http://www.w3.org/2001/04/xmlenc#kw-aes128, http://www.w3.org/2009/xmlenc11#aes128-gcm, http://www.w3.org/2001/04/xmlenc#sha256",
            "AGRMNT.2, plaintext.xml, EC-P384_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate, http://www.w3.org/2001/04/xmlenc#kw-aes192, http://www.w3.org/2009/xmlenc11#aes192-gcm, http://www.w3.org/2001/04/xmldsig-more#sha384",
            "AGRMNT.3, plaintext.xml, EC-P521_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate, http://www.w3.org/2001/04/xmlenc#kw-aes256, http://www.w3.org/2009/xmlenc11#aes256-gcm, http://www.w3.org/2001/04/xmlenc#sha512",
    })
    void testAgreementKeyEncryptDecryptDocument(String w3cTag,
                                               String data,
                                               String keystoreFile, String keystoreType,
                                               String passwd, String alias,
                                               String keyWrapAlgorithm,
                                               String encryptionAlgorithm,
                                               String kdfAlgorithm) throws Exception {
        Assumptions.assumeTrue(haveISOPadding,
                "Skipping testAgreementKey ["+w3cTag+"] as necessary crypto algorithms are not available");

        KeyStore keyStore = loadKeyStoreFromResource(keystoreFile, passwd, keystoreType);
        Certificate cert = keyStore.getCertificate(alias);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwd.toCharArray()));
        PrivateKey ecKey = pkEntry.getPrivateKey();

        // Perform encryption
        Document doc = loadDocumentFromResource(data);
        Key sessionKey = getSessionKey(encryptionAlgorithm);


        int keyBitLen = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);
        KeyDerivationParameters keyDerivationParameter = ConcatKDFParams
                .createBuilder(keyBitLen, kdfAlgorithm)
                .build();

        AlgorithmParameterSpec parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                keyDerivationParameter);


        EncryptedKey encryptedKey =
                createEncryptedKey(
                        doc,
                        (X509Certificate)cert,
                        sessionKey,
                        keyWrapAlgorithm,
                        parameterSpec, null);


        doc = encryptDocument(
                doc,
                encryptedKey,
                sessionKey,
                encryptionAlgorithm
        );

        Files.write(Paths.get("target","test-enc-"+w3cTag+".xml"), toString(doc.getFirstChild()).getBytes());
        // XMLUtils.outputDOM(doc.getFirstChild(), System.out);

        // Perform decryption
        Document dd = decryptElement(doc, ecKey, (X509Certificate)cert);
        // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
        checkDecryptedDoc(dd, true);
    }

    /**
     * The KeyAgreement test cases from the W3C test suite using XML as input. The method decrypts the document from
     * test page and compares the result with the expected result.
     *
     * https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement
     */
    @ParameterizedTest
    @CsvSource({
            "AGRMNT.1-dec, cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF-1.xml, EC-P256_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate",
            "AGRMNT.2-dec, cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF-2.xml, EC-P384_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate",
            "AGRMNT.3-dec, cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF-3.xml, EC-P521_SHA256WithECDSA-v02.p12, PKCS12, passwd, test-certificate",
    })
    void testAgreementKeyDecryptDocument(String w3cTag,
                                                       String encryptedData,
                                                       String keystoreFile, String keystoreType,
                                                       String passwd, String alias) throws Exception {
        Assumptions.assumeTrue(haveISOPadding,
                "Skipping testAgreementKey ["+w3cTag+"] as necessary crypto algorithms are not available");

        KeyStore keyStore = loadKeyStoreFromResource(keystoreFile, passwd, keystoreType);
        Certificate cert = keyStore.getCertificate(alias);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwd.toCharArray()));
        PrivateKey ecKey = pkEntry.getPrivateKey();

        // get encrypted data from test page
        Document ecryptedXmlDocument = loadDocumentFromResource(encryptedData);
        // Perform decryption
        Document dd = decryptElement(ecryptedXmlDocument, ecKey, (X509Certificate)cert);
        checkDecryptedDoc(dd, true);
    }

    /**
     * The KeyAgreement test cases from the W3C test suite using bytearray as input.
     *
     * https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement
     */
    @ParameterizedTest
    @CsvSource({
            "AGRMNT.4, binary-data.hex, EC-P256.pfx, PKCS12, 1234, certreq-5b4623c8-5790-4b32-b59f-540c8bcfda4a, http://www.w3.org/2001/04/xmlenc#kw-aes128, http://www.w3.org/2009/xmlenc11#aes128-gcm, http://www.w3.org/2001/04/xmlenc#sha256",
            "AGRMNT.5, binary-data.hex, EC-P384.pfx, PKCS12, 1234, certreq-4c7c6242-e408-4391-a7e7-1a87a2ef2ba8, http://www.w3.org/2001/04/xmlenc#kw-aes192, http://www.w3.org/2009/xmlenc11#aes192-gcm, http://www.w3.org/2001/04/xmldsig-more#sha384",
            "AGRMNT.6, binary-data.hex, EC-P521.pfx, PKCS12, 1234, certreq-61afb173-5eab-475a-8c54-0cb792c82820, http://www.w3.org/2001/04/xmlenc#kw-aes256, http://www.w3.org/2009/xmlenc11#aes256-gcm, http://www.w3.org/2001/04/xmlenc#sha512"
    })
    void testAgreementKeyEncryptDecryptData(String w3cTag,
                                               String resourceHexFileName,
                                               String keystoreFile, String keystoreType,
                                               String passwd, String alias,
                                               String keyWrapAlgorithm,
                                               String encryptionAlgorithm,
                                               String kdfAlgorithm) throws Exception {
        Assumptions.assumeTrue(haveISOPadding,
                "Skipping testAgreementKey ["+w3cTag+"] as necessary crypto algorithms are not available");

        KeyStore keyStore = loadKeyStoreFromResource(keystoreFile, passwd, keystoreType);
        Certificate cert = keyStore.getCertificate(alias);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwd.toCharArray()));
        PrivateKey ecKey = pkEntry.getPrivateKey();

        // Perform encryption
        byte[] testData = hexFileContentByteArray(resourceHexFileName);
        // create empty document for EncryptedKey
        Document doc = DEFAULT_DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().newDocument();

        Key sessionKey = getSessionKey(encryptionAlgorithm);


        int keyBitLen = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);
        KeyDerivationParameters keyDerivationParameter = ConcatKDFParams
                .createBuilder(keyBitLen, kdfAlgorithm)
                .build();
        AlgorithmParameterSpec parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                keyDerivationParameter);


        EncryptedKey encryptedKey =
                createEncryptedKey(
                        doc,
                        (X509Certificate)cert,
                        sessionKey,
                        keyWrapAlgorithm,
                        parameterSpec, null);


        doc = encryptData(
                doc,
                encryptedKey,
                sessionKey,
                encryptionAlgorithm,
                new ByteArrayInputStream(testData)
        );

        Files.write(Paths.get("target","test-enc-"+w3cTag+".xml"), toString(doc.getFirstChild()).getBytes());
        // Perform decryption
        byte[] result  = decryptData(doc, ecKey, (X509Certificate)cert);
        // XMLUtils.outputDOM(dd.getFirstChild(), System.out);
        assertNotNull(result);
        assertArrayEquals(testData, result);
    }


    /**
     * The KeyAgreement test cases from the W3C test suite using bytearray as input.
     *
     * https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement
     */
    @ParameterizedTest
    @CsvSource({
            "AGRMNT.4-dec, binary-data.hex, cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF-4.xml, EC-P256.pfx, PKCS12, 1234, certreq-5b4623c8-5790-4b32-b59f-540c8bcfda4a",
            "AGRMNT.5-dec, binary-data.hex, cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF-5.xml, EC-P384.pfx, PKCS12, 1234, certreq-4c7c6242-e408-4391-a7e7-1a87a2ef2ba8",
            "AGRMNT.6-dec, binary-data.hex, cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF-6.xml, EC-P521.pfx, PKCS12, 1234, certreq-61afb173-5eab-475a-8c54-0cb792c82820"
    })
    void testAgreementKeyDecryptData(String w3cTag,
                                                   String resourceHexFileName,
                                                   String decryptResourceData,
                                                   String keystoreFile, String keystoreType,
                                                   String passwd, String alias) throws Exception {
        Assumptions.assumeTrue(haveISOPadding,
                "Skipping testAgreementKey ["+w3cTag+"] as necessary crypto algorithms are not available");

        KeyStore keyStore = loadKeyStoreFromResource(keystoreFile, passwd, keystoreType);
        Certificate cert = keyStore.getCertificate(alias);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwd.toCharArray()));
        PrivateKey ecKey = pkEntry.getPrivateKey();

        // Perform encryption
        byte[] testData = hexFileContentByteArray(resourceHexFileName);

        // get encrypted data from test page
        Document doc = loadDocumentFromResource(decryptResourceData);

        // Perform decryption
        byte[] result  = decryptData(doc, ecKey, (X509Certificate)cert);
        // compare results
        assertNotNull(result);
        assertArrayEquals(testData, result);
    }
}
