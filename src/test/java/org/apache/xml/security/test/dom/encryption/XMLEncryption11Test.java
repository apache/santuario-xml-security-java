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
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.AgreementMethod;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.keys.KeyInfoEnc;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

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
class XMLEncryption11Test {

    private static final DocumentBuilderFactory DEFAULT_DOCUMENT_BUILDER_FACTORY;
    static {
        DEFAULT_DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
        DEFAULT_DOCUMENT_BUILDER_FACTORY.setNamespaceAware(true);
    }
    private static final String RESOURCE_FOLDER = "/org/w3c/www/interop/xmlenc-core-11/";

    private static String cardNumber;
    private static int nodeCount = 0;
    private boolean haveISOPadding;
    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    private static final Logger LOG = System.getLogger(XMLEncryption11Test.class.getName());


    /**
     *  Constructor XMLEncryption11Test
     */
    public XMLEncryption11Test() throws Exception {

        // Create the comparison strings
        File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
        Document doc = XMLUtils.read(f, false);

        cardNumber = retrieveCCNumber(doc);

        // Count the nodes in the document as a secondary test
        nodeCount = countNodes(doc);

        // Initialise the library
        org.apache.xml.security.Init.init();

        // Check what algorithms are available

        haveISOPadding = false;
        String algorithmId = JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        if (algorithmId != null) {
            try {
                if (Cipher.getInstance(algorithmId) != null) {
                    haveISOPadding = true;
                }
            } catch (NoSuchAlgorithmException nsae) {
                //
            } catch (NoSuchPaddingException nspe) {
                //
            }
        }
    }

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
        KeyDerivationParameters keyDerivationParameter = new ConcatKDFParams(keyBitLen, kdfAlgorithm);
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
        KeyDerivationParameters keyDerivationParameter = new ConcatKDFParams(keyBitLen, kdfAlgorithm);
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

    private KeyStore loadKeyStore(File keystore)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(getKeystoreTypeForFileName(keystore.getName()));
        try (FileInputStream inputStream = new FileInputStream(keystore)) {
            keyStore.load(inputStream, "passwd".toCharArray());
        }
        return keyStore;
    }

    private KeyStore loadKeyStoreFromResource(String filename, String passwd, String keystoreType)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try ( InputStream keystoreIS = getResourceInputStream(filename);) {
            keyStore.load(keystoreIS, passwd!=null?passwd.toCharArray():null);
        }
        return keyStore;
    }

    private Document loadDocumentFromResource(String resourceName)
            throws IOException, XMLParserException {

        try (InputStream dataXMLInputStream = getResourceInputStream(resourceName)){
            return XMLUtils.read(dataXMLInputStream, false);
        }
    }

    private String getKeystoreTypeForFileName(String filename){
        return filename.toLowerCase().endsWith(".p12") ? "PKCS12" : "JKS";
    }

    /**
     * Method decryptElement
     *
     * Take a key, encryption type and a file, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param decKey The Key to use for decryption
     * @param encCert The certificate used to encrypt the key
     */
    private Document decryptElement(File file, Key decKey, X509Certificate encCert) throws Exception {
        // Parse the document in question
        Document doc;
        try (FileInputStream inputStream = new FileInputStream(file)) {
            doc = XMLUtils.read(inputStream, false);
        }
        return decryptElement(doc, decKey, encCert);
    }

    /**
     * Method decryptElement
     *
     * Take a key, encryption type and a document, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param doc the XML document wrrapping the encrypted data
     * @param decKey The Key to use for decryption
     * @param encCert The certificate used to encrypt the key
     */
    private Document decryptElement(Document doc, Key decKey, X509Certificate encCert) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance();

        // Need to pre-load the Encrypted Data so we can get the key info
        Element ee = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(doc, ee);

        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        KeyInfoEnc kiek = (KeyInfoEnc)encryptedKey.getKeyInfo();
        if (kiek.containsAgreementMethod()){
            AgreementMethod agreementMethod = kiek.itemAgreementMethod(0);
            kiek = agreementMethod.getRecipientKeyInfo();
        }
        X509Data certData = kiek.itemX509Data(0);
        XMLX509Certificate xcert = certData.itemCertificate(0);
        X509Certificate cert = xcert.getX509Certificate();
        assertEquals(encCert, cert);

        XMLCipher cipher2 = XMLCipher.getInstance();
        cipher2.init(XMLCipher.UNWRAP_MODE, decKey);
        Key key = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());

        cipher.init(XMLCipher.DECRYPT_MODE, key);
        Document dd = cipher.doFinal(doc, ee);

        return dd;
    }

    /**
     * Method decryptElement
     *
     * Take a key, encryption type and a document, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param doc the XML document wrrapping the encrypted data
     * @param decKey The Key to use for decryption
     * @param rsaCert The certificate used to encrypt the key
     *
     */
    private byte[] decryptData(Document doc, Key decKey, X509Certificate rsaCert) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance();

        // Need to pre-load the Encrypted Data so we can get the key info
        Element ee = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(doc, ee);

        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        KeyInfoEnc kiek = (KeyInfoEnc)encryptedKey.getKeyInfo();
        if (kiek.containsAgreementMethod()){
            AgreementMethod agreementMethod = kiek.itemAgreementMethod(0);
            kiek = agreementMethod.getRecipientKeyInfo();
        }
        X509Data certData = kiek.itemX509Data(0);
        XMLX509Certificate xcert = certData.itemCertificate(0);
        X509Certificate cert = xcert.getX509Certificate();
        assertEquals(rsaCert, cert);

        XMLCipher cipher2 = XMLCipher.getInstance();
        cipher2.init(XMLCipher.UNWRAP_MODE, decKey);
        Key key = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());

        cipher.init(XMLCipher.DECRYPT_MODE, key);
        return cipher.decryptToByteArray(ee);
    }

    /**
     * Create an EncryptedKey object using the given parameters.
     */
    private EncryptedKey createEncryptedKey(
        Document doc,
        X509Certificate rsaCert,
        Key sessionKey,
        String encryptionMethod,
        String digestMethod,
        String mgfAlgorithm,
        byte[] oaepParams
    ) throws Exception {
        return createEncryptedKey(doc, rsaCert, sessionKey, encryptionMethod,
                                  digestMethod, mgfAlgorithm, oaepParams, null);
    }

    private EncryptedKey createEncryptedKey(
        Document doc,
        X509Certificate rsaCert,
        Key sessionKey,
        String encryptionMethod,
        String digestMethod,
        String mgfAlgorithm,
        byte[] oaepParams,
        SecureRandom random
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod, null, digestMethod);

        cipher.init(XMLCipher.WRAP_MODE, rsaCert.getPublicKey());

        EncryptedKey encryptedKey = cipher.encryptKey(doc, sessionKey, mgfAlgorithm, oaepParams, random);

        KeyInfo builderKeyInfo = encryptedKey.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            encryptedKey.setKeyInfo(builderKeyInfo);
        }

        X509Data x509Data = new X509Data(doc);
        x509Data.addCertificate(rsaCert);
        builderKeyInfo.add(x509Data);

        return encryptedKey;
    }

    private EncryptedKey createEncryptedKey(
            Document doc,
            X509Certificate cert,
            Key sessionKey,
            String encryptionMethod,
            AlgorithmParameterSpec params,
            SecureRandom random
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod, null, null);

        cipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());

        EncryptedKey encryptedKey = cipher.encryptKey(doc, sessionKey, params, random);

        KeyInfo builderKeyInfo = encryptedKey.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfoEnc(doc);
            encryptedKey.setKeyInfo(builderKeyInfo);
        }

        X509Data x509Data = new X509Data(doc);
        x509Data.addCertificate(cert);
        if (builderKeyInfo instanceof KeyInfoEnc
                && ((KeyInfoEnc)builderKeyInfo).lengthAgreementMethod()>0) {
            AgreementMethod agreementMethod = ((KeyInfoEnc)builderKeyInfo).itemAgreementMethod(0);
            agreementMethod.getRecipientKeyInfo().add(x509Data);
        } else {
            builderKeyInfo.add(x509Data);
        }
        return encryptedKey;
    }

    /**
     * Generate a session key using the given algorithm
     */
    private Key getSessionKey(String encryptionMethod) throws Exception {
        // Generate a session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        if (encryptionMethod.contains("128")) {
            keyGen.init(128);
        } else if (encryptionMethod.contains("192")) {
            keyGen.init(192);
        } else if (encryptionMethod.contains("256")) {
            keyGen.init(256);
        }
        return keyGen.generateKey();
    }

    /**
     * Encrypt a Document using the given parameters.
     */
    private Document encryptDocument(
        Document doc,
        EncryptedKey encryptedKey,
        Key sessionKey,
        String encryptionMethod
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod);

        cipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        EncryptedData builder = cipher.getEncryptedData();

        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builder.setKeyInfo(builderKeyInfo);
        }

        builderKeyInfo.add(encryptedKey);

        return cipher.doFinal(doc, doc.getDocumentElement());
    }


    /**
     * Encrypt a Document using the given parameters.
     */
    private Document encryptData(
            Document doc,
            EncryptedKey encryptedKey,
            Key sessionKey,
            String encryptionMethod,
            InputStream dataToEncrypt
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod);

        cipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        EncryptedData builder = cipher.getEncryptedData();

        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builder.setKeyInfo(builderKeyInfo);
        }

        builderKeyInfo.add(encryptedKey);

        EncryptedData endData = cipher.encryptData(doc, null, dataToEncrypt);
        Element encDataElement =  cipher.martial(endData);
        doc.appendChild(encDataElement);
        return doc;
    }

    /**
     * Method countNodes
     *
     * Recursively count the number of nodes in the document
     *
     * @param n Node to count beneath
     */
    private static int countNodes(Node n) {

        if (n == null) {
            return 0;  // Paranoia
        }

        int count = 1;  // Always count myself
        Node c = n.getFirstChild();

        while (c != null) {
            count += countNodes(c);
            c = c.getNextSibling();
        }

        return count;
    }

    /**
     * Method retrieveCCNumber
     *
     * Retrieve the credit card number from the payment info document
     *
     * @param doc The document to retrieve the card number from
     * @return The retrieved credit card number
     * @throws XPathExpressionException
     */
    private static String retrieveCCNumber(Document doc)
        throws javax.xml.transform.TransformerException,
        XPathExpressionException {

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        Map<String, String> namespace = new HashMap<>();
        namespace.put("x", "urn:example:po");
        DSNamespaceContext context = new DSNamespaceContext(namespace);
        xpath.setNamespaceContext(context);

        String expression = "//x:Number/text()";
        Node ccnumElt =
            (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);

        if (ccnumElt != null) {
            return ccnumElt.getNodeValue();
        }

        return null;
    }

    /*
     * Check we have retrieved a Credit Card number and that it is OK
     * Check that the document has the correct number of nodes
     */
    private void checkDecryptedDoc(Document d, boolean doNodeCheck) throws Exception {

        String cc = retrieveCCNumber(d);
        LOG.log(Level.DEBUG, "Retrieved Credit Card : " + cc);
        assertEquals(cardNumber, cc);

        // Test cc numbers
        if (doNodeCheck) {
            int myNodeCount = countNodes(d);

            assertTrue(
                myNodeCount > 0 && myNodeCount == nodeCount, "Node count mismatches"
            );
        }
    }

    public static byte[] hexFileContentByteArray(String fileName) throws IOException {
        byte[] data;
        try (InputStream is = getResourceInputStream(fileName)) {
            int l = is.available() / 2;
            data = new byte[l];
            byte[] charByte = new byte[2];
            for (int i = 0; i < l; i++) {
                is.read(charByte);
                data[i] = (byte) ((Character.digit(charByte[0], 16) << 4)
                        + Character.digit(charByte[1], 16));
            }
        }
        return data;
    }

    /**
     *  Method returns  a resource input stream object from resources folder '/org/w3c/www/interop/xmlenc-core-11/'
     * @param resourceName name of the resource file
     * @return InputStream object or null if resource not found
     */
    public static InputStream getResourceInputStream(String resourceName) {
        return XMLEncryption11Test.class.getResourceAsStream(RESOURCE_FOLDER + resourceName);
    }


    private String toString (Node n) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

            c14n.canonicalizeSubtree(n, baos);
            baos.flush();

            return baos.toString(StandardCharsets.UTF_8);
        }
    }
}
