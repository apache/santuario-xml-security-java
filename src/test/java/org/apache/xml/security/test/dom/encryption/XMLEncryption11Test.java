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

import java.io.File;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;


/**
 * This is a set of tests that use the test vectors associated with the W3C XML Encryption 1.1 specification:
 *
 * http://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/
 *
 * Note: I had to convert the given .p12 file into a .jks as it could not be loaded with KeyStore.
 *
 * TODO As of now all of the KeyWrapping tests are supported, but none of the KeyAgreement tests.
 */
public class XMLEncryption11Test {

    private static String cardNumber;
    private static int nodeCount = 0;
    private boolean haveISOPadding;
    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(XMLEncryption11Test.class);

    /**
     *  Constructor XMLEncryption11Test
     */
    public XMLEncryption11Test() throws Exception {

        // Create the comparison strings
        File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
        Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA2048() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

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
            LOG.warn(
                "Skipping testRSA2048 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA2048EncryptDecrypt() throws Exception {

        assumeFalse(isIBMJdK);

        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");

            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                "Skipping testRSA2048 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA2048EncryptDecryptWithSecureRandom() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-2048_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                "Skipping testRSA2048 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA3072() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

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
            LOG.warn(
                "Skipping testRSA3072 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA3072EncryptDecrypt() throws Exception {
        assumeFalse(isIBMJdK);

        if (haveISOPadding) {
            File keystore = resolveFile(
                "src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                "Skipping testRSA3072 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA3072OAEP() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

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
            LOG.warn(
                "Skipping testRSA307OAEP as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA3072OAEPEncryptDecrypt() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-3072_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                "Skipping testRSA2048 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA4096() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

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
            LOG.warn(
                "Skipping testRSA4096 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */
    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA4096EncryptDecrypt() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                "Skipping testRSA2048 as necessary "
                + "crypto algorithms are not available"
            );
        }
    }

    @org.junit.jupiter.api.Test
    public void testKeyWrappingRSA4096EncryptDecryptSHA224() throws Exception {
        if (haveISOPadding) {
            File keystore = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/RSA-4096_SHA256WithRSA.jks");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(new java.io.FileInputStream(keystore), "passwd".toCharArray());

            Certificate cert = keyStore.getCertificate("importkey");

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry("importkey", new KeyStore.PasswordProtection("passwd".toCharArray()));
            PrivateKey rsaKey = pkEntry.getPrivateKey();

            // Perform encryption
            File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
            Document doc = XMLUtils.read(new java.io.FileInputStream(f), false);

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
            LOG.warn(
                    "Skipping testRSA2048 as necessary "
                            + "crypto algorithms are not available"
            );
        }
    }

    /**
     * Method decryptElement
     *
     * Take a key, encryption type and a file, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param filename File to decrypt from
     * @param key The Key to use for decryption
     */
    private Document decryptElement(File file, Key rsaKey, X509Certificate rsaCert) throws Exception {
        // Parse the document in question
        Document doc = XMLUtils.read(new java.io.FileInputStream(file), false);
        return decryptElement(doc, rsaKey, rsaCert);
    }

    /**
     * Method decryptElement
     *
     * Take a key, encryption type and a document, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param filename File to decrypt from
     * @param key The Key to use for decryption
     */
    private Document decryptElement(Document doc, Key rsaKey, X509Certificate rsaCert) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance();

        // Need to pre-load the Encrypted Data so we can get the key info
        Element ee = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(doc, ee);

        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        KeyInfo kiek = encryptedKey.getKeyInfo();
        X509Data certData = kiek.itemX509Data(0);
        XMLX509Certificate xcert = certData.itemCertificate(0);
        X509Certificate cert = xcert.getX509Certificate();
        assertEquals(rsaCert, cert);

        XMLCipher cipher2 = XMLCipher.getInstance();
        cipher2.init(XMLCipher.UNWRAP_MODE, rsaKey);
        Key key = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());

        cipher.init(XMLCipher.DECRYPT_MODE, key);
        Document dd = cipher.doFinal(doc, ee);

        return dd;
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
        LOG.debug("Retrieved Credit Card : " + cc);
        assertEquals(cardNumber, cc);

        // Test cc numbers
        if (doNodeCheck) {
            int myNodeCount = countNodes(d);

            assertTrue(
                myNodeCount > 0 && myNodeCount == nodeCount, "Node count mismatches"
            );
        }
    }

}