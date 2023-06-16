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
package org.apache.xml.security.test.dom.algorithms;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A test to make sure that the various Symmetric Encryption algorithms are working
 */
public class SymmetricEncryptionAlgorithmTest {

    private static boolean bcInstalled;

    static {
        org.apache.xml.security.Init.init();
    }

    @BeforeAll
    public static void setup() throws Exception {
        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (Exception e) {
                //ignore
            }
            if (cons != null) {
                Provider provider = (Provider)cons.newInstance();
                Security.insertProviderAt(provider, 2);
                bcInstalled = true;
            }
        }
    }

    @AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @Test
    public void testAES128() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_128;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAES128_GCM() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_128_GCM;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAES192() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_192;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAES192_GCM() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_192_GCM;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAES256() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_256;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAES256_GCM() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_256_GCM;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testTRIPLE_DES() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.TRIPLEDES;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testSEED_128() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("SEED");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.SEED_128;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testCAMELLIA_128() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_128;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testCAMELLIA_192() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(192);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_192;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testCAMELLIA_256() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(256);
        SecretKey key = keygen.generateKey();

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_256;

        encrypt(encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);
        document = decrypt(encryptionAlgorithm, document, key);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    private void encrypt(
        String algorithm,
        Document document,
        List<String> localNames,
        Key encryptingKey
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, encryptingKey);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        for (String localName : localNames) {
            String expression = "//*[local-name()='" + localName + "']";
            Element elementToEncrypt =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(elementToEncrypt);

            document = cipher.doFinal(document, elementToEncrypt, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertTrue(nodeList.getLength() > 0);
    }

    private Document decrypt(
        String algorithm,
        Document document,
        Key key
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.DECRYPT_MODE, key);

        NodeList nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        Element ee = (Element)nodeList.item(0);
        return cipher.doFinal(document, ee);
    }

}