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
package org.apache.xml.security.test.stax.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.signature.TestSecurityEventListener;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
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
 * A test to make sure that the various KeyWrap Decryption algorithms are working
 */
class KeyWrapEncryptionVerificationTest {

    private static boolean bcInstalled;
    private static KeyPair rsaKeyPair;
    private final XMLInputFactory xmlInputFactory;
    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

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

        rsaKeyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
    }

    public KeyWrapEncryptionVerificationTest() throws Exception {
        org.apache.xml.security.Init.init();

        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @Test
    void testAES128KW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128_KeyWrap);
        keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_128;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));
        final XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testAES192KW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
        keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_192;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));
        final XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testAES256KW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_256_KeyWrap);
        keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.AES_256;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));
        final XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testTripleDESKW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);
        keygen = KeyGenerator.getInstance("DESede");
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.TRIPLEDES;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testRSAv15KW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
        Key keyWrappingKey = rsaKeyPair.getPublic();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.TRIPLEDES;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(rsaKeyPair.getPrivate());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testRSAOAEPKW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
        Key keyWrappingKey = rsaKeyPair.getPublic();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.TRIPLEDES;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(rsaKeyPair.getPrivate());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testRSAOAEP11KW() throws Exception {
        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP_11);
        Key keyWrappingKey = rsaKeyPair.getPublic();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.TRIPLEDES;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(rsaKeyPair.getPrivate());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testCamellia128KW() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.CAMELLIA_128_KeyWrap);
        keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(128);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_128;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testCamellia192KW() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(192);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.CAMELLIA_192_KeyWrap);
        keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(192);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_192;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testCamellia256KW() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(256);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.CAMELLIA_256_KeyWrap);
        keygen = KeyGenerator.getInstance("Camellia");
        keygen.init(256);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.CAMELLIA_256;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    void testSEED128KW() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        String name = "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        Document document = XMLUtils.readResource(name, getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("SEED");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set up the Key Wrapping Key
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.SEED_128_KeyWrap);
        keygen = KeyGenerator.getInstance("SEED");
        keygen.init(128);
        SecretKey keyWrappingKey = keygen.generateKey();
        cipher.init(XMLCipher.WRAP_MODE, keyWrappingKey);
        EncryptedKey encryptedKey = cipher.encryptKey(document, key);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String encryptionAlgorithm = XMLCipher.SEED_128;
        encrypt(encryptedKey, encryptionAlgorithm, document, localNames, key);

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Decrypt
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(keyWrappingKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    private void encrypt(
        EncryptedKey encryptedKey,
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

        EncryptedData builder = cipher.getEncryptedData();
        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(document);
            builder.setKeyInfo(builderKeyInfo);
        }
        builderKeyInfo.add(encryptedKey);

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

}