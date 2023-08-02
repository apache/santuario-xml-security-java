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
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.DefaultTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedKeyTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.signature.TestSecurityEventListener;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;


/**
 * A set of test-cases for Decryption.
 *
 */
class DecryptionTest {

    private XMLInputFactory xmlInputFactory;
    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    @BeforeEach
    public void setUp() throws Exception {
        org.apache.xml.security.Init.init();

        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @Test
    void testDecryptElementValidation() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
            localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo , "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }


    @Test
    void testDecryptContentValidation() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
            localNames, true
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }

    @Test
    void testStrongDecryption() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc", secretKey, null, null, document,
            localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes256-cbc", null);
    }

    @Test
    void testDecryptMultipleElements() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        localNames.add("ShippingAddress");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
            localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the ShippingAddress decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "ShippingAddress");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkMultipleEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }

    /**
     * Test encryption using a generated AES 128 bit key that is
     * encrypted using a AES 192 bit key.  Then reverse using the KEK
     */
    @Test
    void testAES128ElementAES192KWCipherUsingKEKInbound() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        SecretKey kek = new SecretKeySpec(bits192, "AES");

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc", secretKey,
            "http://www.w3.org/2001/04/xmlenc#kw-aes192", kek, document, localNames, true
        );

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
        properties.setDecryptionKey(kek);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_EncryptedKey,
                "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                  "http://www.w3.org/2001/04/xmlenc#kw-aes192");
    }

    /**
     * Test encryption using a generated AES 256 bit key that is
     * encrypted using an RSA key.  Reverse using KEK
     */
    @Test
    void testAES256ElementRSAKWCipherUsingKEKInbound() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc", secretKey,
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5", pub, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_EncryptedKey,
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                  "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
    }

    @Test
    void testAES256ElementRSAKWCipherUsingKEKInboundIncludeEKKeyInfo() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc", secretKey,
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5", pub, true, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_EncryptedKey,
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                  "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
    }

    /**
     * Test encryption using a generated AES 192 bit key that is
     * encrypted using a 3DES key.  Then reverse by decrypting EncryptedKey.
     */
    @Test
    void testAES192Element3DESKWCipherInbound() throws Exception {
        assumeFalse(isIBMJdK);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        Key kek = keyFactory.generateSecret(keySpec);

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc", secretKey,
            "http://www.w3.org/2001/04/xmlenc#kw-tripledes", kek, document, localNames, true
        );

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
        properties.setDecryptionKey(kek);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_EncryptedKey,
                "http://www.w3.org/2001/04/xmlenc#aes192-cbc");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                  "http://www.w3.org/2001/04/xmlenc#kw-tripledes");
    }

    @Test
    void testTripleDesElementCipher() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey,
            "", null, document, localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "");
    }

    @Test
    void testAes128ElementCipher() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] bits128 = {
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey secretKey = new SecretKeySpec(bits128, "AES");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc", secretKey,
            "", null, document, localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "");
    }

    @Test
    void testAes192ElementCipher() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] bits192 = {
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey secretKey = new SecretKeySpec(bits192, "AES");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc", secretKey,
            "", null, document, localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "");
    }

    @Test
    void testAes256ElementCipher() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] bits256 = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey secretKey = new SecretKeySpec(bits256, "AES");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc", secretKey,
            "", null, document, localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "");
    }

    // Test case for when the entire document is encrypted and decrypted
    // In this case the EncryptedData becomes the root element of the document
    @Test
    void testTripleDesDocumentCipher() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PurchaseOrder");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey,
            "", null, document, localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "");
    }

    @Test
    void testPhysicalRepresentation() throws Exception {
        final String DATA1 =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns:root xmlns:ns=\"ns.com\"><ns:elem xmlns:ns2=\"ns2.com\">11</ns:elem></ns:root>";
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(DATA1.getBytes(StandardCharsets.UTF_8))) {
            document = XMLUtils.read(is, false);
        }

        // Set up the Key
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("elem");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey,
            "", null, document, localNames, false
        );

        // Check the element encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("ns.com", "elem");
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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the element decrypted ok
        nodeList = document.getElementsByTagNameNS("ns.com", "elem");
        assertEquals(nodeList.getLength(), 1);

        Element decrElem = (Element)document.getDocumentElement().getFirstChild();
        assertEquals("ns:elem", decrElem.getNodeName());
        assertEquals("ns.com", decrElem.getNamespaceURI());
        assertEquals(1, decrElem.getAttributes().getLength());
        Attr attr = (Attr)decrElem.getAttributes().item(0);
        assertEquals("xmlns:ns2", attr.getName());
        assertEquals("ns2.com", attr.getValue());

        // Check the SecurityEvents
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "");
    }

    @Test
    void testPhysicalRepresentation2() throws Exception {
        final String DATA1 =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns:root xmlns=\"defns.com\" xmlns:ns=\"ns.com\"><elem xmlns=\"\">11</elem></ns:root>";
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(DATA1.getBytes(StandardCharsets.UTF_8))) {
            document = XMLUtils.read(is, false);
        }

        // Set up the Key
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("elem");
        encryptUsingDOM(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey,
            "", null, document, localNames, false
        );

        // Check the element encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("", "elem");
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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the element decrypted ok
        nodeList = document.getElementsByTagNameNS("", "elem");
        assertEquals(nodeList.getLength(), 1);

        Element decrElem = (Element)document.getDocumentElement().getFirstChild();
        assertEquals("elem", decrElem.getNodeName());
        assertNull(decrElem.getNamespaceURI());
        assertEquals(1, decrElem.getAttributes().getLength());
        Attr attr = (Attr)decrElem.getAttributes().item(0);
        assertEquals("xmlns", attr.getName());
        assertEquals("", attr.getValue());

        // Check the SecurityEvents
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                  securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "");
    }

    /**
     * Generate a secret key
     */
    private SecretKey generateSecretKey() throws Exception {
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        return keyFactory.generateSecret(keySpec);
    }

    private void encryptUsingDOM(
            String algorithm,
            SecretKey secretKey,
            String keyTransportAlgorithm,
            Key wrappingKey,
            Document document,
            List<String> localNames,
            boolean content
        ) throws Exception {
        encryptUsingDOM(algorithm, secretKey, keyTransportAlgorithm, wrappingKey, false,
                document, localNames, content);
    }

    /**
     * Encrypt the document using DOM APIs and run some tests on the encrypted Document.
     */
    private void encryptUsingDOM(
        String algorithm,
        SecretKey secretKey,
        String keyTransportAlgorithm,
        Key wrappingKey,
        boolean includeWrappingKeyInfo,
        Document document,
        List<String> localNames,
        boolean content
    ) throws Exception {
        KeyInfo encryptedKeyKeyInfo = null;
        if (wrappingKey != null && includeWrappingKeyInfo && wrappingKey instanceof PublicKey) {
            // Create a KeyInfo for the EncryptedKey
            encryptedKeyKeyInfo = new KeyInfo(document);
            encryptedKeyKeyInfo = new KeyInfo(document);
            encryptedKeyKeyInfo.getElement().setAttributeNS(
                "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
            );
            encryptedKeyKeyInfo.add((PublicKey)wrappingKey);
        }
        encryptUsingDOM(algorithm, secretKey, keyTransportAlgorithm, wrappingKey,
                        encryptedKeyKeyInfo, document, localNames, content);
    }

    /**
     * Encrypt the document using DOM APIs and run some tests on the encrypted Document.
     */
    private void encryptUsingDOM(
        String algorithm,
        SecretKey secretKey,
        String keyTransportAlgorithm,
        Key wrappingKey,
        KeyInfo encryptedKeyKeyInfo,
        Document document,
        List<String> localNames,
        boolean content
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

        if (wrappingKey != null) {
            XMLCipher newCipher = XMLCipher.getInstance(keyTransportAlgorithm);
            newCipher.init(XMLCipher.WRAP_MODE, wrappingKey);
            EncryptedKey encryptedKey = newCipher.encryptKey(document, secretKey);
            if (encryptedKeyKeyInfo != null) {
                encryptedKey.setKeyInfo(encryptedKeyKeyInfo);
            }

            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(document);
                builderKeyInfo.getElement().setAttributeNS(
                    "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
                );
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);
        }

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        for (String localName : localNames) {
            String expression = "//*[local-name()='" + localName + "']";
            Element elementToEncrypt =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(elementToEncrypt);

            document = cipher.doFinal(document, elementToEncrypt, content);
        }

        NodeList nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertTrue(nodeList.getLength() > 0);
    }

    protected void checkEncryptedElementSecurityEvents(TestSecurityEventListener securityEventListener) {
        EncryptedElementSecurityEvent encryptedElementEvent =
                (EncryptedElementSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.EncryptedElement);
        assertNotNull(encryptedElementEvent);
        assertEquals(encryptedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", encryptedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}PaymentInfo", encryptedElementEvent.getElementPath().get(1).toString());
        assertTrue(encryptedElementEvent.isEncrypted());
    }

    protected void checkMultipleEncryptedElementSecurityEvents(TestSecurityEventListener securityEventListener) {
        List<SecurityEvent> encryptedElements =
                securityEventListener.getSecurityEvents(SecurityEventConstants.EncryptedElement);
        assertThat(encryptedElements, hasSize(2));

        EncryptedElementSecurityEvent encryptedElementEvent =
                (EncryptedElementSecurityEvent)encryptedElements.get(0);
        assertNotNull(encryptedElementEvent);
        assertEquals(encryptedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", encryptedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}ShippingAddress", encryptedElementEvent.getElementPath().get(1).toString());
        assertTrue(encryptedElementEvent.isEncrypted());

        encryptedElementEvent =
                (EncryptedElementSecurityEvent)encryptedElements.get(1);
        assertNotNull(encryptedElementEvent);
        assertEquals(encryptedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", encryptedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}PaymentInfo", encryptedElementEvent.getElementPath().get(1).toString());
        assertTrue(encryptedElementEvent.isEncrypted());
    }

    protected void checkEncryptedContentSecurityEvents(TestSecurityEventListener securityEventListener) {
        ContentEncryptedElementSecurityEvent encryptedElementEvent =
                (ContentEncryptedElementSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.ContentEncrypted);
        assertNotNull(encryptedElementEvent);
        assertEquals(encryptedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", encryptedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}PaymentInfo", encryptedElementEvent.getElementPath().get(1).toString());
        assertTrue(encryptedElementEvent.isEncrypted());
    }

    protected void checkEncryptionToken(
            TestSecurityEventListener securityEventListener,
            X509Certificate cert, Key key,
            SecurityTokenConstants.KeyIdentifier keyIdentifier,
            String algorithm) throws XMLSecurityException {
        if (SecurityTokenConstants.KeyIdentifier_NoKeyInfo.equals(keyIdentifier)) {
            DefaultTokenSecurityEvent tokenEvent =
                    (DefaultTokenSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.DefaultToken);
            assertNotNull(tokenEvent);
            Key processedKey = tokenEvent.getSecurityToken().getSecretKey().values().iterator().next();
            assertEquals(processedKey, key);
        } else if (SecurityTokenConstants.KeyIdentifier_EncryptedKey.equals(keyIdentifier)) {
            EncryptedKeyTokenSecurityEvent tokenEvent =
                    (EncryptedKeyTokenSecurityEvent) securityEventListener.getSecurityEvent(
                            SecurityEventConstants.EncryptedKeyToken);
            assertNotNull(tokenEvent);
            Key processedKey = tokenEvent.getSecurityToken().getSecretKey().values().iterator().next();
            assertEquals(processedKey, key);
        }
    }

    protected void checkEncryptionMethod(
            TestSecurityEventListener securityEventListener,
            String encryptionAlgorithm,
            String keywrapAlgorithm
    ) {
        List<SecurityEvent> algorithmEvents =
                securityEventListener.getSecurityEvents(SecurityEventConstants.AlgorithmSuite);
        assertFalse(algorithmEvents.isEmpty());

        boolean matchedEncryptionAlgorithm = false;
        boolean matchedKeywrapAlgorithm = false;
        for (SecurityEvent event : algorithmEvents) {
            AlgorithmSuiteSecurityEvent algorithmEvent = (AlgorithmSuiteSecurityEvent) event;
            if (XMLSecurityConstants.Enc.equals(algorithmEvent.getAlgorithmUsage())) {
                assertEquals(encryptionAlgorithm, algorithmEvent.getAlgorithmURI());
                matchedEncryptionAlgorithm = true;
            } else if (XMLSecurityConstants.Sym_Key_Wrap.equals(algorithmEvent.getAlgorithmUsage())
                || XMLSecurityConstants.Asym_Key_Wrap.equals(algorithmEvent.getAlgorithmUsage())) {
                assertEquals(keywrapAlgorithm, algorithmEvent.getAlgorithmURI());
                matchedKeywrapAlgorithm = true;
            }
        }

        assertTrue(matchedEncryptionAlgorithm);
        if (keywrapAlgorithm != null && keywrapAlgorithm.length() != 0) {
            assertTrue(matchedKeywrapAlgorithm);
        }
    }

    @Test
    void testMaximumAllowedXMLStructureDepth() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        for (int i = 0; i < 7; i++) {
            NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
            Element creditCardElement = (Element)nodeList.item(nodeList.getLength() - 1);
            creditCardElement.appendChild(document.getDocumentElement().cloneNode(true));
        }

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
                "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
                localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            document = StAX2DOM.readDoc(securityStreamReader);
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof XMLSecurityException);
            assertEquals("Maximum depth (100) of the XML structure reached. You can raise the maximum via the " +
                    "\"MaximumAllowedXMLStructureDepth\" property in the configuration.", e.getCause().getMessage());
        }
    }

    @Test
    void testModifiedEncryptedKeyCipherValue() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc", secretKey,
                "http://www.w3.org/2001/04/xmlenc#rsa-1_5", pub, document, localNames, true
        );

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        NodeList cipherValues = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_CipherValue.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_CipherValue.getLocalPart());
        Element cipherValueElement = (Element)cipherValues.item(0);
        assertEquals(
                cipherValueElement.getParentNode().getParentNode().getLocalName(),
                XMLSecurityConstants.TAG_xenc_EncryptedKey.getLocalPart());

        String cipherValue = cipherValueElement.getTextContent();
        StringBuilder stringBuilder = new StringBuilder(cipherValue);
        int index = stringBuilder.length() / 2;
        char ch = stringBuilder.charAt(index);
        if (ch != 'A') {
            ch = 'A';
        } else {
            ch = 'B';
        }
        stringBuilder.setCharAt(index, ch);
        cipherValueElement.setTextContent(stringBuilder.toString());

        //XMLUtils.outputDOM(document, System.out);

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
        properties.setDecryptionKey(priv);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            document = StAX2DOM.readDoc(securityStreamReader);
        } catch (XMLStreamException e) {
            assertFalse(e.getMessage().contains("Unwrapping failed"));
        }
    }

    @Test
    void testKeyValue() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), true, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testIssuerSerial() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        KeyInfo encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo.getElement().setAttributeNS(
            "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
        );
        X509Data x509Data = new X509Data(document);
        x509Data.addIssuerSerial(cert.getIssuerX500Principal().getName(),
                                 cert.getSerialNumber());
        encryptedKeyKeyInfo.add(x509Data);

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), encryptedKeyKeyInfo, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testX509Certificate() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        KeyInfo encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo.getElement().setAttributeNS(
            "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
        );
        X509Data x509Data = new X509Data(document);
        x509Data.addCertificate(cert);
        encryptedKeyKeyInfo.add(x509Data);

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), encryptedKeyKeyInfo, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testSubjectName() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        KeyInfo encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo.getElement().setAttributeNS(
            "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
        );
        X509Data x509Data = new X509Data(document);
        x509Data.addSubjectName(cert);
        encryptedKeyKeyInfo.add(x509Data);

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), encryptedKeyKeyInfo, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testSKI() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        try (InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("test.jceks")) {
            keyStore.load(inputStream, "secret".toCharArray());
        }
        PrivateKey priv = (PrivateKey)keyStore.getKey("rsakey", "secret".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("rsakey");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        KeyInfo encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo = new KeyInfo(document);
        encryptedKeyKeyInfo.getElement().setAttributeNS(
            "http://www.w3.org/2000/xmlns/", "xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#"
        );
        X509Data x509Data = new X509Data(document);
        x509Data.addSKI(cert);
        encryptedKeyKeyInfo.add(x509Data);

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), encryptedKeyKeyInfo, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testNoKeyInfo() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        encryptUsingDOM(
            XMLCipher.AES_128, key, XMLCipher.RSA_OAEP,
            cert.getPublicKey(), false, document, localNames, true
        );

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
        properties.setDecryptionKey(priv);
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
    void testDecryptElementValidationInDecryptOnlyMode() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
                "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
                localNames, false
        );

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
        properties.setDecryptionKey(secretKey);
        properties.addAction(XMLSecurityConstants.ENCRYPTION);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // XMLUtils.outputDOM(document, System.out);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedElementSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo , "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }


    @Test
    void testDecryptContentValidationInDecryptOnlyMode() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        encryptUsingDOM(
                "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
                localNames, true
        );

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
        properties.setDecryptionKey(secretKey);
        properties.addAction(XMLSecurityConstants.ENCRYPTION);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        checkEncryptedContentSecurityEvents(securityEventListener);
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo, "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }

    @Test
    void testDecryptWholeDocumentInDecryptOnlyMode() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        SecretKey secretKey = generateSecretKey();

        // Encrypt using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PurchaseOrder");
        encryptUsingDOM(
                "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", secretKey, null, null, document,
                localNames, false
        );

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PurchaseOrder");
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
        properties.setDecryptionKey(secretKey);
        properties.addAction(XMLSecurityConstants.ENCRYPTION);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the CreditCard decrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "PurchaseOrder");
        assertEquals(nodeList.getLength(), 1);

        // Check the SecurityEvents
        EncryptedElementSecurityEvent encryptedElementEvent =
                (EncryptedElementSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.EncryptedElement);
        assertNotNull(encryptedElementEvent);
        assertEquals(encryptedElementEvent.getElementPath().size(), 1);
        assertEquals("{urn:example:po}PurchaseOrder", encryptedElementEvent.getElementPath().get(0).toString());
        assertTrue(encryptedElementEvent.isEncrypted());
        checkEncryptionToken(securityEventListener, null, secretKey,
                SecurityTokenConstants.KeyIdentifier_NoKeyInfo , "");
        checkEncryptionMethod(
                securityEventListener, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null);
    }
}