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
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.ElementSelector;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.SecurePartFactory;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XPathElementSelector;
import org.apache.xml.security.stax.ext.XPathModifier;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;
import org.mockito.stubbing.Answer;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import static org.apache.xml.security.test.stax.utils.TestUtils.containsRegex;
import static org.apache.xml.security.test.stax.utils.TestUtils.matchesName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;


/**
 * A set of test-cases for Encryption.
 *
 */
public class EncryptionCreationTest {

    private XMLInputFactory xmlInputFactory;

    private boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    @BeforeEach
    public void setUp() throws Exception {
        org.apache.xml.security.Init.init();

        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @Test
    public void testEncryptionContentCreation() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        SecretKey key = generateDESSecretKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 1);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptRootElementInRequest() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        SecretKey key = generateDESSecretKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart((QName)null, SecurePart.Modifier.Content);
        securePart.setSecureEntireRequest(true);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testExceptionOnElementToEncryptNotFound() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        SecretKey key = generateDESSecretKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "NonExistingElement"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        try {
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof XMLSecurityException);
            String message = e.getCause().getMessage();
            assertThat(message, startsWith("Too few (0/1) elements found to encrypt:"));
            assertThat(message, containsString("{urn:example:po}NonExistingElement"));
        }
    }

    @Test
    public void testEncryptionElementCreation() throws Exception {
        testEncryptElementCreation(XMLSecurityConstants.ENCRYPTION);
    }

    @Test
    public void testEncryptBackwardCompatibility() throws Exception {
        testEncryptElementCreation(XMLSecurityConstants.ENCRYPT);
    }

    private void testEncryptElementCreation(XMLSecurityConstants.Action action) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(action);
        properties.setActions(actions);

        // Set the key up
        SecretKey key = generateDESSecretKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testStrongEncryption() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 1);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#aes256-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptionMultipleElements() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        SecretKey key = generateDESSecretKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
            new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);
        securePart =
            new SecurePart(new QName("urn:example:po", "ShippingAddress"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 1);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 2);
    }

    // Test encryption using a generated AES 128 bit key that is encrypted using a AES 192 bit key.
    @Test
    public void testAES128ElementAES192KWCipherUsingKEKOutbound() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, transportKey, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    // Test encryption using a generated AES 256 bit key that is encrypted using an RSA key.
    @Test
    public void testAES256ElementRSAKWCipherUsingKEKOutbound() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        // Generate an RSA key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();
        properties.setEncryptionTransportKey(pub);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyKeyValueReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        // Generate an RSA key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();
        properties.setEncryptionTransportKey(pub);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyKeyNameReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        // Generate an RSA key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();
        properties.setEncryptionTransportKey(pub);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);
        properties.setEncryptionKeyName("PublicKey");

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyMultipleElements() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        // Generate an RSA key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();
        properties.setEncryptionTransportKey(pub);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);

        SecurePart securePart =
            new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);
        securePart =
            new SecurePart(new QName("urn:example:po", "ShippingAddress"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Check the CreditCard encrypted ok
        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 2);

        // Decrypt using DOM API
        decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);
    }

    @Test
    public void testEncryptedKeyIssuerSerialReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setEncryptionUseThisCertificate(cert);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_IssuerSerial);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyX509CertificateReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setEncryptionUseThisCertificate(cert);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeySKI() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(
            this.getClass().getClassLoader().getResource("test.jceks").openStream(),
            "secret".toCharArray()
        );
        PrivateKey priv = (PrivateKey)keyStore.getKey("rsakey", "secret".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("rsakey");
        properties.setEncryptionUseThisCertificate(cert);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyX509SubjectName() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setEncryptionUseThisCertificate(cert);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509SubjectName);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testEncryptedKeyNoKeyInfo() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        PrivateKey priv = (PrivateKey)keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setEncryptionUseThisCertificate(cert);
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        properties.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_NoKeyInfo);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, priv, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    // Test encryption using a generated AES 192 bit key that is encrypted using a 3DES key.
    @Test
    public void testAES192Element3DESKWCipher() throws Exception {
        assumeFalse(isIBMJdK);

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        SecretKey transportKey = generateDESSecretKey();
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-tripledes");
        properties.setEncryptionTransportKey(transportKey);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(192);
        SecretKey key = keygen.generateKey();
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes192-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, transportKey, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testTripleDesElementCipher() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAes128ElementCipher() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits128 = {
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey key = new SecretKeySpec(bits128, "AES");
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#aes128-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAes192ElementCipher() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits192 = {
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey key = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes192-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#aes192-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @Test
    public void testAes256ElementCipher() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits256 = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        SecretKey key = new SecretKeySpec(bits256, "AES");
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document =
            XMLUtils.read(new ByteArrayInputStream(baos.toByteArray()), false);

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#aes256-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    // Test case for when the entire document is encrypted and decrypted
    // In this case the EncryptedData becomes the root element of the document
    @Test
    public void testTripleDesDocumentCipher() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PurchaseOrder"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    // Test physical representation of decrypted element, see SANTUARIO-309
    @Test
    public void testPhysicalRepresentation1() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("ns.com", "elem"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final String DATA1 =
                "<ns:root xmlns:ns=\"ns.com\"><ns:elem xmlns:ns2=\"ns2.com\">11</ns:elem></ns:root>";
        try (InputStream sourceDocument = new ByteArrayInputStream(DATA1.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("ns.com", "elem");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        Element decrElem = (Element)doc.getDocumentElement().getFirstChild();
        assertEquals("ns:elem", decrElem.getNodeName());
        assertEquals("ns.com", decrElem.getNamespaceURI());
        assertEquals(1, decrElem.getAttributes().getLength());
        Attr attr = (Attr)decrElem.getAttributes().item(0);
        assertEquals("xmlns:ns2", attr.getName());
        assertEquals("ns2.com", attr.getValue());
    }

    // Test default namespace undeclaration is preserved
    @Test
    public void testPhysicalRepresentation2() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);
        properties.setEncryptionKey(key);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart securePart =
               new SecurePart(new QName("", "elem"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final String DATA2 =
                "<ns:root xmlns=\"defns.com\" xmlns:ns=\"ns.com\"><elem xmlns=\"\">11</elem></ns:root>";
        try (InputStream sourceDocument = new ByteArrayInputStream(DATA2.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
        }

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("", "elem");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", key, null, document);

        Element decrElem = (Element)doc.getDocumentElement().getFirstChild();
        assertEquals("elem", decrElem.getNodeName());
        assertNull(decrElem.getNamespaceURI());
        assertEquals(1, decrElem.getAttributes().getLength());
        Attr attr = (Attr)decrElem.getAttributes().item(0);
        assertEquals("xmlns", attr.getName());
        assertEquals("", attr.getValue());
    }

    @Test
    public void testTransportKey() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up - only specify a transport key, so the session key gets generated
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(nodeList.getLength(), 0);

        // Check the CreditCard encrypted ok
        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 0);

        nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        assertEquals(nodeList.getLength(), 1);

        // Decrypt using DOM API
        Document doc =
            decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", null, transportKey, document);

        // Check the CreditCard decrypted ok
        nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);
    }

    @ParameterizedTest
    @EnumSource(XPathModifier.class)
    public void testEncryptionMultipleElementsMatchingXPathExpression(XPathModifier modifier) throws Exception {
        String xml = "<?xml version='1.0'?>\n" +
                "<Fortune>\n" +
                "  <Wallet>\n" +
                "    <Banknotes currency='EUR'>50</Banknotes>\n" +
                "    <Banknotes currency='USD'>50</Banknotes>\n" +
                "    <Coins currency='EUR'>2.50</Coins>\n" +
                "  </Wallet>\n" +
                "  <BankAccount>\n" +
                "    <Balance currency='EUR'>102.50</Balance>\n" +
                "    <Balance currency='USD'>12.31</Balance>\n" +
                "  </BankAccount>\n" +
                "</Fortune>\n";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setActions(Collections.singletonList(XMLSecurityConstants.ENCRYPTION));

        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII);
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        // The selector is node-local, so works with any ElementModifier.
        ElementSelector elementSelector = new XPathElementSelector("//*[@currency='EUR']", modifier);
        SecurePartFactory securePartFactory = (element, outputProcessorChain) -> element != null ? new SecurePart(element.getName(), SecurePart.Modifier.Content) : null;
        properties.addEncryptionPartSelector(elementSelector, securePartFactory, -1);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(encryptedOut, StandardCharsets.UTF_8.name());

        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        String encryptedXml = new String(encryptedOut.toByteArray(), StandardCharsets.UTF_8);
//        System.out.println(encryptedXml);
        // Verify that all currency='EUR' have been encrypted, while currency='USD' have not.
        assertThat(encryptedXml, not(containsRegex("<Banknotes currency=.EUR.>50</Banknotes>", true, 1)));
        assertThat(encryptedXml, containsRegex("<Balance currency=.USD.>12\\.31</Balance>", 1));
        assertThat(encryptedXml, not(containsRegex("<Coins currency=.EUR.>2\\.50</Coins>", true, 1)));
        assertThat(encryptedXml, containsRegex(Pattern.compile("<Coins currency=.EUR.>\\s*<xenc:EncryptedData", Pattern.DOTALL), 1));
        assertThat(encryptedXml, not(containsRegex("<Balance currency=.EUR.>120\\.50</Banknotes>", true, 1)));
        assertThat(encryptedXml, containsRegex(Pattern.compile("<Banknotes currency=.EUR.>\\s*<xenc:EncryptedData", Pattern.DOTALL), 1));
        assertThat(encryptedXml, containsRegex(Pattern.compile("<Balance currency=.EUR.>\\s*<xenc:EncryptedData", Pattern.DOTALL), 1));
        assertThat(encryptedXml, containsRegex("<Banknotes currency=.USD.>50</Banknotes>", 1));
        assertThat(encryptedXml, containsRegex("<Balance currency=.USD.>12\\.31</Balance>", 1));
    }

    @Test
    public void testEncryptionOfSingleElementMatchingXPathExpressionThatRequiresTree() throws Exception {
        String xml = "<?xml version='1.0'?>\n" +
                "<Fortune>\n" +
                "  <DomesticAccount>\n" +
                "    <Balance currency='YEN'>102.50</Balance>\n" +
                "    <Balance currency='USD'>12.31</Balance>\n" +
                "  </DomesticAccount>\n" +
                "  <OffshoreAccount>\n" +
                "    <Balance currency='CHF'>20000000.00</Balance>\n" +
                "    <Balance currency='EUR'>10000000.00</Balance>\n" +
                "  </OffshoreAccount>\n" +
                "</Fortune>\n";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setActions(Collections.singletonList(XMLSecurityConstants.ENCRYPTION));

        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII);
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        // The XPath expression needs the context of all siblings in order to be evaluated correctly,
        // so it only works with ElementModifier.Tree.
        ElementSelector elementSelector = new XPathElementSelector("//OffshoreAccount/Balance[2]", XPathModifier.Tree);
        SecurePartFactory securePartFactory = (element, outputProcessorChain) -> element != null ? new SecurePart(element.getName(), SecurePart.Modifier.Content) : null;
        properties.addEncryptionPartSelector(elementSelector, securePartFactory, -1);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(encryptedOut, StandardCharsets.UTF_8.name());

        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        String encryptedXml = new String(encryptedOut.toByteArray(), StandardCharsets.UTF_8);
        System.out.println(encryptedXml);
        // Verify that all currency='EUR' have been encrypted, while currency='USD' have not.
        assertThat(encryptedXml, containsRegex("<Balance currency=.YEN.>102\\.50</Balance>", 1));
        assertThat(encryptedXml, containsRegex("<Balance currency=.USD.>12\\.31</Balance>", 1));
        assertThat(encryptedXml, not(containsRegex("<Balance currency=.EUR.>10000000\\.00</Balance>", true, 1)));
        assertThat(encryptedXml, containsRegex(Pattern.compile("<Balance currency=.EUR.>\\s*<xenc:EncryptedData", Pattern.DOTALL), 1));
        assertThat(encryptedXml, containsRegex("<Balance currency=.CHF.>20000000\\.00</Balance>", 1));
    }

    private void encrypt(String xml, ElementSelector elementSelector, int requiredNumOccurrences) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setActions(Collections.singletonList(XMLSecurityConstants.ENCRYPTION));

        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII);
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        SecurePartFactory securePartFactory = (element, outputProcessorChain) -> element != null ? new SecurePart(element.getName(), SecurePart.Modifier.Content) : null;
        properties.addEncryptionPartSelector(elementSelector, securePartFactory, requiredNumOccurrences);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(encryptedOut, StandardCharsets.UTF_8.name());

        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
    }

    @Test
    public void testEncryptionWithNodeModifier() throws Exception {
        String xml = "<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch><branch d='d'>content</branch></ns0:root>";
        ElementSelector elementSelector = spy(new XPathElementSelector("xyz", XPathModifier.Node));
        List<String> recordedElementsXml = new ArrayList<>();
        doAnswer(byRecordingElementXmlBeforeCallingRealMethod(recordedElementsXml)).when(elementSelector).select(any(XMLSecStartElement.class), any(OutputProcessorChain.class));

        encrypt(xml, elementSelector, -1);

        InOrder inOrder = inOrder(elementSelector);
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("urn:ns0", "root", "ns0"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("leaf"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));

        // Verify that the skeleton element preserves attributes and namespaces.
        assertThat(recordedElementsXml.get(0), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'/>")))));
        // Verify that the skeleton element does NOT preserve the path to the document root.
        assertThat(recordedElementsXml.get(1), is(equalTo(toString(toDocument("<branch b='b' c='c'/>")))));
        assertThat(recordedElementsXml.get(2), is(equalTo(toString(toDocument("<leaf/>")))));
        // Verify that the skeleton element does NOT preserve any content.
        assertThat(recordedElementsXml.get(3), is(equalTo(toString(toDocument("<branch d='d'/>")))));
    }

    @Test
    public void testEncryptionWithPathModifier() throws Exception {
        String xml = "<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch><branch d='d'>content</branch></ns0:root>";
        ElementSelector elementSelector = spy(new XPathElementSelector("", XPathModifier.Path));
        List<String> actualElementsXml = new ArrayList<>();
        doAnswer(byRecordingElementXmlBeforeCallingRealMethod(actualElementsXml)).when(elementSelector).select(any(XMLSecStartElement.class), any(OutputProcessorChain.class));

        encrypt(xml, elementSelector, -1);

        InOrder inOrder = inOrder(elementSelector);
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("urn:ns0", "root", "ns0"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("leaf"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));

        // Verify that the skeleton element preserves attributes and namespaces.
        assertThat(actualElementsXml.get(0), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'/>")))));
        // Verify that the skeleton element preserves the path to the document root.
        assertThat(actualElementsXml.get(1), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'/></ns0:root>")))));
        assertThat(actualElementsXml.get(2), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch></ns0:root>")))));
        // Verify that the skeleton element does NOT preserve any content.
        // Verify that the skeleton element does NOT preserve the whole document content so far, only the path to the document root.
        assertThat(actualElementsXml.get(3), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch d='d'/></ns0:root>")))));
    }

    @Test
    public void testEncryptionWithTreeModifier() throws Exception {
        String xml = "<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch><branch d='d'>content</branch></ns0:root>";
        ElementSelector elementSelector = spy(new XPathElementSelector("", XPathModifier.Tree));
        List<String> actualElementsXml = new ArrayList<>();
        doAnswer(byRecordingElementXmlBeforeCallingRealMethod(actualElementsXml)).when(elementSelector).select(any(XMLSecStartElement.class), any(OutputProcessorChain.class));

        encrypt(xml, elementSelector, -1);

        InOrder inOrder = inOrder(elementSelector);
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("urn:ns0", "root", "ns0"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("leaf"))), any(OutputProcessorChain.class));
        inOrder.verify(elementSelector).select(argThat(matchesName(new QName("branch"))), any(OutputProcessorChain.class));

        // Verify that skeleton element preserves attributes and namespaces.
        assertThat(actualElementsXml.get(0), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'/>")))));
        assertThat(actualElementsXml.get(1), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'/></ns0:root>")))));
        assertThat(actualElementsXml.get(2), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch></ns0:root>")))));
        // Verify that skeleton element preserves the whole document tree so far.
        // Verify that skeleton element does NOT preserve any content.
        assertThat(actualElementsXml.get(3), is(equalTo(toString(toDocument("<ns0:root a='a' xmlns:ns0='urn:ns0'><branch b='b' c='c'><leaf/></branch><branch d='d'/></ns0:root>")))));
    }

    private static <T> Answer<T> byRecordingElementXmlBeforeCallingRealMethod(List<String> recordedElementXml) {
        return invocation -> {
            OutputProcessorChain outputProcessorChain = invocation.getArgument(1);
            Element element = outputProcessorChain.getSecurityContext().get(Element.class);
            recordedElementXml.add(toString(element.getOwnerDocument()));
            return (T) invocation.callRealMethod();
        };
    }

    private static Document toDocument(String elementXml) throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        return documentBuilder.parse(new InputSource(new StringReader(elementXml)));
    }

    private static final String toString(Document document) {
        try {
            DOMSource source = new DOMSource(document);
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            transformer.transform(source, result);
            return writer.toString();
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testRootElementMatchesOnlyOnceWithNodeElementModifier() throws Exception {
        String xml = "<root><branch/></root>";
        ElementSelector elementSelector = new XPathElementSelector("/*", XPathModifier.Path);

        encrypt(xml, elementSelector, 1);
    }

    /**
     * Generate a secret key
     */
    private SecretKey generateDESSecretKey() throws Exception {
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
        DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        return keyFactory.generateSecret(keySpec);
    }

    @Test
    public void testEncryptionIdToEncrypt() throws Exception {
        SecurePart securePart = new SecurePart(SecurePart.Modifier.Element);
        securePart.setIdToSecure("abc");
        testEncryptionIdToEncrypt(securePart);
    }

    @Test
    public void testEncryptionIdToSign() throws Exception {
        SecurePart securePart = new SecurePart(SecurePart.Modifier.Element);
        securePart.setIdToSign("abc");
        testEncryptionIdToEncrypt(securePart);
    }

    private void testEncryptionIdToEncrypt(SecurePart securePart) throws Exception {
        String xml = "<?xml version='1.0'?>\n" +
                "<Root>\n" +
                "  <Branch attr1='abc'/>\n" +
                "</Root>\n";
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setIdAttributeNS(new QName("attr1"));
        properties.setActions(Collections.singletonList(XMLSecurityConstants.ENCRYPTION));
        properties.addEncryptionPart(securePart);
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII);
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(encryptedOut, StandardCharsets.UTF_8.name());
        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        byte[] encryptedData = encryptedOut.toByteArray();
//        System.out.println(new String(encryptedOut.toByteArray(), StandardCharsets.UTF_8));
        Document document = XMLUtils.read(new ByteArrayInputStream(encryptedData), false);
        NodeList encryptedElements = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        assertEquals(encryptedElements.getLength(), 1);
    }

    @Test
    public void testEncryptionIdToSecureSupersedesName() throws Exception {
        String xml = "<?xml version='1.0'?>\n" +
                "<Root>\n" +
                "  <Branch1 attr1='abc'/>\n" +
                "  <Branch2 attr1='def'/>\n" +
                "</Root>\n";
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setIdAttributeNS(new QName("attr1"));
        properties.setActions(Collections.singletonList(XMLSecurityConstants.ENCRYPTION));
        SecurePart securePart = new SecurePart(new QName("Branch1"), SecurePart.Modifier.Element);
        securePart.setIdToSecure("def");
        properties.addEncryptionPart(securePart);
        byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII);
        SecretKey transportKey = new SecretKeySpec(bits192, "AES");
        properties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#kw-aes192");
        properties.setEncryptionTransportKey(transportKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(encryptedOut, StandardCharsets.UTF_8.name());
        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        byte[] encryptedData = encryptedOut.toByteArray();
//        System.out.println(new String(encryptedOut.toByteArray(), StandardCharsets.UTF_8));
        Document document = XMLUtils.read(new ByteArrayInputStream(encryptedData), false);
        NodeList encryptedElements = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        assertEquals(1, encryptedElements.getLength());
        assertEquals(1, document.getElementsByTagName("Branch1").getLength());
        assertEquals(0, document.getElementsByTagName("Branch2").getLength());
    }

    /**
     * Decrypt the document using DOM API and run some tests on the decrypted Document.
     */
    private Document decryptUsingDOM(
        String algorithm,
        SecretKey secretKey,
        Key wrappingKey,
        Document document
    ) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.DECRYPT_MODE, secretKey);
        if (wrappingKey != null) {
            cipher.setKEK(wrappingKey);
        }

        NodeList nodeList = document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
            );
        Element ee = (Element)nodeList.item(0);
        return cipher.doFinal(document, ee);
    }

}