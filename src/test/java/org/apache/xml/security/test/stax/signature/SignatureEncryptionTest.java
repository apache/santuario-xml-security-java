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
package org.apache.xml.security.test.stax.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A set of test-cases for Signature + Encryption.
 */
public class SignatureEncryptionTest extends AbstractSignatureCreationTest {

    @Test
    public void testSignatureEncryption() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();
        properties.setEncryptionKey(encryptionKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart signatureSecurePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(signatureSecurePart);

        SecurePart encryptionSecurePart =
                new SecurePart(new QName("urn:example:po", "PurchaseOrder"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(encryptionSecurePart);

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

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encryptionKey, null, document);

        // Check the CreditCard decrypted ok
        NodeList nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignaturePartSelectors());

        TestSecurityEventListener testSecurityEventListener =
                verifyUsingStAX(baos.toByteArray(), encryptionKey, cert.getPublicKey());

        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement).size());
        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.ContentEncrypted).size());
    }

    @Test
    public void testSignatureEncryptionSameElement() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();
        properties.setEncryptionKey(encryptionKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart signatureSecurePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(signatureSecurePart);

        SecurePart encryptionSecurePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(encryptionSecurePart);

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

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encryptionKey, null, document);

        // Check the CreditCard decrypted ok
        NodeList nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getEncryptionPartSelectors());

        TestSecurityEventListener testSecurityEventListener =
                verifyUsingStAX(baos.toByteArray(), encryptionKey, cert.getPublicKey());

        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement).size());
        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.EncryptedElement).size());
    }

    @Test
    public void testEnvelopedSignatureEncryptionElement() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();
        properties.setEncryptionKey(encryptionKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart signatureSecurePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(signatureSecurePart);

        SecurePart encryptionSecurePart =
                new SecurePart(new QName("urn:example:po", "PurchaseOrder"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(encryptionSecurePart);

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

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encryptionKey, null, document);

        // Check the CreditCard decrypted ok
        NodeList nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getEncryptionPartSelectors());

        TestSecurityEventListener testSecurityEventListener =
                verifyUsingStAX(baos.toByteArray(), encryptionKey, cert.getPublicKey());

        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement).size());
        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.EncryptedElement).size());
    }

    @Test
    public void testEnvelopedSignatureEncryptionContent() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();
        properties.setEncryptionKey(encryptionKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart signatureSecurePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(signatureSecurePart);

        SecurePart encryptionSecurePart =
                new SecurePart(new QName("urn:example:po", "PurchaseOrder"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(encryptionSecurePart);

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

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encryptionKey, null, document);

        // Check the CreditCard decrypted ok
        NodeList nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getEncryptionPartSelectors());

        TestSecurityEventListener testSecurityEventListener =
                verifyUsingStAX(baos.toByteArray(), encryptionKey, cert.getPublicKey());

        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement).size());
        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.ContentEncrypted).size());
    }

    @Test
    public void testEncryptionSignature() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();
        properties.setEncryptionKey(encryptionKey);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        SecurePart signatureSecurePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(signatureSecurePart);

        SecurePart encryptionSecurePart =
                new SecurePart(new QName("urn:example:po", "PurchaseOrder"), SecurePart.Modifier.Content);
        properties.addEncryptionPart(encryptionSecurePart);

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

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getEncryptionPartSelectors());

        // Decrypt using DOM API
        Document doc =
                decryptUsingDOM("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", encryptionKey, null, document);

        // Check the CreditCard decrypted ok
        NodeList nodeList = doc.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(nodeList.getLength(), 1);

        TestSecurityEventListener testSecurityEventListener =
                verifyUsingStAX(baos.toByteArray(), encryptionKey, cert.getPublicKey());

        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement).size());
        assertEquals(1, testSecurityEventListener.getSecurityEvents(SecurityEventConstants.ContentEncrypted).size());
    }

    @Test
    public void testUnsecuredDocument() throws Exception {
        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        // Set the key up
        SecretKey encryptionKey = generateDESSecretKey();

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");

        try {
            verifyUsingStAX(sourceDocument, encryptionKey, cert.getPublicKey());
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertEquals("Unsecured message. Neither a Signature nor a EncryptedData element found.",
                    e.getCause().getMessage());
        }
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
        Element ee = (Element) nodeList.item(0);
        return cipher.doFinal(document, ee);
    }

    private TestSecurityEventListener verifyUsingStAX(
            byte[] doc, Key decryptionKey, PublicKey signatureVerificationKey) throws Exception {
        try (InputStream is = new ByteArrayInputStream(doc)) {
            return verifyUsingStAX(is, decryptionKey, signatureVerificationKey);
        }
    }

    private TestSecurityEventListener verifyUsingStAX(
            InputStream doc, Key decryptionKey, PublicKey signatureVerificationKey) throws Exception {

        XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(doc);

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(decryptionKey);
        properties.setSignatureVerificationKey(signatureVerificationKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener testSecurityEventListener = new TestSecurityEventListener();

        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, testSecurityEventListener);

        Document document = StAX2DOM.readDoc(securityStreamReader);

        // javax.xml.transform.Transformer transformer = TransformerFactory.newInstance().newTransformer();
        // transformer.transform(new DOMSource(document), new StreamResult(System.out));

        NodeList nodeList = document.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
        assertEquals(nodeList.getLength(), 0);

        return testSecurityEventListener;
    }
}
