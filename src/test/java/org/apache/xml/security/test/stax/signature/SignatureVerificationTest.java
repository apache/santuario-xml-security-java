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
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.implementations.Canonicalizer20010315OmitComments;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.KeyNameTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.KeyValueTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.implementations.TransformC14N;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * A set of test-cases for Signature verification.
 */
public class SignatureVerificationTest extends AbstractSignatureVerificationTest {

    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @Test
    public void testSignatureVerification() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testMultipleElements() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        localNames.add("ShippingAddress");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementMultipleSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final List<SignedElementSecurityEvent> signedElementSecurityEventList = securityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement);
        assertEquals(2, signedElementSecurityEventList.size());
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID1 = signedElementSecurityEventList.get(0).getCorrelationID();
        final String signedElementCorrelationID2 = signedElementSecurityEventList.get(1).getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents1 = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents2 = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID1)) {
                signedElementSecurityEvents1.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID2)) {
                signedElementSecurityEvents2.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents1.size());
        assertEquals(3, signedElementSecurityEvents2.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents1.size() + signedElementSecurityEvents2.size());
    }

    @Test
    public void testMultipleSignatures() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        localNames.add("ShippingAddress");
        XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Now do second signature
        sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
        } catch (final XMLStreamException ex) {
            assertEquals("Multiple signatures are not supported.", ex.getCause().getMessage());
        }
    }

    @Test
    public void testEnvelopedSignatureVerification() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        final ReferenceInfo referenceInfo = new ReferenceInfo(
            "",
            new String[]{
                         "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                         "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            },
            "http://www.w3.org/2000/09/xmldsig#sha1",
            false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key, referenceInfos
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testEnvelopedSignatureVerificationC14n11() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "",
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/2006/12/xml-c14n11"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key, referenceInfos
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testHMACSignatureVerification() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);
        final SecretKey key = new SecretKeySpec(hmacKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1", document, localNames, key
        );

        // Add KeyInfo
        final KeyInfo keyInfo = sig.getKeyInfo();
        final KeyName keyName = new KeyName(document, "SecretKey");
        keyInfo.add(keyName);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(key);
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener,
                            "http://www.w3.org/2001/10/xml-exc-c14n#",
                            "http://www.w3.org/2000/09/xmldsig#sha1",
                            "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, null, key,
                            SecurityTokenConstants.KeyIdentifier_KeyName);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final KeyNameTokenSecurityEvent keyNameSecurityToken = securityEventListener.getSecurityEvent(SecurityEventConstants.KeyNameToken);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = keyNameSecurityToken.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testHMACSignatureVerificationWrongKey() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);
        SecretKey key = new SecretKeySpec(hmacKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1", document, localNames, key
        );

        // Add KeyInfo
        final KeyInfo keyInfo = sig.getKeyInfo();
        final KeyName keyName = new KeyName(document, "SecretKey");
        keyInfo.add(keyName);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();

        final byte[] badKey = "secret2".getBytes(StandardCharsets.US_ASCII);
        key = new SecretKeySpec(badKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
        properties.setSignatureVerificationKey(key);
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Failure expected on a bad key");
        } catch (final XMLStreamException ex) {
            assertTrue(ex.getCause() instanceof XMLSecurityException);
            assertEquals("INVALID signature -- core validation failed.", ex.getCause().getMessage());
        }
    }

    @Test
    public void testECDSASignatureVerification() throws Exception {

        if (Security.getProvider("BC") == null) {
            return;
        }

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        final Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener,
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testDifferentC14nMethod() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener,
                            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                            "http://www.w3.org/2000/09/xmldsig#sha1",
                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testC14n11Method() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
            "http://www.w3.org/2006/12/xml-c14n11"
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener,
                            "http://www.w3.org/2006/12/xml-c14n11",
                            "http://www.w3.org/2000/09/xmldsig#sha1",
                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testStrongSignatureVerification() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", document, localNames, key,
            "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2001/04/xmlenc#sha256"
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener,
                            "http://www.w3.org/2001/10/xml-exc-c14n#",
                            "http://www.w3.org/2001/04/xmlenc#sha256",
                            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testIssuerSerial() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        final KeyInfo keyInfo = sig.getKeyInfo();
        final XMLX509IssuerSerial issuerSerial =
            new XMLX509IssuerSerial(sig.getDocument(), cert);
        final X509Data x509Data = new X509Data(sig.getDocument());
        x509Data.add(issuerSerial);
        keyInfo.add(x509Data);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_IssuerSerial);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testSubjectName() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        final KeyInfo keyInfo = sig.getKeyInfo();
        final X509Data x509Data = new X509Data(sig.getDocument());
        x509Data.addSubjectName(cert);
        keyInfo.add(x509Data);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_X509SubjectName);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testSubjectSKI() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(
            this.getClass().getClassLoader().getResource("test.jceks").openStream(),
            "secret".toCharArray()
        );
        final Key key = keyStore.getKey("rsakey", "secret".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("rsakey");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        final KeyInfo keyInfo = sig.getKeyInfo();
        final X509Data x509Data = new X509Data(sig.getDocument());
        x509Data.addSKI(cert);
        keyInfo.add(x509Data);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, cert, null,
                            SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testKeyValue() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert.getPublicKey());

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        // Check the SecurityEvents
        checkSecurityEvents(securityEventListener);
        checkSignedElementSecurityEvents(securityEventListener);
        checkSignatureToken(securityEventListener, null, cert.getPublicKey(),
                            SecurityTokenConstants.KeyIdentifier_KeyValue);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final KeyValueTokenSecurityEvent keyValueTokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.KeyValueToken);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = keyValueTokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testSignatureVerificationTransformBase64() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document, localNames, "http://www.w3.org/2000/09/xmldsig#base64", key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        //XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        document = StAX2DOM.readDoc(securityStreamReader);

        final SignedElementSecurityEvent signedElementSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        final X509TokenSecurityEvent x509TokenSecurityEvent = securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
        final String signedElementCorrelationID = signedElementSecurityEvent.getCorrelationID();
        final String x509TokenCorrelationID = x509TokenSecurityEvent.getCorrelationID();

        final List<SecurityEvent> signatureSecurityEvents = new ArrayList<>();
        final List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();

        final List<SecurityEvent> securityEvents = securityEventListener.getSecurityEvents();
        for (int i = 0; i < securityEvents.size(); i++) {
            final SecurityEvent securityEvent = securityEvents.get(i);
            if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                signedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(x509TokenCorrelationID)) {
                signatureSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, signatureSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents.size());
        assertEquals(securityEventListener.getSecurityEvents().size(),
                signatureSecurityEvents.size() + signedElementSecurityEvents.size());
    }

    @Test
    public void testDisallowMD5Algorithm() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-md5", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            document = StAX2DOM.readDoc(securityStreamReader);
            fail("Exception expected");
        } catch (final XMLStreamException e) {
            assertTrue(e.getCause() instanceof XMLSecurityException);
            assertEquals("The use of MD5 algorithm is strongly discouraged. Nonetheless can it be enabled via the " +
                    "\"AllowMD5Algorithm\" property in the configuration.",
                    e.getCause().getMessage());
        }
    }

    @Test
    public void testCustomC14nAlgo() throws Exception {

        final String customC14N = "customC14N";
        Transform.register(customC14N, TransformC14N.class);
        Canonicalizer.register(customC14N, Canonicalizer20010315OmitComments.class);

        final Field algorithmsClassMapInField = TransformerAlgorithmMapper.class.getDeclaredField("algorithmsClassMapIn");
        algorithmsClassMapInField.setAccessible(true);
        @SuppressWarnings("unchecked")
        final
        Map<String, Class<?>> transformMap = (Map<String, Class<?>>)algorithmsClassMapInField.get(null);
        transformMap.put(customC14N, org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_OmitCommentsTransformer.class);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                customC14N, (List<ReferenceInfo>)null
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // XMLUtils.outputDOM(document, System.out);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testPartialSignedDocumentTampered_ContentFirst() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Now modify the context of PaymentInfo
        final Element paymentInfoElement =
                (Element)document.getElementsByTagNameNS("urn:example:po", "BillingAddress").item(0);
        paymentInfoElement.setTextContent("Dig PLC, 1 First Ave, Dublin 1, US");

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Failure expected on a modified document");
        } catch (final XMLStreamException ex) {
            assertTrue(ex.getMessage().contains("Invalid digest of reference"));
        }
    }

    @Test
    public void testPartialSignedDocumentTampered_SignatureFirst() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Now modify the context of PaymentInfo
        final Element paymentInfoElement =
                (Element)document.getElementsByTagNameNS("urn:example:po", "BillingAddress").item(0);
        paymentInfoElement.setTextContent("Dig PLC, 1 First Ave, Dublin 1, US");

        //move signature below root element
        final Element sigElement = (Element)document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_dsig_Signature.getNamespaceURI(),
                XMLSecurityConstants.TAG_dsig_Signature.getLocalPart()).item(0);
        document.getDocumentElement().insertBefore(sigElement,
                XMLUtils.getNextElement(document.getDocumentElement().getFirstChild()));

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Failure expected on a modified document");
        } catch (final XMLStreamException ex) {
            assertTrue(ex.getMessage().contains("Invalid digest of reference"));
        }
    }

    @Test
    public void testEnvelopedSignatureTampered_ContentFirst() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "",
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key, referenceInfos
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Now modify the context of PaymentInfo
        final Element paymentInfoElement =
                (Element)document.getElementsByTagNameNS("urn:example:po", "BillingAddress").item(0);
        paymentInfoElement.setTextContent("Dig PLC, 1 First Ave, Dublin 1, US");

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Failure expected on a modified document");
        } catch (final XMLStreamException ex) {
            assertTrue(ex.getMessage().contains("Invalid digest of reference"));
        }
    }

    @Test
    public void testEnvelopedSignatureTampered_SignatureFirst() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "",
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key, referenceInfos
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Now modify the context of PaymentInfo
        final Element paymentInfoElement =
                (Element)document.getElementsByTagNameNS("urn:example:po", "BillingAddress").item(0);
        paymentInfoElement.setTextContent("Dig PLC, 1 First Ave, Dublin 1, US");

        //move signature below root element
        final Element sigElement = (Element)document.getElementsByTagNameNS(
                XMLSecurityConstants.TAG_dsig_Signature.getNamespaceURI(),
                XMLSecurityConstants.TAG_dsig_Signature.getLocalPart()).item(0);
        document.getDocumentElement().insertBefore(sigElement,
                XMLUtils.getNextElement(document.getDocumentElement().getFirstChild()));

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Failure expected on a modified document");
        } catch (final XMLStreamException ex) {
            assertTrue(ex.getMessage().contains("Invalid digest of reference"));
        }
    }
}