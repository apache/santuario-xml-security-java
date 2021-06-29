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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.junit.jupiter.api.Assumptions;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.apache.xml.security.stax.ext.XMLSecurityConstants.NS_C14N_EXCL;
import static org.apache.xml.security.stax.ext.XMLSecurityConstants.NS_XMLDSIG_ENVELOPED_SIGNATURE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A set of test-cases for Signature creation.
 */
public class SignatureCreationTest extends AbstractSignatureCreationTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreation(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignaturePreservesIndentation() throws Exception {
        String xml = "<?xml version='1.0'?>\n" +
                "<Root>\n" +
                "  <Branch/>\n" +
                "</Root>\n";
        SecurePart securePart = new SecurePart(new QName("Branch"), SecurePart.Modifier.Element);
        securePart.setSecureEntireRequest(true);
        String signedXml = signXml(xml, securePart);
//        System.out.println(signedXml);
        assertThat(signedXml, containsString("\n<Root>"));
        assertThat(signedXml, containsString(">\n  <dsig:Signature"));
        assertThat(signedXml, containsString(">\n  </dsig:Signature"));
        assertThat(signedXml, containsString(">\n  <Branch Id="));
        assertThat(signedXml, endsWith(">\n</Root>\n"));
        assertThat(signedXml, not(containsString("><")));
    }

    @Test
    public void testSignaturePreservesIndentationWhenSignEntireRequest() throws Exception {
        String xml = "<Root>\n" +
                "\t<Branch/>\n" +
                "</Root>";
        SecurePart securePart = new SecurePart((String) null);
        securePart.setSecureEntireRequest(true);
        String signedXml = signXml(xml, securePart);
//        System.out.println(signedXml);
        assertThat(signedXml, containsString("<Root Id="));
        assertThat(signedXml, containsString(">\n\t<dsig:Signature"));
        assertThat(signedXml, containsString(">\n\t</dsig:Signature"));
        assertThat(signedXml, containsString(">\n\t<Branch"));
        assertThat(signedXml, endsWith(">\n</Root>"));
        assertThat(signedXml, not(containsString("><")));
    }

    private String signXml(String xml, SecurePart... secureParts) throws XMLStreamException, XMLSecurityException, KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(true);
        properties.setActions(Collections.singletonList(XMLSecurityConstants.SIGNATURE));
        for (SecurePart securePart : secureParts) {
            properties.addSignaturePart(securePart);
        }
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(signedOut, StandardCharsets.UTF_8.name());
        InputStream sourceDocument = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        // Make sure we get the whitespace characters right before the first START_ELEMENT and after the last
        // END_ELEMENT.
        xmlInputFactory.setProperty("org.codehaus.stax2.reportPrologWhitespace", true);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();
        return new String(signedOut.toByteArray(), StandardCharsets.UTF_8);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationRetrieveSignatureValue(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamWriter xmlStreamWriter =
            outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name(), securityEventListener);

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

        // Check Signature bytes
        SignatureValueSecurityEvent sigValueEvent =
            (SignatureValueSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.SignatureValue);
        assertNotNull(sigValueEvent);
        assertNotNull(sigValueEvent.getSignatureValue());

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testExceptionOnElementToSignNotFound(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "NotExistingElement"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
            assertEquals("Part to sign not found: {urn:example:po}NotExistingElement", e.getCause().getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testEnvelopedSignatureCreation(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(securePart);

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

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testEnvelopedSignatureCreationC14n11(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/2006/12/xml-c14n11"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(securePart);

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

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignRootElementInRequest(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(null,
                              SecurePart.Modifier.Content,
                              new String[]{
                                      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                              },
                              "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

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

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignAtSpecificPosition(boolean autoIndent) throws Exception {
        signAtSpecificPosition(autoIndent, -1);
        signAtSpecificPosition(autoIndent, 0);
        signAtSpecificPosition(autoIndent, 1);
        signAtSpecificPosition(autoIndent, 2);
        signAtSpecificPosition(autoIndent, 999);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignAtSpecificPositionViaQName(boolean autoIndent) throws Exception {
        signAtSpecificPosition(autoIndent, 0, new QName("urn:example:po", "PurchaseOrder"), true);
        signAtSpecificPosition(autoIndent, 0, new QName("urn:example:po", "Items"), true);
        signAtSpecificPosition(autoIndent, 0, new QName("urn:example:po", "Items"), false);
        signAtSpecificPosition(autoIndent, 0, new QName("urn:example:po", "ShippingAddress"), true);
        signAtSpecificPosition(autoIndent, 0, new QName("urn:example:po", "ShippingAddress"), false);
    }

    private void signAtSpecificPosition(boolean autoIndent, int position) throws Exception {
        signAtSpecificPosition(autoIndent, position, null, false);
    }

    @SuppressWarnings("PMD.AvoidUsingShortType")
    private static Node getFirstChildOfType(Node node, short nodeType) {
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == nodeType) {
                return child;
            }
        }
        return null;
    }

    @SuppressWarnings("PMD.AvoidUsingShortType")
    private static Node getNextSiblingOfType(Node node, short nodeType) {
        for (Node sibling = node.getNextSibling(); sibling != null; sibling = sibling.getNextSibling()) {
            if (sibling.getNodeType() == nodeType) {
                return sibling;
            }
        }
        return null;
    }

    private void signAtSpecificPosition(boolean autoIndent, int position, QName positionQName, boolean start) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Specify the signature position
        properties.setSignaturePosition(position);
        properties.setSignaturePositionQName(positionQName);
        properties.setSignaturePositionStart(start);

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

        SecurePart securePart
                = new SecurePart(null,
                SecurePart.Modifier.Content,
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument
                = this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        //find first child element:
        Node childNode = XMLUtils.getNextElement(document.getDocumentElement().getFirstChild());

        if (positionQName != null) {
            // Find the Signature node inside the desired QName
            String localName = positionQName.getLocalPart();
            if (!"PurchaseOrder".equals(localName)) {
                String namespace = positionQName.getNamespaceURI();
                while (childNode != null && !(childNode.getLocalName().equals(localName)
                    && childNode.getNamespaceURI().equals(namespace))) {
                    childNode = XMLUtils.getNextElement(childNode.getNextSibling());
                }
                if (start) {
                    childNode = getFirstChildOfType(childNode, Element.ELEMENT_NODE);
                } else {
                    childNode = getNextSiblingOfType(childNode, Element.ELEMENT_NODE);
                }
            }
        } else {
            int expectedPosition = position < 0 ? 0 : position;
            int curPos = 0;
            while (curPos != expectedPosition) {
                Node node = XMLUtils.getNextElement(childNode.getNextSibling());
                curPos++;
                if (node != null) {
                    childNode = node;
                } else {
                    break;
                }
            }
        }

        assertEquals("Signature", childNode.getLocalName());

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testIdAttributeNS(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Specify the signature position
        properties.setIdAttributeNS(new QName(null, "ID"));

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

        SecurePart securePart
                = new SecurePart(null,
                SecurePart.Modifier.Content,
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument
                = this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/testcases/SAML2ArtifactResponseUnsigned.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), null, true, "ID", true);
    }


    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testMultipleElements(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);
        securePart =
                new SecurePart(new QName("urn:example:po", "ShippingAddress"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testMultipleSignatures(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // Now do second signature
        sourceDocument = new ByteArrayInputStream(baos.toByteArray());
        outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        baos = new ByteArrayOutputStream();
        xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//dsig:Signature";
        NodeList sigElements =
                (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
        assertTrue(sigElements.getLength() == 2);

        for (SecurePart secPart : properties.getSignatureSecureParts()) {
            if (secPart.getName() == null) {
                continue;
            }
            expression = "//*[local-name()='" + secPart.getName().getLocalPart() + "']";
            Element signedElement =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, "Id", true);
        }

        for (int i = 0; i < sigElements.getLength(); i++) {
            XMLSignature signature = new XMLSignature((Element)sigElements.item(i), "");
            assertTrue(signature.checkSignatureValue(cert));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testHMACSignatureCreation(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);
        SecretKey key = new SecretKeySpec(hmacKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
        properties.setSignatureKey(key);

        properties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, key, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testStrongSignatureCreation(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        properties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDSASignatureCreation(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        FileInputStream fis = null;
        if (BASEDIR != null && BASEDIR.length() != 0) {
            fis =
                    new FileInputStream(BASEDIR + System.getProperty("file.separator")
                            + "src/test/resources/org/apache/xml/security/samples/input/keystore.jks"
                    );
        } else {
            fis =
                    new FileInputStream("src/test/resources/org/apache/xml/security/samples/input/keystore.jks");
        }
        keyStore.load(fis, "xmlsecurity".toCharArray());
        Key key = keyStore.getKey("test", "xmlsecurity".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("test");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testECDSASignatureCreation(boolean autoIndent) throws Exception {

        Assumptions.assumeTrue(bcInstalled);

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource(
                        "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testStrongECDSASignatureCreation(boolean autoIndent) throws Exception {

        Assumptions.assumeTrue(bcInstalled);

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource(
                        "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
        properties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDifferentC14nMethod(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDifferentC14nMethodForReference(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
                "http://www.w3.org/2000/09/xmldsig#sha1");
        properties.addSignaturePart(securePart);

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

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        Element element = (Element)nodeList.item(0);
        assertEquals(NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_Transform.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_Transform.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_SignatureMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_SignatureMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals(XMLSecurityConstants.NS_XMLDSIG_RSASHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals(XMLSecurityConstants.NS_XMLDSIG_SHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testDifferentDigestMethodForReference(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                "http://www.w3.org/2001/04/xmlenc#sha256");
        properties.addSignaturePart(securePart);

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

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        Element element = (Element)nodeList.item(0);
        assertEquals(NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_Transform.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_Transform.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals(NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_SignatureMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_SignatureMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals(XMLSecurityConstants.NS_XMLDSIG_RSASHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testC14n11Method(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2006/12/xml-c14n11");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testExcC14nInclusivePrefixes(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm(NS_C14N_EXCL);
        properties.setAddExcC14NInclusivePrefixes(true);

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
        assertEquals(2, nodeList.getLength());
        assertEquals("", ((Element)nodeList.item(0)).getAttribute(XMLSecurityConstants.ATT_NULL_PrefixList.getLocalPart()));
        assertEquals("", ((Element)nodeList.item(1)).getAttribute(XMLSecurityConstants.ATT_NULL_PrefixList.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationRSAKeyValue(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationECDSAKeyValue(boolean autoIndent) throws Exception {

        Assumptions.assumeTrue(bcInstalled);

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource(
                        "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationSKI(boolean autoIndent) throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);
        properties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(
            this.getClass().getClassLoader().getResource("test.jceks").openStream(),
            "secret".toCharArray()
        );
        Key key = keyStore.getKey("rsakey", "secret".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("rsakey");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationX509Certificate(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationX509SubjectName(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509SubjectName);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationMultipleKeyIdentifiers(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        List<SecurityTokenConstants.KeyIdentifier> signatureKeyIdentifiers =
            Arrays.asList(SecurityTokenConstants.KeyIdentifier_X509SubjectName,
                          SecurityTokenConstants.KeyIdentifier_IssuerSerial,
                          SecurityTokenConstants.KeyIdentifier_KeyValue);
        properties.setSignatureKeyIdentifiers(signatureKeyIdentifiers);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationTransformBase64(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"),
                        SecurePart.Modifier.Content,
                        new String[]{"http://www.w3.org/2000/09/xmldsig#base64"},
                        "http://www.w3.org/2000/09/xmldsig#sha1");
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testNoKeyInfo(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
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
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_NoKeyInfo);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), null, false, "Id", true);

    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationKeyName(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

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

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationWithoutId(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);
        properties.setSignatureGenerateIds(false);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));
        Document document =
                XMLUtils.read(new ByteArrayInputStream(baos.toByteArray()), false);

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOMWithoutId(document, cert.getPublicKey(), properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void testSignatureCreationWithoutOmittedDefaultTransform(boolean autoIndent) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setAutoIndent(autoIndent);
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);
        properties.setSignatureGenerateIds(false);
        properties.setSignatureIncludeDigestTransform(false);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(null, SecurePart.Modifier.Element, new String[]{
                        NS_XMLDSIG_ENVELOPED_SIGNATURE,
                        NS_C14N_EXCL
                }, "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8.name()));
        Document document =
                XMLUtils.read(new ByteArrayInputStream(baos.toByteArray()), false);

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOMWithoutIdAndDefaultTransform(document, cert.getPublicKey(), properties.getSignatureSecureParts());
    }
}
