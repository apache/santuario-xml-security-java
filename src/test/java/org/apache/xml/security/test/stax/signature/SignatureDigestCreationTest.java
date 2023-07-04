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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A set of test-cases for Signature creation with various digest algorithms
 */
public class SignatureDigestCreationTest extends AbstractSignatureCreationTest {

    @Test
    public void testSHA1() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA224() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha224";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA256() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA384() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha384";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA512() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testRIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#ripemd160";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testWhirlpool() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#whirlpool";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA3_224() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA3_256() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA3_384() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSHA3_512() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

        final SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                digestAlgorithm);
        properties.addSignaturePart(securePart);

        final OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());

        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        assertEquals(1, nodeList.getLength());
        final Element element = (Element)nodeList.item(0);
        assertEquals(digestAlgorithm, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

}