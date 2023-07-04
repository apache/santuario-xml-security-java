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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static java.security.spec.MGF1ParameterSpec.SHA256;

/**
 * A set of test-cases for Signature verification with various PublicKey algorithms
 */
public class PKSignatureVerificationTest extends AbstractSignatureVerificationTest {
    private static KeyPair rsaKeyPair, ecKeyPair;
    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @BeforeAll
    public static void createKeys() throws Exception {
        final KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.genKeyPair();

        ecKeyPair = KeyPairGenerator.getInstance("EC").genKeyPair();
    }

    @Test
    public void testRSA_SHA1() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA256() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA384() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA512() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA1_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA224_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA256_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA384_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testRSA_SHA512_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    @Disabled   // Disabled as I didn't want to have to change the XML Signature core schema
    public void testRSA_SSA_PSS() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        final PSSParameterSpec spec = new PSSParameterSpec("SHA-256", "MGF1", SHA256, 64, 1);
        final String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        final String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";

        signUsingDOM(
                signatureAlgorithm, document, localNames, rsaKeyPair.getPrivate(),
                c14nMethod, digestMethod, null, null, spec
        );

        XMLUtils.outputDOM(document, System.out);

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
        properties.setSignatureVerificationKey(rsaKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_SHA1() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_SHA224() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_SHA256() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_SHA384() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_SHA512() throws Exception {
        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testECDSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        final InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String signatureAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160";
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        signUsingDOM(
                signatureAlgorithm, document, localNames, ecKeyPair.getPrivate(),
                "http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2000/09/xmldsig#sha1"
        );

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
        properties.setSignatureVerificationKey(ecKeyPair.getPublic());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        final XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }


}
