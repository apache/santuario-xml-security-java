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
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD;

/**
 * A set of test-cases for Signature verification with various digest algorithms
 */
class SignatureDigestVerificationTest extends AbstractSignatureVerificationTest {

    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @Test
    void testSHA1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA224() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha224";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA256() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA384() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#sha384";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA512() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testRIPEMD160() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#ripemd160";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testWhirlpool() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#whirlpool";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA3_224() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA3_256() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA3_384() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    void testSHA3_512() throws Exception {
        Assumptions.assumeTrue(isBcInstalled());

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        // Set up the Key
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        String digestAlgorithm = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key,
                "http://www.w3.org/2001/10/xml-exc-c14n#", digestAlgorithm
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
           xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        StAX2DOM.readDoc(securityStreamReader);
    }


}
