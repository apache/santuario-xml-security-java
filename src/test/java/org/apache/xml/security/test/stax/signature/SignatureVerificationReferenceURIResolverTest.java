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
import java.util.UUID;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 */
public class SignatureVerificationReferenceURIResolverTest extends AbstractSignatureVerificationTest {

    @Test
    public void testSignatureVerificationWithSameDocumentXPointerIdApostropheReference() throws Exception {
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
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        final XPathFactory xpf = XPathFactory.newInstance();
        final XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        final String expression = "//*[local-name()='ShippingAddress']";
        final Element elementToSign =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(elementToSign);
        final String id = UUID.randomUUID().toString();
        elementToSign.setAttributeNS(null, "Id", id);
        elementToSign.setIdAttributeNS(null, "Id", true);

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "#xpointer(id('" + id + "'))",
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document,
                localNames,
                key,
                referenceInfos
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
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testSignatureVerificationWithSameDocumentXPointerIdDoubleQuoteReference() throws Exception {
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
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        final XPathFactory xpf = XPathFactory.newInstance();
        final XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        final String expression = "//*[local-name()='ShippingAddress']";
        final Element elementToSign =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(elementToSign);
        final String id = UUID.randomUUID().toString();
        elementToSign.setAttributeNS(null, "Id", id);
        elementToSign.setIdAttributeNS(null, "Id", true);

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "#xpointer(id(\"" + id + "\"))",
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        final List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        final XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document,
                localNames,
                key,
                referenceInfos
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
        properties.setSignatureVerificationKey(cert.getPublicKey());
        final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        final XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testSignatureVerificationWithSameDocumentXPointerSlashReference() throws Exception {
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
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        // Sign using DOM
        final List<String> localNames = new ArrayList<>();

        final ReferenceInfo referenceInfo = new ReferenceInfo(
                "#xpointer(/)",
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
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document,
                localNames,
                key,
                referenceInfos
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        final javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        //System.out.println(baos.toString());

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
}