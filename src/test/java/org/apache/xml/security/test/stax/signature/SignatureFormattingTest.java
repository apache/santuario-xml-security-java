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

import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.formatting.FormattingChecker;
import org.apache.xml.security.formatting.FormattingCheckerFactory;
import org.apache.xml.security.formatting.FormattingTest;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.securityEvent.*;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is a {@link FormattingTest}, it is expected to be run with different system properties
 * to check various formatting configurations.
 *
 * The test adds an XML signature to a sample document using StAX API.
 * Formatting of base64binary values is then checked.
 * Also, signature verification with StAX API is performed to ensure different formatting can be consumed.
 */
@FormattingTest
class SignatureFormattingTest {
    private final FormattingChecker formattingChecker;
    private KeyStore keyStore;
    private XPath xpath;
    private XMLInputFactory xmlInputFactory;

    public SignatureFormattingTest() throws Exception {
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
        formattingChecker = FormattingCheckerFactory.getFormattingChecker();
        keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = getClass()
                .getResourceAsStream("/org/apache/xml/security/samples/input/rsa.p12")) {
            keyStore.load(in, "xmlsecurity".toCharArray());
        } catch (IOException | GeneralSecurityException e) {
            fail("Cannot load test keystore", e);
        }

        XPathFactory xPathFactory = XPathFactory.newInstance();
        xpath = xPathFactory.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        xmlInputFactory = XMLInputFactory.newInstance();
    }

    @Test
    void testSignatureFormatting() throws Exception {
        /* this test checks formatting of base64Binary values */
        byte[] documentBytes = createDocument();

        /*
         * The document retains a part of the original document, so we can't check the whole file linebreaks,
         * i.e. formattingChecker.checkDocument(docStr);
         */

        /* parse as DOM to check base64 values */
        Document document;
        try (InputStream in = new ByteArrayInputStream(documentBytes)) {
            document = XMLUtils.read(in, false);
        }

        /*
         * In StAX implementation long element values are not surrounded by linebreaks,
         * i.e. checkBase64ValueWithSpacing is not applicable.
         */
        Element signatureValue =
                (Element) xpath.evaluate("//ds:SignatureValue", document, XPathConstants.NODE);
        formattingChecker.checkBase64Value(signatureValue.getTextContent());

        Element x509certificate =
                (Element) xpath.evaluate("//ds:X509Certificate", document, XPathConstants.NODE);
        formattingChecker.checkBase64Value(x509certificate.getTextContent());
    }
    
    @Test
    void testSignVerify() throws Exception {
        /* this test checks the signature can be verified with given formatting settings */
        byte[] documentBytes = createDocument();
        
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        
        try (InputStream in = new ByteArrayInputStream(documentBytes)) {
            XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(in, StandardCharsets.UTF_8.name());
            VerificationSecurityEventListener listener = new VerificationSecurityEventListener();
            XMLStreamReader xmlSecReader = inboundXMLSec.processInMessage(reader, null, listener);
            // read the document
            while (xmlSecReader.hasNext()) xmlSecReader.next();
            xmlSecReader.close();
            assertTrue(listener.isSignatureVerified());
        }
    }

    private byte[] createDocument() throws Exception {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("test", "xmlsecurity".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("test");

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setActions(List.of(XMLSecurityConstants.SIGNATURE));
        properties.setSignatureKey(privateKey);
        properties.setSignatureCerts(new X509Certificate[]{ certificate });
        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);
        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        String plaintextResource = "/ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml";
        try (InputStream in = getClass().getResourceAsStream(plaintextResource);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(in);
            OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
            XMLStreamWriter writer = outboundXMLSec.processOutMessage(out, StandardCharsets.UTF_8.name(), null);
            XmlReaderToWriter.writeAllAndClose(reader, writer);
            return out.toByteArray();
        }
    }
    
    private static class VerificationSecurityEventListener implements SecurityEventListener {
        boolean signatureVerified = false;

        public boolean isSignatureVerified() {
            return signatureVerified;
        }

        @Override
        public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
            if (SecurityEventConstants.SignatureValue.equals(securityEvent.getSecurityEventType())) {
                SignatureValueSecurityEvent event = (SignatureValueSecurityEvent) securityEvent;
                assertNotNull(event.getSignatureValue());
                signatureVerified = true;
            } else if (SecurityEventConstants.SignedElement.equals(securityEvent.getSecurityEventType())) {
                SignedElementSecurityEvent event = (SignedElementSecurityEvent) securityEvent;
                assertTrue(event.isSigned());
            }
        }
    }
}
