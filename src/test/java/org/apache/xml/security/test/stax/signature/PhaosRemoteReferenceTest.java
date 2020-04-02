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
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.apache.xml.security.test.stax.utils.HttpRequestRedirectorProxy;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.utils.XMLUtils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.w3c.dom.Document;


/**
 * This is a testcase to validate all "phaos-xmldsig-three"
 * testcases from Phaos
 *
 * These are separated out from PhaosTest as we have to change the default configuration to set
 * "AllowNotSameDocumentReferences" to "true".
 */
public class PhaosRemoteReferenceTest {

    private XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    private TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @BeforeAll
    public static void setUp() throws Exception {
        XMLSec.init();
        Init.init(PhaosRemoteReferenceTest.class.getClassLoader()
                        .getResource("security-config-allow-same-doc.xml").toURI(),
                PhaosRemoteReferenceTest.class);
        org.apache.xml.security.Init.init();
    }

    public PhaosRemoteReferenceTest() throws Exception {
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    // See SANTUARIO-319
    @Test
    public void test_signature_dsa_detached() throws Exception {

        Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            // Read in plaintext document
            InputStream sourceDocument =
                    this.getClass().getClassLoader().getResourceAsStream(
                            "com/phaos/phaos-xmldsig-three/signature-dsa-detached.xml");
            Document document = XMLUtils.read(sourceDocument, false);

            // XMLUtils.outputDOM(document, System.out);

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
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }

    // See SANTUARIO-319
    @Test
    public void test_signature_hmac_sha1_exclusive_c14n_comments_detached() throws Exception {

        Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            // Read in plaintext document
            InputStream sourceDocument =
                    this.getClass().getClassLoader().getResourceAsStream(
                            "com/phaos/phaos-xmldsig-three/signature-hmac-sha1-exclusive-c14n-comments-detached.xml");
            Document document = XMLUtils.read(sourceDocument, false);

            // Set up the key
            byte[] hmacKey = "test".getBytes(StandardCharsets.US_ASCII);
            SecretKey key = new SecretKeySpec(hmacKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");

            // XMLUtils.outputDOM(document, System.out);

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
            properties.setSignatureVerificationKey(key);
            InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
            TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
            XMLStreamReader securityStreamReader =
                    inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

            StAX2DOM.readDoc(securityStreamReader);
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }

    // See SANTUARIO-319
    @Test
    public void test_signature_rsa_detached() throws Exception {

        Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            // Read in plaintext document
            InputStream sourceDocument =
                    this.getClass().getClassLoader().getResourceAsStream(
                            "com/phaos/phaos-xmldsig-three/signature-rsa-detached.xml");
            Document document = XMLUtils.read(sourceDocument, false);

            // XMLUtils.outputDOM(document, System.out);

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
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }


}