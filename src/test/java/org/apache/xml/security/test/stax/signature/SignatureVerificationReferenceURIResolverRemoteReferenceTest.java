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
import java.io.File;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.apache.xml.security.test.stax.utils.HttpRequestRedirectorProxy;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

/**
 * These are separated out from SignatureVerificationReferenceURIResolverTest as we have to change the default configuration to set
 *  * "AllowNotSameDocumentReferences" to "true".
 */
public class SignatureVerificationReferenceURIResolverRemoteReferenceTest extends AbstractSignatureVerificationTest {

    @BeforeAll
    public static void setup() throws Exception {
        XMLSec.init();
        Init.init(SignatureVerificationReferenceURIResolverRemoteReferenceTest.class.getClassLoader()
                        .getResource("security-config-allow-same-doc.xml").toURI(),
                SignatureVerificationReferenceURIResolverRemoteReferenceTest.class);
        org.apache.xml.security.Init.init();
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    @Test
    public void testSignatureVerificationWithExternalFilesystemXMLReference() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        File file = resolveFile("src/test/resources/ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");

        ReferenceInfo referenceInfo = new ReferenceInfo(
                file.toURI().toString(),
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                "http://www.w3.org/2000/09/xmldsig#sha1",
                false
        );

        List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document,
                localNames,
                key,
                referenceInfos
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
        properties.setSignatureVerificationKey(cert.getPublicKey());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testSignatureVerificationWithExternalFilesystemBinaryReference() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        File file = resolveFile(
            "target/test-classes/org/apache/xml/security/test/stax/signature/SignatureVerificationReferenceURIResolverTest.class");

        ReferenceInfo referenceInfo = new ReferenceInfo(
                file.toURI().toString(),
                null,
                "http://www.w3.org/2000/09/xmldsig#sha1",
                true
        );

        List<ReferenceInfo> referenceInfos = new ArrayList<>();
        referenceInfos.add(referenceInfo);

        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                document,
                localNames,
                key,
                referenceInfos
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
        properties.setSignatureVerificationKey(cert.getPublicKey());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

        StAX2DOM.readDoc(securityStreamReader);
    }

    @Test
    public void testSignatureVerificationWithExternalHttpReference() throws Exception {

        Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            Map<String, String> resolverProperties = new HashMap<>();
            resolverProperties.put("http.proxy.host", ((InetSocketAddress)proxy.address()).getAddress().getHostAddress());
            resolverProperties.put("http.proxy.port", "" + ((InetSocketAddress)proxy.address()).getPort());
            ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP(resolverProperties);

            // Read in plaintext document
            InputStream sourceDocument =
                    this.getClass().getClassLoader().getResourceAsStream(
                            "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
            Document document = XMLUtils.read(sourceDocument, false);

            // Set up the Key
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(
                    this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                    "default".toCharArray()
            );
            Key key = keyStore.getKey("transmitter", "default".toCharArray());
            X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

            // Sign using DOM
            List<String> localNames = new ArrayList<>();
            localNames.add("PaymentInfo");

            ReferenceInfo referenceInfo = new ReferenceInfo(
                    "http://www.w3.org/Signature/2002/04/xml-stylesheet.b64",
                    null,
                    "http://www.w3.org/2000/09/xmldsig#sha1",
                    true
            );

            List<ReferenceInfo> referenceInfos = new ArrayList<>();
            referenceInfos.add(referenceInfo);

            XMLSignature sig = signUsingDOM(
                    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    document,
                    localNames,
                    key,
                    referenceInfos,
                    resolverDirectHTTP
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
            properties.setSignatureVerificationKey(cert.getPublicKey());
            InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader);

            StAX2DOM.readDoc(securityStreamReader);
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }

}