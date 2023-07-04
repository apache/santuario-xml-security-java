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
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.apache.xml.security.test.stax.utils.HttpRequestRedirectorProxy;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
public class SignatureCreationReferenceURIResolverTest extends AbstractSignatureCreationTest {

    @BeforeAll
    public static void setup() throws Exception {
        AbstractSignatureCreationTest.setup();
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    @Test
    public void testSignatureCreationWithExternalFilesystemXMLReference() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = getKeyStore();
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(securePart);

        final File file = resolveFile("src/test/resources/ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        securePart = new SecurePart(file.toURI().toString(),
                new String[]{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
                XMLSecurityConstants.NS_XMLDSIG_SHA1);
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

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), false);
    }

    @Test
    public void testSignatureCreationWithExternalFilesystemBinaryReference() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = getKeyStore();
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(securePart);

        final File file = resolveFile(
            "target/test-classes/org/apache/xml/security/test/stax/signature/SignatureVerificationReferenceURIResolverTest.class");
        securePart = new SecurePart(file.toURI().toString(),
                null,
                XMLSecurityConstants.NS_XMLDSIG_SHA1);
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

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), false);
    }

    @Test
    public void testSignatureCreationWithExternalHttpReference() throws Exception {

        final Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            final Map<String, String> resolverProperties = new HashMap<>();
            resolverProperties.put("http.proxy.host", ((InetSocketAddress)proxy.address()).getAddress().getHostAddress());
            resolverProperties.put("http.proxy.port", "" + ((InetSocketAddress)proxy.address()).getPort());
            final ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP(resolverProperties);

            // Set up the Configuration
            final XMLSecurityProperties properties = new XMLSecurityProperties();
            final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
            actions.add(XMLSecurityConstants.SIGNATURE);
            properties.setActions(actions);

            // Set the key up
            final KeyStore keyStore = getKeyStore();
            final Key key = keyStore.getKey("transmitter", "default".toCharArray());
            properties.setSignatureKey(key);
            final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
            properties.setSignatureCerts(new X509Certificate[]{cert});

            SecurePart securePart =
                    new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
            properties.addSignaturePart(securePart);

            securePart = new SecurePart("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64", null, XMLSecurityConstants.NS_XMLDSIG_SHA1);
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

            Document document = null;
            try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
                document = XMLUtils.read(is, false);
            }

            // Verify using DOM
            verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), resolverDirectHTTP);
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }

    @Test
    public void testSignatureCreationWithSameDocumentXPointerIdApostropheReference() throws Exception {
        // Set up the Configuration
        final XMLSecurityProperties properties = new XMLSecurityProperties();
        final List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        final KeyStore keyStore = getKeyStore();
        final Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        final X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        final SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), true, SecurePart.Modifier.Element);
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

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.read(is, false);
        }

        final NodeList nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
        assertEquals(1, nodeList.getLength());

        final String uri = ((Element) nodeList.item(0)).getAttribute("URI");
        assertNotNull(uri);
        assertTrue(uri.startsWith("#xpointer"));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }


    private KeyStore getKeyStore() throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream inputStream = getClass().getClassLoader().getResource("transmitter.jks").openStream()) {
            keyStore.load(inputStream, "default".toCharArray());
        }
        return keyStore;
    }
}