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

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.stax.utils.HttpRequestRedirectorProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
class SignatureCreationReferenceURIResolverTest extends AbstractSignatureCreationTest {

    @BeforeAll
    public static void setup() throws Exception {
        AbstractSignatureCreationTest.setup();
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    @Test
    void testSignatureCreationWithExternalFilesystemXMLReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(securePart);

        File file = resolveFile("src/test/resources/ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        securePart = new SecurePart(file.toURI().toString(),
                new String[]{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
                XMLSecurityConstants.NS_XMLDSIG_SHA1);
        properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);
        // System.out.println("Got:\n" + new String(output, StandardCharsets.UTF_8));
        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), false);
    }

    @Test
    void testSignatureCreationWithExternalFilesystemBinaryReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addSignaturePart(securePart);

        File file = resolveFile(
            "target/test-classes/org/apache/xml/security/test/stax/signature/SignatureVerificationReferenceURIResolverTest.class");
        securePart = new SecurePart(file.toURI().toString(),
                null,
                XMLSecurityConstants.NS_XMLDSIG_SHA1);
        properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);
        // System.out.println("Got:\n" + new String(output, StandardCharsets.UTF_8));
        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), false);
    }

    @Test
    void testSignatureCreationWithExternalHttpReference() throws Exception {

        Proxy proxy = HttpRequestRedirectorProxy.startHttpEngine();

        try {
            ResolverHttp.setProxy(proxy);

            Map<String, String> resolverProperties = new HashMap<>();
            resolverProperties.put("http.proxy.host", ((InetSocketAddress)proxy.address()).getAddress().getHostAddress());
            resolverProperties.put("http.proxy.port", "" + ((InetSocketAddress)proxy.address()).getPort());
            ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP(resolverProperties);

            // Set up the Configuration
            XMLSecurityProperties properties = new XMLSecurityProperties();
            List<XMLSecurityConstants.Action> actions = new ArrayList<>();
            actions.add(XMLSecurityConstants.SIGNATURE);
            properties.setActions(actions);

            // Set the key up
            KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
            Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
            properties.setSignatureKey(key);
            X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
            properties.setSignatureCerts(new X509Certificate[]{cert});

            SecurePart securePart =
                    new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
            properties.addSignaturePart(securePart);

            securePart = new SecurePart("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64", null, XMLSecurityConstants.NS_XMLDSIG_SHA1);
            properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);
        // System.out.println("Got:\n" + new String(output, StandardCharsets.UTF_8));
        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
                document = XMLUtils.read(is, false);
            }

            // Verify using DOM
            verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), resolverDirectHTTP);
        } finally {
            HttpRequestRedirectorProxy.stopHttpEngine();
        }
    }

    @Test
    void testSignatureCreationWithSameDocumentXPointerIdApostropheReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        Key key = keyStore.getKey("transmitter", TRANSMITTER_KS_PASSWORD.toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), true, SecurePart.Modifier.Element);
        properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);
        // System.out.println("Got:\n" + new String(output, StandardCharsets.UTF_8));
        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
        assertEquals(1, nodeList.getLength());

        String uri = ((Element) nodeList.item(0)).getAttribute("URI");
        assertNotNull(uri);
        assertTrue(uri.startsWith("#xpointer"));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }
}