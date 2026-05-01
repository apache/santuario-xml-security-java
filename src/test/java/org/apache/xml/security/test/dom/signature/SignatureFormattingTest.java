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
package org.apache.xml.security.test.dom.signature;

import org.apache.xml.security.Init;
import org.apache.xml.security.formatting.FormattingChecker;
import org.apache.xml.security.formatting.FormattingCheckerFactory;
import org.apache.xml.security.formatting.FormattingTest;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureByteInput;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This is a {@link FormattingTest}, it is expected to be run with different system properties
 * to check various formatting configurations.
 *
 * The test creates a detached signature with a single reference and uses mock resource resolver.
 * RSA-2048 and SHA-512 are used to create longer binary values.
 */
@FormattingTest
class SignatureFormattingTest {
    private final static byte[] MOCK_DATA = new byte[]{ 0x0a, 0x0b, 0x0c, 0x0d };

    private final FormattingChecker formattingChecker;
    private KeyStore keyStore;
    private XPath xpath;
    private ResourceResolverSpi resolver;

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

        resolver = new TestResourceResolver(MOCK_DATA);

        XPathFactory xPathFactory = XPathFactory.newInstance();
        xpath = xPathFactory.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
    }

    @Test
    void testSignatureFormatting() throws Exception {
        /* this test checks formatting of base64Binary values */
        Document doc = createDocument();

        String docStr;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            XMLUtils.outputDOM(doc, out);
            out.flush();
            docStr = out.toString(StandardCharsets.UTF_8);
        }

        formattingChecker.checkDocument(docStr);

        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        Element digest = findElementByXpath("//ds:DigestValue[1]", doc);
        formattingChecker.checkBase64Value(digest.getTextContent());

        Element signatureValue = findElementByXpath("//ds:SignatureValue[1]", doc);
        formattingChecker.checkBase64ValueWithSpacing(signatureValue.getTextContent());

        Element x509certValue = findElementByXpath("//ds:X509Certificate[1]", doc);
        formattingChecker.checkBase64ValueWithSpacing(x509certValue.getTextContent());
    }

    @Test
    void testSignVerify() throws Exception {
        /* this test checks the signature can be verified with given formatting settings */
        Document doc = createDocument();
        Element signatureElement = findElementByXpath("//ds:Signature[1]", doc);
        XMLSignature signature = new XMLSignature(signatureElement, null);
        signature.addResourceResolver(resolver);

        PublicKey publicKey = keyStore.getCertificate("test").getPublicKey();
        assertTrue(signature.checkSignatureValue(publicKey));
    }

    private Document createDocument() throws Exception {
        Document doc = TestUtils.newDocument();

        XMLSignature signature = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
        signature.addResourceResolver(resolver);

        signature.addDocument("some.resource", null, DigestMethod.SHA512);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey("test", "xmlsecurity".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("test");

        signature.addKeyInfo(certificate);
        signature.sign(privateKey);

        doc.appendChild(signature.getElement());

        return doc;
    }

    private Element findElementByXpath(String expression, Node node) throws XPathExpressionException {
        return (Element) xpath.evaluate(expression, node, XPathConstants.NODE);
    }

    /**
     * Resolver implementation which resolves every URI to the same given mock data.
     */
    private static class TestResourceResolver extends ResourceResolverSpi {
        private byte[] mockData;

        /**
         * Creates new resolver.
         * @param mockData  Mock data bytes
         */
        public TestResourceResolver(byte[] mockData) {
            this.mockData = mockData;
        }

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
            return new XMLSignatureByteInput(mockData);
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            return true;
        }
    }
}
