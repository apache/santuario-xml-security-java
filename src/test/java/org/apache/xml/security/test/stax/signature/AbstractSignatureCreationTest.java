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

import java.io.File;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.stream.XMLInputFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.Before;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 */
public class AbstractSignatureCreationTest {

    protected static String BASEDIR;

    protected XMLInputFactory xmlInputFactory;

    @Before
    public void setUp() throws Exception {

        BASEDIR = System.getProperty("basedir");
        if (BASEDIR == null) {
            BASEDIR = new File(".").getCanonicalPath();
        }

        org.apache.xml.security.Init.init();

        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    /**
     * Verify the document using DOM
     */
    protected void verifyUsingDOM(
            Document document,
            X509Certificate cert,
            List<SecurePart> secureParts
    ) throws Exception {
        verifyUsingDOM(document, cert, secureParts, null);
    }

    /**
     * Verify the document using DOM
     */
    protected void verifyUsingDOM(
            Document document,
            X509Certificate cert,
            List<SecurePart> secureParts,
            ResourceResolverSpi resourceResolverSpi
    ) throws Exception {
        verifyUsingDOM(document, cert, secureParts, resourceResolverSpi, true, "Id");
    }

    /**
     * Verify the document using DOM
     */
    protected void verifyUsingDOM(
            Document document,
            X509Certificate cert,
            List<SecurePart> secureParts,
            ResourceResolverSpi resourceResolverSpi,
            boolean keyInfoRequired,
            String idAttributeNS
    ) throws Exception {
        XPath xpath = getxPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        for (SecurePart securePart : secureParts) {
            if (securePart.getName() == null) {
                continue;
            }
            expression = "//*[local-name()='" + securePart.getName().getLocalPart() + "']";
            Element signedElement =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, idAttributeNS, true);
        }

        XMLSignature signature = new XMLSignature(sigElement, "");
        if (resourceResolverSpi != null) {
            signature.addResourceResolver(resourceResolverSpi);
        }
        if (keyInfoRequired) {
            KeyInfo ki = signature.getKeyInfo();
            assertNotNull(ki);
        }

        assertTrue(signature.checkSignatureValue(cert));
    }

    /**
     * Verify the document using DOM
     */
    protected void verifyUsingDOM(
            Document document,
            Key key,
            List<SecurePart> secureParts
    ) throws Exception {
        XPath xpath = getxPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        for (SecurePart securePart : secureParts) {
            expression = "//*[local-name()='" + securePart.getName().getLocalPart() + "']";
            Element signedElement =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, "Id", true);
        }

        XMLSignature signature = new XMLSignature(sigElement, "");
        assertTrue(signature.checkSignatureValue(key));
    }

    protected void verifyUsingDOMWihtoutId(
            Document document,
            Key key,
            List<SecurePart> secureParts
    ) throws Exception {
        XPath xpath = getxPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);
        assertEquals("", sigElement.getAttribute("Id"));

        assertEquals("Without Id there can only be one secure part", 1, secureParts.size());
        expression = "//*[local-name()='" + secureParts.get(0).getName().getLocalPart() + "']";
        Element signedElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(signedElement);
        assertEquals("", signedElement.getAttribute("Id"));

        XMLSignature signature = new XMLSignature(sigElement, "");

        // We need a special resolver for the empty URI
        signature.addResourceResolver(new EmptyURIResourceResolverSpi(signedElement));

        assertTrue(signature.checkSignatureValue(key));
    }

    protected void verifyUsingDOMWihtoutIdAndDefaultTransform (
            Document document,
            Key key,
            List<SecurePart> secureParts
    ) throws Exception {
        XPath xpath = getxPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);
        assertEquals("", sigElement.getAttribute("Id"));

        assertEquals("Without Id there can only be one secure part", 1, secureParts.size());
        //assertNull(secureParts.get(0).getName());

        Element signedElement = document.getDocumentElement();

        XMLSignature signature = new XMLSignature(sigElement, "");

        // We need a special resolver for the empty URI
        signature.addResourceResolver(new EmptyURIResourceResolverSpi(signedElement));

        assertTrue(signature.checkSignatureValue(key));
    }

    private XPath getxPath() {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        return xpath;
    }

    private static class EmptyURIResourceResolverSpi extends ResourceResolverSpi {
        private final Element signedElement;

        public EmptyURIResourceResolverSpi(Element signedElement) {
            this.signedElement = signedElement;
        }

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
            if (!context.uriToResolve.isEmpty()) {
                throw new ResourceResolverException("This resolved can only handle empty URIs", context.uriToResolve, context.baseUri);
            }
            return new XMLSignatureInput(signedElement);
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            return context.uriToResolve.isEmpty();
        }
    }
}