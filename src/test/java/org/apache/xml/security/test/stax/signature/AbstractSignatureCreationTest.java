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
import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 */
public class AbstractSignatureCreationTest {

    protected static String BASEDIR;
    protected static boolean bcInstalled;

    protected XMLInputFactory xmlInputFactory;

    @BeforeAll
    public static void setup() throws Exception {
        String baseDir = System.getProperty("basedir");
        if (baseDir == null) {
            baseDir = new File(".").getCanonicalPath();
        }
        BASEDIR = baseDir;

        org.apache.xml.security.Init.init();

        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (Exception e) {
                //ignore
            }
            if (cons != null) {
                Provider provider = (Provider)cons.newInstance();
                Security.insertProviderAt(provider, 2);
                bcInstalled = true;
            }
        }
    }

    @org.junit.jupiter.api.AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @BeforeEach
    public void createXMLInputFactory() throws Exception {
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

    protected void verifyUsingDOM(
            Document document,
            X509Certificate cert,
            List<SecurePart> secureParts,
            boolean secureValidation
    ) throws Exception {
        verifyUsingDOM(document, cert, secureParts, null,
                true, "Id", secureValidation);
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
        verifyUsingDOM(document, cert, secureParts, resourceResolverSpi, true, "Id", true);
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
            String idAttributeNS,
            boolean secureValidation
    ) throws Exception {
        XPath xpath = getXPath();

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

        XMLSignature signature = new XMLSignature(sigElement, "", secureValidation, null);
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
        XPath xpath = getXPath();

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

    protected void verifyUsingDOMWithoutId(
            Document document,
            Key key,
            List<SecurePart> secureParts
    ) throws Exception {
        XPath xpath = getXPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);
        assertEquals("", sigElement.getAttribute("Id"));

        assertEquals(1, secureParts.size(), "Without Id there can only be one secure part");
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

    protected void verifyUsingDOMWithoutIdAndDefaultTransform (
            Document document,
            Key key,
            List<SecurePart> secureParts
    ) throws Exception {
        XPath xpath = getXPath();

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);
        assertEquals("", sigElement.getAttribute("Id"));

        assertEquals(1, secureParts.size(), "Without Id there can only be one secure part");
        //assertNull(secureParts.get(0).getName());

        Element signedElement = document.getDocumentElement();

        XMLSignature signature = new XMLSignature(sigElement, "");

        // We need a special resolver for the empty URI
        signature.addResourceResolver(new EmptyURIResourceResolverSpi(signedElement));

        assertTrue(signature.checkSignatureValue(key));
    }

    private XPath getXPath() {
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