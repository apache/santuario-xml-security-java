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


import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.VerifiedReference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.reference.ReferenceData;
import org.apache.xml.security.signature.reference.ReferenceNodeSetData;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Test a Signature and Validation, and check that we have access to the Element(s) that was
 * validated.
 */
public class SignatureReferenceTest {
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    public SignatureReferenceTest() throws Exception {
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
    }

    @Test
    public void testSigningVerifyingReference() throws Throwable {
        final Document doc = getOriginalDocument();
        final XMLSignature signature = signDocument(doc);

        final PublicKey pubKey = getPublicKey(XmlSecTestEnvironment.getTestKeyStore());
        assertTrue(signature.checkSignatureValue(pubKey));

        // Check the reference(s)
        final SignedInfo signedInfo = signature.getSignedInfo();
        assertTrue(signedInfo.getLength() == 1);
        final Reference reference = signedInfo.item(0);
        final ReferenceData referenceData = reference.getReferenceData();
        assertNotNull(referenceData);
        assertTrue(referenceData instanceof ReferenceNodeSetData);

        // Test the cached Element
        final Element referenceElement =
            (Element)((ReferenceNodeSetData)referenceData).iterator().next();
        assertNotNull(referenceElement);
        assertEquals("root", referenceElement.getLocalName());

        final Element originalElement =
            (Element) doc.getElementsByTagNameNS("http://ns.example.org/", "root").item(0);
        assertNotNull(originalElement);
        assertEquals(referenceElement, originalElement);
    }

    // See SANTUARIO-465
    @Test
    public void testNoReferenceChildren() throws ParserConfigurationException, XMLSecurityException {
        final Document doc = TestUtils.newDocument();
        final Element referenceElement = doc.createElementNS(Constants.SignatureSpecNS, "Reference");
        referenceElement.setAttributeNS(null, "URI", "#_12345");

        // No DigestMethod child
        try {
            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestMethod child element");
        } catch (final XMLSecurityException ex) {
            // ex.printStackTrace();
            // expected
        }

        // No DigestValue child
        try {
            final Element digestMethod = doc.createElementNS(Constants.SignatureSpecNS, "DigestMethod");
            digestMethod.setAttributeNS(null, "Algorithm", DigestMethod.SHA1);
            referenceElement.appendChild(digestMethod);

            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestValue child element");
        } catch (final XMLSecurityException ex) {
            // expected
        }

        final Element digestValue = doc.createElementNS(Constants.SignatureSpecNS, "DigestValue");
        digestValue.setTextContent("abcabc");
        referenceElement.appendChild(digestValue);

        new WrappedReference(referenceElement, "_54321", null);
    }

    @Test
    public void testManifestReferences() throws Throwable {

        final XPathFactory xpf = XPathFactory.newInstance();
        final XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        final InputStream sourceDocument =
            this.getClass().getClassLoader().getResourceAsStream(
                    "at/iaik/ixsil/coreFeatures/signatures/manifestSignature.xml");
        final Document document = XMLUtils.read(sourceDocument, false);

        final String expression = "//dsig:Signature[1]";
        final Element sigElement =
            (Element) xPath.evaluate(expression, document, XPathConstants.NODE);

        XMLSignature signatureToVerify = new XMLSignature(sigElement, "");

        final KeyInfo ki = signatureToVerify.getKeyInfo();
        final PublicKey publicKey = ki.getPublicKey();

        boolean signResult = signatureToVerify.checkSignatureValue(publicKey);
        assertTrue(signResult);

        List<VerifiedReference> verifiedReferences = signatureToVerify.getSignedInfo().getVerificationResults();
        assertEquals(verifiedReferences.size(), 1);
        assertEquals("#manifest", verifiedReferences.get(0).getUri());
        assertTrue(verifiedReferences.get(0).isValid());
        assertTrue(verifiedReferences.get(0).getManifestReferences().isEmpty());

        signatureToVerify = new XMLSignature(sigElement, "");
        signatureToVerify.addResourceResolver(new DummyResourceResolver());
        signatureToVerify.setFollowNestedManifests(true);

        signResult = signatureToVerify.checkSignatureValue(publicKey);
        assertFalse(signResult);

        verifiedReferences = signatureToVerify.getSignedInfo().getVerificationResults();
        assertEquals(verifiedReferences.size(), 1);
        assertEquals("#manifest", verifiedReferences.get(0).getUri());
        assertTrue(verifiedReferences.get(0).isValid());

        assertEquals(1, verifiedReferences.get(0).getManifestReferences().size());
        assertEquals("../samples/sampleXMLData.xml", verifiedReferences.get(0).getManifestReferences().get(0).getUri());
        assertFalse(verifiedReferences.get(0).getManifestReferences().get(0).isValid());
    }


    private PublicKey getPublicKey(KeyStore keyStore) throws Exception {
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    private PrivateKey getPrivateKey(KeyStore keyStore) throws Exception {
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, XmlSecTestEnvironment.TEST_KS_PASSWORD.toCharArray());
            }
        }
        return null;
    }

    private Document getOriginalDocument() throws Throwable {
        final Document doc = TestUtils.newDocument();

        final Element rootElement = doc.createElementNS("http://ns.example.org/", "root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
        doc.appendChild(rootElement);

        return doc;
    }

    private XMLSignature signDocument(Document doc) throws Throwable {
        final XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        final Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());

        sig.getSignedInfo().addResourceResolver(new ResolverXPointer());

        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        final KeyStore keyStore = XmlSecTestEnvironment.getTestKeyStore();
        sig.addKeyInfo(getPublicKey(keyStore));
        sig.sign(getPrivateKey(keyStore));

        return sig;
    }

    private static class WrappedReference extends Reference {
        public WrappedReference(Element element, String baseURI, Manifest manifest) throws XMLSecurityException {
            super(element, baseURI, manifest);
        }
    }

    private static class DummyResourceResolver extends ResourceResolverSpi {

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context)
            throws ResourceResolverException {
            final XMLSignatureInput result = new XMLSignatureInput("xyz");

            result.setSourceURI(context.uriToResolve);

            return result;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            return context.uriToResolve.endsWith("sampleXMLData.xml");
        }

    }
}