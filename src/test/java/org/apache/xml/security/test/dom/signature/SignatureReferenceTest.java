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


import java.io.FileInputStream;
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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
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
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * Test a Signature and Validation, and check that we have access to the Element(s) that was
 * validated.
 */
public class SignatureReferenceTest {
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private static final String BASEDIR =
        System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    public static final String KEYSTORE_DIRECTORY = BASEDIR + "/src/test/resources/";
    public static final String KEYSTORE_PASSWORD_STRING = "changeit";
    public static final char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    public SignatureReferenceTest() throws Exception {
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
    }

    @org.junit.Test
    public void testSigningVerifyingReference() throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature signature = signDocument(doc);

        PublicKey pubKey = getPublicKey();
        assertTrue(signature.checkSignatureValue(pubKey));

        // Check the reference(s)
        SignedInfo signedInfo = signature.getSignedInfo();
        assertTrue(signedInfo.getLength() == 1);
        Reference reference = signedInfo.item(0);
        ReferenceData referenceData = reference.getReferenceData();
        assertNotNull(referenceData);
        assertTrue(referenceData instanceof ReferenceNodeSetData);

        // Test the cached Element
        Element referenceElement =
            (Element)((ReferenceNodeSetData)referenceData).iterator().next();
        assertNotNull(referenceElement);
        assertTrue("root".equals(referenceElement.getLocalName()));

        Element originalElement =
            (Element) doc.getElementsByTagNameNS("http://ns.example.org/", "root").item(0);
        assertNotNull(originalElement);
        assertEquals(referenceElement, originalElement);
    }

    // See SANTUARIO-465
    @org.junit.Test
    public void testNoReferenceChildren() throws ParserConfigurationException, XMLSecurityException {
        Document doc = XMLUtils.newDocument();
        Element referenceElement = doc.createElementNS(Constants.SignatureSpecNS, "Reference");
        referenceElement.setAttributeNS(null, "URI", "#_12345");

        // No DigestMethod child
        try {
            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestMethod child element");
        } catch (XMLSecurityException ex) {
            // ex.printStackTrace();
            // expected
        }

        // No DigestValue child
        try {
            Element digestMethod = doc.createElementNS(Constants.SignatureSpecNS, "DigestMethod");
            digestMethod.setAttributeNS(null, "Algorithm", DigestMethod.SHA1);
            referenceElement.appendChild(digestMethod);

            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestValue child element");
        } catch (XMLSecurityException ex) {
            // expected
        }

        Element digestValue = doc.createElementNS(Constants.SignatureSpecNS, "DigestValue");
        digestValue.setTextContent("abcabc");
        referenceElement.appendChild(digestValue);

        new WrappedReference(referenceElement, "_54321", null);
    }

    @org.junit.Test
    public void testManifestReferences() throws Throwable {

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        InputStream sourceDocument =
            this.getClass().getClassLoader().getResourceAsStream(
                    "at/iaik/ixsil/coreFeatures/signatures/manifestSignature.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        String expression = "//dsig:Signature[1]";
        Element sigElement =
            (Element) xPath.evaluate(expression, document, XPathConstants.NODE);

        XMLSignature signatureToVerify = new XMLSignature(sigElement, "");

        KeyInfo ki = signatureToVerify.getKeyInfo();
        PublicKey publicKey = ki.getPublicKey();

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

    /**
     * Loads the 'localhost' keystore from the test keystore.
     *
     * @return test keystore.
     * @throws Exception
     */
    private KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream ksis = new FileInputStream(KEYSTORE_DIRECTORY + "test.jks");
        ks.load(ksis, KEYSTORE_PASSWORD);
        ksis.close();
        return ks;
    }

    private PublicKey getPublicKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    private PrivateKey getPrivateKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD);
            }
        }
        return null;
    }

    private Document getOriginalDocument() throws Throwable {
        Document doc = XMLUtils.newDocument();

        Element rootElement = doc.createElementNS("http://ns.example.org/", "root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
        doc.appendChild(rootElement);

        return doc;
    }

    private XMLSignature signDocument(Document doc) throws Throwable {
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());

        sig.getSignedInfo().addResourceResolver(new ResolverXPointer());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(getPublicKey());
        sig.sign(getPrivateKey());

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
            XMLSignatureInput result = new XMLSignatureInput("xyz");

            result.setSourceURI(context.uriToResolve);

            return result;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            return context.uriToResolve.endsWith("sampleXMLData.xml");
        }

    }
}