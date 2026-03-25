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

import java.security.*;
import java.util.Enumeration;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class SignatureTest {
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private final KeyStore keyStore;

    public SignatureTest() throws Exception {
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
        keyStore = XmlSecTestEnvironment.getTestKeyStore();
    }

    @Test
    void testSigning() throws Throwable {
        signDocument(getOriginalDocument());
    }

    @Test
    void testSigningVerifyingFromRebuildSignature() throws Throwable {
        Document doc = getOriginalDocument();
        signDocument(doc);
        Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS, "Signature").item(0);
        XMLSignature signature = new XMLSignature(signatureElem, "");

        PublicKey pubKey = getPublicKey();

        assertTrue(signature.checkSignatureValue(pubKey));
    }

    @Test
    void testSigningVerifyingFromRebuildSignatureWithProvider() throws Throwable {
        Provider provider = null;
        try {
            Class<?> bouncyCastleProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            provider = (Provider)bouncyCastleProviderClass.getConstructor().newInstance();

            Document doc = getOriginalDocument();
            XMLSignature signature = signDocument(doc, provider);
            assertEquals(provider.getName(), signature.getSignedInfo().getSignatureAlgorithm().getJCEProviderName());

            Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS, "Signature").item(0);
            signature = new XMLSignature(signatureElem, "", provider);
            assertEquals(provider.getName(), signature.getSignedInfo().getSignatureAlgorithm().getJCEProviderName());

            PublicKey pubKey = getPublicKey();
            assertTrue(signature.checkSignatureValue(pubKey));
        } catch (ReflectiveOperationException e) {
            // BouncyCastle not installed, skip
            assumeFalse(provider == null);
        }
    }

    @Test
    void testSigningVerifyingFromExistingSignature() throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature signature = signDocument(doc);

        PublicKey pubKey = getPublicKey();
        assertTrue(signature.checkSignatureValue(pubKey));
    }

    @Test
    void testSigningVerifyingFromExistingSignatureWithProvider() throws Throwable {
        Provider provider = null;
        try {
            Class<?> bouncyCastleProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            provider = (Provider)bouncyCastleProviderClass.getConstructor().newInstance();
            Document doc = getOriginalDocument();
            XMLSignature signature = signDocument(doc, provider);
            assertEquals(provider.getName(), signature.getSignedInfo().getSignatureAlgorithm().getJCEProviderName());

            PublicKey pubKey = getPublicKey();
            assertTrue(signature.checkSignatureValue(pubKey));
        } catch (ReflectiveOperationException e) {
            // BouncyCastle not installed, skip
            assumeFalse(provider == null);
        }
    }

    @Test
    void testSigningVerifyingFromExistingSignatureSameThread()
        throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature signature = signDocument(doc);

        PublicKey pubKey = getPublicKey();

        VerifyingRunnable r = new VerifyingRunnable(signature, pubKey);
        r.run();
        if (r.throwable != null) {
            throw r.throwable;
        }
        assertTrue(r.result);
    }

    @Test
    void testSigningVerifyingFromExistingSignatureSeparateThread()
        throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature signature = signDocument(doc);

        PublicKey pubKey = getPublicKey();
        VerifyingRunnable r = new VerifyingRunnable(signature, pubKey);
        Thread t = new Thread(r);
        t.start();
        t.join();
        if (r.throwable != null) {
            throw r.throwable;
        }
        assertTrue(r.result);
    }

    public static class VerifyingRunnable implements Runnable {
        public volatile Throwable throwable;
        public volatile boolean result;
        private final XMLSignature signature;
        private final PublicKey pubKey;

        public VerifyingRunnable(XMLSignature signature, PublicKey pubKey) {
            this.signature = signature;
            this.pubKey = pubKey;
        }

        @Override
        public void run() {
            try {
                result = signature.checkSignatureValue(pubKey);
            } catch (XMLSignatureException e) {
                throwable = e;
            }
        }
    }

    private PublicKey getPublicKey() throws Exception {
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
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, XmlSecTestEnvironment.TEST_KS_PASSWORD.toCharArray());
            }
        }
        return null;
    }

    private Document getOriginalDocument() throws Throwable {
        Document doc = TestUtils.newDocument();

        Element rootElement = doc.createElementNS("http://ns.example.org/", "root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
        doc.appendChild(rootElement);

        return doc;
    }

    private XMLSignature signDocument(Document doc) throws Throwable {
        return signDocument(doc, null);
    }

    private XMLSignature signDocument(Document doc, Provider provider) throws Throwable {
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA, provider);
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

    /**
     * Test that null private key is rejected during signing.
     */
    @Test
    void testSignWithNullKeyRejection() throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        doc.getDocumentElement().appendChild(sig.getElement());
        
        sig.addDocument("", null, Constants.ALGO_ID_DIGEST_SHA1);
        
        assertThrows(XMLSignatureException.class, () -> {
            sig.sign(null);
        }, "Null private key should be rejected");
    }

    /**
     * Test that tampered signature value is detected.
     */
    @Test
    void testTamperedSignatureValueDetection() throws Throwable {
        Document doc = getOriginalDocument();
        signDocument(doc);
        
        // Tamper with the SignatureValue
        Element sigValue = (Element) doc.getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);
        String originalValue = sigValue.getTextContent();
        
        // Flip some bits by changing a character
        String tamperedValue = "AAAA" + originalValue.substring(4);
        sigValue.setTextContent(tamperedValue);
        
        // Rebuild signature and verify - should fail
        Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS, "Signature").item(0);
        XMLSignature signature = new XMLSignature(signatureElem, "");
        
        assertFalse(signature.checkSignatureValue(getPublicKey()),
            "Tampered signature should not verify");
    }

    /**
     * Test that tampered document content is detected.
     */
    @Test
    void testTamperedDocumentContentDetection() throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature sig = signDocument(doc);
        
        // Tamper with the document content after signing
        Element root = doc.getDocumentElement();
        root.setTextContent("Tampered content!");
        
        // Signature should not verify
        assertFalse(sig.checkSignatureValue(getPublicKey()),
            "Signature should not verify after document tampering");
    }

    /**
     * Test that empty document can be signed.
     */
    @Test
    void testSignEmptyDocument() throws Throwable {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://ns.example.org/", "root");
        // No content - empty element
        doc.appendChild(root);
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        root.appendChild(sig.getElement());
        
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        
        sig.sign(getPrivateKey());
        
        // Verify
        assertTrue(sig.checkSignatureValue(getPublicKey()),
            "Empty document signature should verify");
    }

    /**
     * Test that zero-length signature is handled correctly.
     */
    @Test
    void testZeroLengthSignatureRejection() throws Throwable {
        Document doc = getOriginalDocument();
        signDocument(doc);
        
        // Set SignatureValue to empty
        Element sigValue = (Element) doc.getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);
        sigValue.setTextContent("");
        
        Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS, "Signature").item(0);
        XMLSignature signature = new XMLSignature(signatureElem, "");
        
        // Should fail (either throw exception or return false)
        try {
            boolean result = signature.checkSignatureValue(getPublicKey());
            assertFalse(result, "Empty signature should not verify");
        } catch (XMLSignatureException e) {
            // Also acceptable - exception on empty signature
            assertNotNull(e);
        }
    }

    /**
     * Test that malformed signature element structure is detected.
     */
    @Test
    void testMalformedSignatureStructureRejection() throws Throwable {
        Document doc = getOriginalDocument();
        signDocument(doc);
        
        // Remove required SignedInfo element
        Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS, "Signature").item(0);
        Element signedInfo = (Element) signatureElem.getElementsByTagNameNS(DS_NS, "SignedInfo").item(0);
        signatureElem.removeChild(signedInfo);
        
        // Trying to create XMLSignature from malformed structure should fail
        assertThrows(XMLSignatureException.class, () -> {
            new XMLSignature(signatureElem, "");
        }, "Signature without SignedInfo should be rejected");
    }

    /**
     * Test concurrent signing operations don't interfere.
     */
    @Test
    void testConcurrentSigningOperations() throws Throwable {
        final int numThreads = 5;
        final Thread[] threads = new Thread[numThreads];
        final Throwable[] exceptions = new Throwable[numThreads];
        final boolean[] results = new boolean[numThreads];
        
        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    Document doc = getOriginalDocument();
                    XMLSignature sig = signDocument(doc);
                    results[index] = sig.checkSignatureValue(getPublicKey());
                } catch (Throwable t) {
                    exceptions[index] = t;
                }
            });
        }
        
        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Wait for completion
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Verify all succeeded
        for (int i = 0; i < numThreads; i++) {
            if (exceptions[i] != null) {
                throw new Exception("Thread " + i + " failed", exceptions[i]);
            }
            assertTrue(results[i], "Thread " + i + " signature should verify");
        }
    }
}
