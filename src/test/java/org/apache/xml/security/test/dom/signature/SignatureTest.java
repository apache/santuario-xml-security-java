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
}
