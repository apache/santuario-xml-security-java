/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.extension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureProcessorTest {

    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void setup() throws Exception {
        Init.init();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();
    }

    private XMLSignature newSignature(Document doc) throws Exception {
        return new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    }

    @Test
    void preProcessorIsInvokedBeforeSignatureValue() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        boolean[] sigValueEmptyInPreProcessor = {false};

        sig.addPreProcessor(signature -> {
            try {
                byte[] value = signature.getSignatureValue();
                sigValueEmptyInPreProcessor[0] = (value == null || value.length == 0);
            } catch (XMLSignatureException e) {
                sigValueEmptyInPreProcessor[0] = true;
            }
        });

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(rsaKeyPair.getPrivate());

        assertTrue(sigValueEmptyInPreProcessor[0],
                "Pre-processor must be called before SignatureValue is populated");
    }

    @Test
    void postProcessorIsInvokedAfterSignatureValue() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        boolean[] sigValueSetInPostProcessor = {false};

        sig.addPostProcessor(signature -> {
            try {
                byte[] value = signature.getSignatureValue();
                sigValueSetInPostProcessor[0] = (value != null && value.length > 0);
            } catch (XMLSignatureException e) {
                sigValueSetInPostProcessor[0] = false;
            }
        });

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(rsaKeyPair.getPrivate());

        assertTrue(sigValueSetInPostProcessor[0],
                "Post-processor must be called after SignatureValue is populated");
    }

    @Test
    void multiplePreProcessorsAreInvokedInRegistrationOrder() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        List<String> invocationOrder = new ArrayList<>();
        sig.addPreProcessor(signature -> invocationOrder.add("pre-1"));
        sig.addPreProcessor(signature -> invocationOrder.add("pre-2"));
        sig.addPreProcessor(signature -> invocationOrder.add("pre-3"));

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(rsaKeyPair.getPrivate());

        assertEquals(List.of("pre-1", "pre-2", "pre-3"), invocationOrder,
                "Pre-processors must be invoked in registration order");
    }

    @Test
    void multiplePostProcessorsAreInvokedInRegistrationOrder() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        List<String> invocationOrder = new ArrayList<>();
        sig.addPostProcessor(signature -> invocationOrder.add("post-1"));
        sig.addPostProcessor(signature -> invocationOrder.add("post-2"));
        sig.addPostProcessor(signature -> invocationOrder.add("post-3"));

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(rsaKeyPair.getPrivate());

        assertEquals(List.of("post-1", "post-2", "post-3"), invocationOrder,
                "Post-processors must be invoked in registration order");
    }

    @Test
    void preProcessorExceptionAbortsSigningAndPropagates() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        sig.addPreProcessor(signature -> {
            throw new SignatureExtensionException("pre-processor failure");
        });

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        XMLSignatureException thrown = assertThrows(XMLSignatureException.class,
                () -> sig.sign(rsaKeyPair.getPrivate()),
                "XMLSignatureException from a pre-processor must propagate out of sign()");

        assertEquals("pre-processor failure", thrown.getMessage());
    }

    @Test
    void postProcessorCanReadSignatureValueId() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        sig.setSignatureValueId("sig-value-id-1");

        String[] idInPostProcessor = {null};
        sig.addPostProcessor(signature -> idInPostProcessor[0] = signature.getSignatureValueId());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(rsaKeyPair.getPrivate());

        assertEquals("sig-value-id-1", idInPostProcessor[0],
                "Post-processor must read the SignatureValue Id set before signing");
    }

    @Test
    void addPreProcessorRejectsNull() throws Exception {
        Document doc = TestUtils.newDocument();
        XMLSignature sig = newSignature(doc);
        assertThrows(NullPointerException.class, () -> sig.addPreProcessor(null));
    }

    @Test
    void addPostProcessorRejectsNull() throws Exception {
        Document doc = TestUtils.newDocument();
        XMLSignature sig = newSignature(doc);
        assertThrows(NullPointerException.class, () -> sig.addPostProcessor(null));
    }

    @Test
    void signatureValueIdRoundTrip() throws Exception {
        Document doc = TestUtils.newDocument();
        XMLSignature sig = newSignature(doc);

        assertNull(sig.getSignatureValueId(), "Id must be null before it is set");

        sig.setSignatureValueId("my-id");
        assertEquals("my-id", sig.getSignatureValueId());

        sig.setSignatureValueId(null);
        assertNull(sig.getSignatureValueId(), "Id must be null after passing null");
    }

    @Test
    void signatureRemainsValidWithHooks() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://example.org/", "root");
        doc.appendChild(root);
        XMLSignature sig = newSignature(doc);
        root.appendChild(sig.getElement());

        sig.addPreProcessor(signature -> { /* no-op */ });
        sig.addPostProcessor(signature -> { /* no-op */ });

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        sig.sign(rsaKeyPair.getPrivate());

        PublicKey publicKey = rsaKeyPair.getPublic();
        assertTrue(sig.checkSignatureValue(publicKey),
                "Signature produced with no-op hooks must verify correctly");
    }
}
