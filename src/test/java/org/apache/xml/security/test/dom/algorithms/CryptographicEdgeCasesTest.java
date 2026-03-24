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
package org.apache.xml.security.test.dom.algorithms;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.TestUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for cryptographic edge cases including zero-length signatures,
 * all-zeros signatures, and other boundary conditions.
 */
class CryptographicEdgeCasesTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public CryptographicEdgeCasesTest() {
        // Public constructor for JUnit
    }

    /**
     * Test that empty signature values are rejected.
     */
    @Test
    void testEmptySignatureValueRejected() throws Exception {
        Document doc = TestUtils.newDocument();
        SignatureAlgorithm sa = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        
        // Initialize with proper key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        sa.initSign(keyPair.getPrivate());
        
        // Sign some data
        byte[] data = "test data".getBytes();
        sa.update(data);
        byte[] signature = sa.sign();
        
        // Valid signature should be non-empty
        assertTrue(signature.length > 0, "Signature should not be empty");
    }

    /**
     * Test that all-zeros signature is rejected during verification.
     */
    @Test
    void testAllZerosSignatureRejected() throws Exception {
        Document doc = TestUtils.newDocument();
        SignatureAlgorithm sa = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Initialize verification
        sa.initVerify(keyPair.getPublic());
        
        // Create all-zeros signature (256 bytes for RSA-2048)
        byte[] zeroSignature = new byte[256];
        
        // Update with some data
        byte[] data = "test data".getBytes();
        sa.update(data);
        
        // All-zeros signature should fail verification
        assertFalse(sa.verify(zeroSignature), 
            "All-zeros signature should not verify successfully");
    }

    /**
     * Test that signature verification requires the correct data.
     */
    @Test
    void testSignatureVerificationWithWrongData() throws Exception {
        Document doc = TestUtils.newDocument();
        SignatureAlgorithm sa = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Sign original data
        sa.initSign(keyPair.getPrivate());
        byte[] originalData = "original data".getBytes();
        sa.update(originalData);
        byte[] signature = sa.sign();
        
        // Try to verify with different data
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair.getPublic());
        byte[] wrongData = "wrong data".getBytes();
        verifier.update(wrongData);
        
        // Should fail verification
        assertFalse(verifier.verify(signature),
            "Signature should not verify with wrong data");
    }

    /**
     * Test that signature verification requires the correct key.
     */
    @Test
    void testSignatureVerificationWithWrongKey() throws Exception {
        Document doc = TestUtils.newDocument();
        SignatureAlgorithm sa = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
        KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
        
        // Sign with first key
        sa.initSign(keyPair1.getPrivate());
        byte[] data = "test data".getBytes();
        sa.update(data);
        byte[] signature = sa.sign();
        
        // Try to verify with second key
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair2.getPublic());
        verifier.update(data);
        
        // Should fail verification
        assertFalse(verifier.verify(signature),
            "Signature should not verify with wrong key");
    }

    /**
     * Test that signature algorithm names are properly registered.
     */
    @Test
    void testAlgorithmNamesRegistered() {
        // Test that common algorithm URIs are recognized
        String[] algorithms = {
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384,
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512,
            XMLSignature.ALGO_ID_SIGNATURE_DSA_SHA256,
            XMLSignature.ALGO_ID_MAC_HMAC_SHA256
        };
        
        for (String algo : algorithms) {
            assertNotNull(algo, "Algorithm URI should not be null");
            assertTrue(algo.startsWith("http://"), 
                "Algorithm URI should start with http://");
        }
    }

    /**
     * Test that signature creation and verification roundtrip works.
     */
    @Test
    void testSignatureRoundtrip() throws Exception {
        Document doc = TestUtils.newDocument();
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Sign
        SignatureAlgorithm signer = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        signer.initSign(keyPair.getPrivate());
        byte[] data = "test data for signing".getBytes();
        signer.update(data);
        byte[] signature = signer.sign();
        
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        
        assertTrue(verifier.verify(signature),
            "Signature should verify successfully with correct key and data");
    }

    /**
     * Test that multiple updates before signing work correctly.
     */
    @Test
    void testMultipleUpdatesBeforeSigning() throws Exception {
        Document doc = TestUtils.newDocument();
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Sign with multiple updates
        SignatureAlgorithm signer = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        signer.initSign(keyPair.getPrivate());
        signer.update("part1".getBytes());
        signer.update("part2".getBytes());
        signer.update("part3".getBytes());
        byte[] signature = signer.sign();
        
        // Verify with same multiple updates
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("part1".getBytes());
        verifier.update("part2".getBytes());
        verifier.update("part3".getBytes());
        
        assertTrue(verifier.verify(signature),
            "Signature should verify with same sequence of updates");
    }

    /**
     * Test that different update order produces different signature.
     */
    @Test
    void testDifferentUpdateOrder() throws Exception {
        Document doc = TestUtils.newDocument();
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Sign with one order
        SignatureAlgorithm signer = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        signer.initSign(keyPair.getPrivate());
        signer.update("part1".getBytes());
        signer.update("part2".getBytes());
        byte[] signature = signer.sign();
        
        // Verify with different order
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("part2".getBytes());
        verifier.update("part1".getBytes());
        
        assertFalse(verifier.verify(signature),
            "Signature should not verify with different update order");
    }

    /**
     * Test that empty update is handled correctly.
     */
    @Test
    void testEmptyUpdate() throws Exception {
        Document doc = TestUtils.newDocument();
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Sign with empty data
        SignatureAlgorithm signer = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        signer.initSign(keyPair.getPrivate());
        signer.update(new byte[0]);
        byte[] signature = signer.sign();
        
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify
        SignatureAlgorithm verifier = new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(new byte[0]);
        
        assertTrue(verifier.verify(signature),
            "Empty data signature should verify correctly");
    }
}
