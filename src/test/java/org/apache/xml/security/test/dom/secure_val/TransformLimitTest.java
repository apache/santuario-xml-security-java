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
package org.apache.xml.security.test.dom.secure_val;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the maximum number of transforms in a Reference.
 * This prevents DoS attacks via excessive transform processing.
 */
class TransformLimitTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public TransformLimitTest() {
        // Public constructor for JUnit
    }

    /**
     * Test that the MAXIMUM_TRANSFORM_COUNT constant is defined and has
     * the expected value (5 transforms as per spec).
     */
    @Test
    void testTransformCountConstantExists() {
        // Verify the constant is defined
        int maxCount = Reference.MAXIMUM_TRANSFORM_COUNT;
        
        // Per the XML Digital Signature spec and security best practices,
        // the maximum should be 5
        assertEquals(5, maxCount, 
            "Maximum transform count should be 5 to prevent DoS attacks");
    }

    /**
     * Test that a signature with exactly 5 transforms is accepted
     * when secure validation is enabled.
     */
    @Test
    void testExactlyMaxTransformsAccepted() throws Exception {
        Document doc = createSignatureWithTransforms(Reference.MAXIMUM_TRANSFORM_COUNT);
        
        // Parse with secure validation enabled - should succeed
        byte[] signedBytes = docToBytes(doc);
        Document parsedDoc = XMLUtils.read(new ByteArrayInputStream(signedBytes), false);
        Element sigElement = getSignatureElement(parsedDoc);
        
        // This should not throw an exception
        XMLSignature signature = new XMLSignature(sigElement, "", true);
        assertNotNull(signature);
        assertEquals(1, signature.getSignedInfo().getLength());
        
        // Access the reference to trigger parsing and validation
        Reference ref = signature.getSignedInfo().item(0);
        assertNotNull(ref);
    }

    /**
     * Test that a signature with 6 transforms (exceeding the limit) is rejected
     * when secure validation is enabled.
     */
    @Test
    void testExcessiveTransformsRejectedWithSecureValidation() throws Exception {
        int transformCount = Reference.MAXIMUM_TRANSFORM_COUNT + 1;
        Document doc = createSignatureWithTransforms(transformCount);
        
        // Parse with secure validation enabled - should fail
        byte[] signedBytes = docToBytes(doc);
        Document parsedDoc = XMLUtils.read(new ByteArrayInputStream(signedBytes), false);
        Element sigElement = getSignatureElement(parsedDoc);
        
        XMLSignature signature = new XMLSignature(sigElement, "", true);
        
        // Accessing the reference should trigger the validation and throw exception
        XMLSecurityException exception = assertThrows(XMLSecurityException.class, () -> {
            signature.getSignedInfo().item(0);
        }, "Should reject signature with " + transformCount + " transforms when secure validation is enabled");
        
        assertTrue(exception.getMessage().contains("tooManyTransforms") ||
                   exception.getMessage().contains("transforms"),
                   "Exception message should mention transforms: " + exception.getMessage());
    }

    /**
     * Test that a signature with 6 transforms is accepted when secure validation
     * is disabled (backward compatibility).
     */
    @Test
    void testExcessiveTransformsAcceptedWithoutSecureValidation() throws Exception {
        int transformCount = Reference.MAXIMUM_TRANSFORM_COUNT + 1;
        Document doc = createSignatureWithTransforms(transformCount);
        
        // Parse with secure validation disabled - should succeed
        byte[] signedBytes = docToBytes(doc);
        Document parsedDoc = XMLUtils.read(new ByteArrayInputStream(signedBytes), false);
        Element sigElement = getSignatureElement(parsedDoc);
        
        // This should not throw an exception when secure validation is disabled
        XMLSignature signature = new XMLSignature(sigElement, "", false);
        assertNotNull(signature);
        assertEquals(1, signature.getSignedInfo().getLength());
        
        // Access the reference - should work without secure validation
        Reference ref = signature.getSignedInfo().item(0);
        assertNotNull(ref);
    }

    /**
     * Test with an extreme number of transforms (10) to verify the limit enforcement.
     */
    @Test
    void testExtremeTransformCountRejected() throws Exception {
        int transformCount = 10;
        Document doc = createSignatureWithTransforms(transformCount);
        
        // Parse with secure validation enabled - should fail
        byte[] signedBytes = docToBytes(doc);
        Document parsedDoc = XMLUtils.read(new ByteArrayInputStream(signedBytes), false);
        Element sigElement = getSignatureElement(parsedDoc);
        
        XMLSignature signature = new XMLSignature(sigElement, "", true);
        
        // Accessing the reference should trigger the validation and throw exception
        XMLSecurityException exception = assertThrows(XMLSecurityException.class, () -> {
            signature.getSignedInfo().item(0);
        }, "Should reject signature with " + transformCount + " transforms");
        
        assertTrue(exception.getMessage().contains("tooManyTransforms") ||
                   exception.getMessage().contains("transforms"),
                   "Exception message should mention transforms");
    }

    /**
     * Creates a signed XML document with the specified number of transforms.
     * Each transform is a valid canonicalization transform.
     */
    private Document createSignatureWithTransforms(int transformCount) throws Exception {
        // Create a simple document
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some content to sign"));

        // Create signature
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());

        // Create transforms with the specified count
        Transforms transforms = new Transforms(doc);
        
        // Add the requested number of transforms
        // We alternate between different canonicalization methods to ensure validity
        String[] transformAlgorithms = {
            Transforms.TRANSFORM_C14N_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N11_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N11_WITH_COMMENTS
        };
        
        for (int i = 0; i < transformCount; i++) {
            String algorithm = transformAlgorithms[i % transformAlgorithms.length];
            transforms.addTransform(algorithm);
        }

        // Add document reference with transforms
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        
        // Add public key info
        sig.addKeyInfo(kp.getPublic());
        
        // Sign the document
        sig.sign(kp.getPrivate());

        return doc;
    }

    private byte[] docToBytes(Document doc) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    private Element getSignatureElement(Document doc) {
        return (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
    }
}
