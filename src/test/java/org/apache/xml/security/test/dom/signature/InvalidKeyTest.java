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

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test case contributed by Matthias Germann for testing that bug 43239 is
 * fixed: "No installed provider supports this key" when checking a RSA
 * signature against a DSA key before RSA key.
 */
class InvalidKeyTest {

    static {
        Init.init();
    }

    @Test
    void test() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream input = new FileInputStream(
            resolveFile("src/test/resources/org/apache/xml/security/samples/input/truststore.jks"))) {
            trustStore.load(input, "testpw".toCharArray());
        }

        try {
            validate(trustStore.getCertificate("bedag-test").getPublicKey());
            throw new Exception("Failure expected on a DSA key");
        } catch (Exception e) {
            // e.printStackTrace();
        }
        validate(trustStore.getCertificate("a70-garaio-frontend-u").getPublicKey());
    }

    private void validate(PublicKey pk) throws Exception {
        File file = resolveFile("src/test/resources/org/apache/xml/security/samples/input/test-assertion.xml");
        Document e = XMLUtils.read(file, false);
        Node assertion = e.getFirstChild();
        while (!(assertion instanceof Element)) {
            assertion = assertion.getNextSibling();
        }
        Attr attr = ((Element)assertion).getAttributeNodeNS(null, "AssertionID");
        if (attr != null) {
            ((Element)assertion).setIdAttributeNode(attr, true);
        }

        Element n = (Element)assertion.getLastChild();

        XMLSignature si = new XMLSignature(n, "");
        si.checkSignatureValue(pk);

        // System.out.println("VALIDATION OK" );
    }

    /**
     * Test that wrong key type is properly rejected.
     * Using EC key when RSA is expected should fail clearly.
     */
    @Test
    void testWrongKeyTypeRejection() throws Exception {
        File file = resolveFile("src/test/resources/org/apache/xml/security/samples/input/test-assertion.xml");
        Document doc = XMLUtils.read(file, false);
        Node assertion = doc.getFirstChild();
        while (!(assertion instanceof Element)) {
            assertion = assertion.getNextSibling();
        }
        
        Element n = (Element)assertion.getLastChild();
        XMLSignature sig = new XMLSignature(n, "");
        
        // Generate an EC key when signature expects RSA/DSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        assertThrows(XMLSecurityException.class, () -> {
            sig.checkSignatureValue(keyPair.getPublic());
        }, "EC key should be rejected when RSA/DSA signature expected");
    }

    /**
     * Test that different keys from same algorithm type are rejected.
     * Sign with one RSA key, verify with different RSA key.
     */
    @Test
    void testDifferentKeySameAlgorithm() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Test content"));
        
        // Generate two different RSA key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair1 = keyGen.generateKeyPair();
        KeyPair keyPair2 = keyGen.generateKeyPair();
        
        // Sign with first key
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(keyPair1.getPrivate());
        
        // Verify with second key should fail
        assertFalse(sig.checkSignatureValue(keyPair2.getPublic()),
            "Signature should not verify with different RSA key");
    }

    /**
     * Test that matching key pair works correctly.
     */
    @Test
    void testMatchingKeyPairSucceeds() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Test content"));
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(keyPair.getPrivate());
        
        // Verify with matching public key should succeed
        assertTrue(sig.checkSignatureValue(keyPair.getPublic()),
            "Signature should verify with matching key pair");
    }

}
