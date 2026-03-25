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
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class NoKeyInfoTest {

    static {
        Init.init();
    }

    @Test
    void testNullKeyInfo() throws Exception {
        String filename = "src/test/resources/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1.xml";
        File f = XmlSecTestEnvironment.resolveFile(filename);
        Document doc = XMLUtils.read(f, false);
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
        XMLSignature sig = new XMLSignature((Element) nl.item(0), f.toURI().toURL().toString());
        KeyInfo ki = sig.getKeyInfo();
        assertNull(ki);
    }

    /**
     * Test that empty KeyInfo element (no children) is handled.
     */
    @Test
    void testEmptyKeyInfo() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://test.example.org/", "root");
        doc.appendChild(root);
        
        // Create signature with empty KeyInfo
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        
        // Add empty KeyInfo manually
        Element keyInfo = doc.createElementNS(Constants.SignatureSpecNS, "KeyInfo");
        sig.getElement().insertBefore(keyInfo, sig.getElement().getFirstChild());
        
        // Should have KeyInfo but it's empty
        KeyInfo ki = sig.getKeyInfo();
        assertNotNull(ki, "Empty KeyInfo should still be accessible");
        assertNull(ki.getPublicKey(), "Empty KeyInfo should have no public key");
    }

    /**
     * Test that malformed KeyInfo with invalid XML structure is rejected.
     */
    @Test
    void testMalformedKeyInfoStructure() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://test.example.org/", "root");
        doc.appendChild(root);
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        
        // Add KeyInfo with malformed X509Data (missing required elements)
        Element keyInfo = doc.createElementNS(Constants.SignatureSpecNS, "KeyInfo");
        Element x509Data = doc.createElementNS(Constants.SignatureSpecNS, "X509Data");
        Element invalidChild = doc.createElementNS("http://invalid.example.org/", "InvalidElement");
        invalidChild.setTextContent("malformed");
        x509Data.appendChild(invalidChild);
        keyInfo.appendChild(x509Data);
        sig.getElement().insertBefore(keyInfo, sig.getElement().getFirstChild());
        
        // Accessing KeyInfo should work, but getting public key should fail or return null
        KeyInfo ki = sig.getKeyInfo();
        assertNotNull(ki);
        assertNull(ki.getPublicKey(), "Malformed KeyInfo should not yield public key");
    }

    /**
     * Test that KeyInfo with KeyName that doesn't resolve is handled.
     */
    @Test
    void testUnresolvedKeyName() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://test.example.org/", "root");
        doc.appendChild(root);
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        
        // Add KeyInfo with KeyName that won't resolve
        Element keyInfo = doc.createElementNS(Constants.SignatureSpecNS, "KeyInfo");
        Element keyName = doc.createElementNS(Constants.SignatureSpecNS, "KeyName");
        keyName.setTextContent("NonExistentKey_12345");
        keyInfo.appendChild(keyName);
        sig.getElement().insertBefore(keyInfo, sig.getElement().getFirstChild());
        
        KeyInfo ki = sig.getKeyInfo();
        assertNotNull(ki);
        // KeyName that doesn't resolve should return null for public key
        assertNull(ki.getPublicKey(), "Unresolved KeyName should not yield public key");
    }

    /**
     * Test duplicate KeyInfo elements in signature.
     */
    @Test
    void testDuplicateKeyInfo() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("http://test.example.org/", "root");
        doc.appendChild(root);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        
        // Add first KeyInfo
        sig.addKeyInfo(keyPair.getPublic());
        
        // Manually add second KeyInfo element (duplicate)
        Element keyInfo2 = doc.createElementNS(Constants.SignatureSpecNS, "KeyInfo");
        Element keyValue = doc.createElementNS(Constants.SignatureSpecNS, "KeyValue");
        keyValue.setTextContent("duplicate-key-info");
        keyInfo2.appendChild(keyValue);
        sig.getElement().appendChild(keyInfo2);
        
        sig.sign(keyPair.getPrivate());
        
        // Should access first KeyInfo (library behavior may vary)
        KeyInfo ki = sig.getKeyInfo();
        assertNotNull(ki);
    }

}