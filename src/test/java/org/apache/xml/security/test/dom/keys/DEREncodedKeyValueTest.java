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
package org.apache.xml.security.test.dom.keys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.keys.content.DEREncodedKeyValue;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.*;


class DEREncodedKeyValueTest {

    private static final String ID_CONTROL = "abc123";

    private final PublicKey rsaKeyControl;
    private final PublicKey dsaKeyControl;
    private final PublicKey ecKeyControl;
    private final PublicKey edecKeyControl;
    private final PublicKey xecKeyControl;
    private final PublicKey dhKeyControl;
    private final PublicKey rsaSsaPssKeyControl;

    public DEREncodedKeyValueTest() throws Exception {
        rsaKeyControl = loadPublicKey("rsa.key", "RSA");
        dsaKeyControl = loadPublicKey("dsa.key", "DSA");
        ecKeyControl = loadPublicKey("ec.key", "EC");
        edecKeyControl = loadPublicKey("ed25519.key", "EdDSA");
        xecKeyControl = loadPublicKey("x25519.key", "XDH");
        dhKeyControl = loadPublicKey("dh.key", "DiffieHellman");
        rsaSsaPssKeyControl = loadPublicKey("rsassa-pss.key", "RSASSA-PSS");
    }

    @AfterEach
    void cleanup() {
        if (JDKTestUtils.isAuxiliaryProviderRegistered()) {
            JDKTestUtils.unregisterAuxiliaryProvider();
        }
    }

    @Test
    void testSchema() throws Exception {
        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
        Element element = derEncodedKeyValue.getElement();

        assertEquals("http://www.w3.org/2009/xmldsig11#", element.getNamespaceURI());
        assertEquals("DEREncodedKeyValue", element.getLocalName());
    }

    @Test
    void testRSAPublicKeyFromElement() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-RSA.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(rsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(rsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testDSAPublicKeyFromElement() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-DSA.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(dsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(dsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testECPublicKeyFromElement() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-EC.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(ecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(ecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testEdECPublicKeyFromElement() throws Exception {
        Assumptions.assumeTrue(edecKeyControl != null, "Skip tests since EdEC Key is not supported");
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(edecKeyControl.getAlgorithm())) {
            JDKTestUtils.registerAuxiliaryProvider();
        }

        Document doc = loadXML("DEREncodedKeyValue-EdEC.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(edecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(edecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testXECPublicKeyFromElement() throws Exception {
        Assumptions.assumeTrue(xecKeyControl != null, "Skip tests since XEC Key is not supported");
        String algorithm = xecKeyControl.getAlgorithm();
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(algorithm)) {
            JDKTestUtils.registerAuxiliaryProvider();
        }

        Document doc = loadXML("DEREncodedKeyValue-XEC.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertNotNull(xecKeyControl.getAlgorithm(), derEncodedKeyValue.getPublicKey().getAlgorithm());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testDiffieHellmanPublicKeyFromElement() throws Exception {
        Assumptions.assumeTrue(dhKeyControl != null, "Skip tests since DH Key is not supported");

        Document doc = loadXML("DEREncodedKeyValue-DH.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertNotNull(dhKeyControl.getAlgorithm(), derEncodedKeyValue.getPublicKey().getAlgorithm());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testRsaSsaPssKeyControlPublicKeyFromElement() throws Exception {
        Assumptions.assumeTrue(rsaSsaPssKeyControl != null, "Skip tests since RSASSA-PSS Key is not supported");

        Document doc = loadXML("DEREncodedKeyValue-RSASSA-PSS.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        Element element = (Element) nl.item(0);

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertNotNull(rsaSsaPssKeyControl.getAlgorithm(), derEncodedKeyValue.getPublicKey().getAlgorithm());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    void testRSAPublicKeyFromKey() throws Exception {
        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
        assertEquals(rsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(rsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    void testDSAPublicKeyFromKey() throws Exception {
        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), dsaKeyControl);
        assertEquals(dsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(dsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    void testECPublicKeyFromKey() throws Exception {
        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), ecKeyControl);
        assertEquals(ecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(ecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    void testEdECPublicKeyFromKey() throws Exception {
        Assumptions.assumeTrue(edecKeyControl != null, "Skip tests since EdEC Key is not supported");
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(edecKeyControl.getAlgorithm())) {
            JDKTestUtils.registerAuxiliaryProvider();
        }

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), edecKeyControl);
        assertEquals(edecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(edecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    void testXECPublicKeyFromKey() throws Exception {
        Assumptions.assumeTrue(xecKeyControl != null, "Skip tests since XEC Key is not supported");
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(xecKeyControl.getAlgorithm())) {
            JDKTestUtils.registerAuxiliaryProvider();
        }

        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), xecKeyControl);
        assertArrayEquals(xecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    void testId() throws Exception {
        DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
        assertEquals("", derEncodedKeyValue.getId());
        assertNull(derEncodedKeyValue.getElement().getAttributeNodeNS(null, Constants._ATT_ID));

        derEncodedKeyValue.setId(ID_CONTROL);
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
        assertTrue(derEncodedKeyValue.getElement().getAttributeNodeNS(null, Constants._ATT_ID).isId());

        derEncodedKeyValue.setId(null);
        assertEquals("", derEncodedKeyValue.getId());
        assertNull(derEncodedKeyValue.getElement().getAttributeNodeNS(null, Constants._ATT_ID));
    }

    // Utility methods

    private Path getControlFilePath(String fileName) {
        return XmlSecTestEnvironment.resolvePath("src", "test", "resources", "org", "apache", "xml", "security", "keys",
            "content", fileName);
    }

    private Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(getControlFilePath(fileName).toFile(), false);
    }

    private PublicKey loadPublicKey(String fileName, String algorithm) throws Exception {
        String fileData = Files.readString(getControlFilePath(fileName));
        byte[] keyBytes = XMLUtils.decode(fileData);
        if (!JDKTestUtils.isAlgorithmSupported(algorithm, true)) {
            return null;
        }
        Provider provider = JDKTestUtils.isAlgorithmSupportedByJDK(algorithm) ? null : JDKTestUtils.getAuxiliaryProvider();

        KeyFactory kf = provider == null?
                KeyFactory.getInstance(algorithm) :  KeyFactory.getInstance(algorithm, provider);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }
}
