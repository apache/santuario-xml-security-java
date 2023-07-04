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

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.FileSystems;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.keys.content.DEREncodedKeyValue;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class DEREncodedKeyValueTest {

    private static final String SEP = FileSystems.getDefault().getSeparator();

    private static final String ID_CONTROL = "abc123";

    private final PublicKey rsaKeyControl;
    private final PublicKey dsaKeyControl;
    private final PublicKey ecKeyControl;

    public DEREncodedKeyValueTest() throws Exception {
        rsaKeyControl = loadPublicKey("rsa.key", "RSA");
        dsaKeyControl = loadPublicKey("dsa.key", "DSA");
        ecKeyControl = loadPublicKey("ec.key", "EC");
    }

    @Test
    public void testSchema() throws Exception {
        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
        final Element element = derEncodedKeyValue.getElement();

        assertEquals("http://www.w3.org/2009/xmldsig11#", element.getNamespaceURI());
        assertEquals("DEREncodedKeyValue", element.getLocalName());
    }

    @Test
    public void testRSAPublicKeyFromElement() throws Exception {
        final Document doc = loadXML("DEREncodedKeyValue-RSA.xml");
        final NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        final Element element = (Element) nl.item(0);

        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(rsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(rsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    public void testDSAPublicKeyFromElement() throws Exception {
        final Document doc = loadXML("DEREncodedKeyValue-DSA.xml");
        final NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        final Element element = (Element) nl.item(0);

        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(dsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(dsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    public void testECPublicKeyFromElement() throws Exception {
        final Document doc = loadXML("DEREncodedKeyValue-EC.xml");
        final NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        final Element element = (Element) nl.item(0);

        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(element, "");
        assertEquals(ecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(ecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
        assertEquals(ID_CONTROL, derEncodedKeyValue.getId());
    }

    @Test
    public void testRSAPublicKeyFromKey() throws Exception {
        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
        assertEquals(rsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(rsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    public void testDSAPublicKeyFromKey() throws Exception {
        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), dsaKeyControl);
        assertEquals(dsaKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(dsaKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    public void testECPublicKeyFromKey() throws Exception {
        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), ecKeyControl);
        assertEquals(ecKeyControl, derEncodedKeyValue.getPublicKey());
        assertArrayEquals(ecKeyControl.getEncoded(), derEncodedKeyValue.getBytesFromTextChild());
    }

    @Test
    public void testId() throws Exception {
        final DEREncodedKeyValue derEncodedKeyValue = new DEREncodedKeyValue(TestUtils.newDocument(), rsaKeyControl);
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

    private File getControlFilePath(String fileName) {
        return XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "keys",
            "content", fileName);
    }

    private Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(new FileInputStream(getControlFilePath(fileName)), false);
    }

    private PublicKey loadPublicKey(String filePath, String algorithm) throws Exception {
        final String fileData = new String(JavaUtils.getBytesFromFile(getControlFilePath(filePath).getAbsolutePath()));
        final byte[] keyBytes = XMLUtils.decode(fileData);
        final KeyFactory kf = KeyFactory.getInstance(algorithm);
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }

}