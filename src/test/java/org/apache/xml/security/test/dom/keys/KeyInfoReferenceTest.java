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

import java.io.FileInputStream;

import org.apache.xml.security.keys.content.KeyInfoReference;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class KeyInfoReferenceTest {

    private static final String BASEDIR = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    private static final String SEP = System.getProperty("file.separator");

    private static final String ID_CONTROL = "abc123";
    private static final String URI_CONTROL = "http://www.example.org/keyinfo.xml";

    @org.junit.jupiter.api.Test
    public void testSchema() throws Exception {
        KeyInfoReference keyInfoReference = new KeyInfoReference(XMLUtils.newDocument(), URI_CONTROL);
        Element element = keyInfoReference.getElement();

        assertEquals("http://www.w3.org/2009/xmldsig11#", element.getNamespaceURI());
        assertEquals("KeyInfoReference", element.getLocalName());
    }

    @org.junit.jupiter.api.Test
    public void testURIFromElement() throws Exception {
        Document doc = loadXML("KeyInfoReference.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_KEYINFOREFERENCE);
        Element element = (Element) nl.item(0);

        KeyInfoReference keyInfoReference = new KeyInfoReference(element, "");
        assertEquals(URI_CONTROL, keyInfoReference.getURI());
        assertEquals(ID_CONTROL, keyInfoReference.getId());
    }

    @org.junit.jupiter.api.Test
    public void testURIOnConstruction() throws Exception {
        KeyInfoReference keyInfoReference = new KeyInfoReference(XMLUtils.newDocument(), URI_CONTROL);
        assertEquals(URI_CONTROL, keyInfoReference.getURI());
    }

    @org.junit.jupiter.api.Test
    public void testId() throws Exception {
        KeyInfoReference keyInfoReference = new KeyInfoReference(XMLUtils.newDocument(), URI_CONTROL);
        assertEquals("", keyInfoReference.getId());
        assertNull(keyInfoReference.getElement().getAttributeNodeNS(null, Constants._ATT_ID));

        keyInfoReference.setId(ID_CONTROL);
        assertEquals(ID_CONTROL, keyInfoReference.getId());
        assertTrue(keyInfoReference.getElement().getAttributeNodeNS(null, Constants._ATT_ID).isId());

        keyInfoReference.setId(null);
        assertEquals("", keyInfoReference.getId());
        assertNull(keyInfoReference.getElement().getAttributeNodeNS(null, Constants._ATT_ID));
    }

    // Utility methods

    private String getControlFilePath(String fileName) {
        return BASEDIR + SEP + "src" + SEP + "test" + SEP + "resources" +
            SEP + "org" + SEP + "apache" + SEP + "xml" + SEP + "security" +
            SEP + "keys" + SEP + "content" +
            SEP + fileName;
    }

    private Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(new FileInputStream(getControlFilePath(fileName)), false);
    }

}