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
package org.apache.xml.security.test.dom.parser;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for XML parser security features including entity expansion attacks,
 * XXE (XML External Entity) attacks, and DOCTYPE declaration handling.
 */
class XMLParserSecurityTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public XMLParserSecurityTest() {
        // Public constructor for JUnit
    }

    /**
     * Test that external HTTP entity references are blocked.
     */
    @Test
    void testExternalHttpEntityBlocked() {
        String xxe = "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE foo [" +
            "<!ENTITY xxe SYSTEM \"http://evil.example.com/malicious.dtd\">" +
            "]>" +
            "<root>&xxe;</root>";

        ByteArrayInputStream bais = new ByteArrayInputStream(xxe.getBytes(StandardCharsets.UTF_8));

        // Should throw exception
        XMLParserException exception = assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        });
        assertNotNull(exception.getMessage());
    }

    /**
     * Test that DOCTYPE declarations can be disabled.
     */
    @Test
    void testDoctypeDisallowed() {
        String xmlWithDTD = "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE root SYSTEM \"test.dtd\">" +
            "<root/>";

        ByteArrayInputStream bais = new ByteArrayInputStream(xmlWithDTD.getBytes(StandardCharsets.UTF_8));

        // Should throw exception when DTDs are disallowed
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, true);
        });
    }

    /**
     * Test that parameter entity references are blocked.
     */
    @Test
    void testParameterEntityBlocked() {
        String xml = "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE foo [" +
            "<!ENTITY % xxe SYSTEM \"http://evil.example.com/xxe.dtd\">" +
            "%xxe;" +
            "]>" +
            "<root/>";

        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));

        // Should throw exception
        XMLParserException exception = assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        });
        assertNotNull(exception.getMessage());
    }

    /**
     * Test that circular entity references are detected.
     */
    @Test
    void testCircularEntityDetected() {
        String xml = "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE root [" +
            "<!ENTITY a \"&b;\">" +
            "<!ENTITY b \"&a;\">" +
            "]>" +
            "<root>&a;</root>";

        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));

        // Should throw exception for circular reference
        XMLParserException exception = assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        });
        assertNotNull(exception.getMessage());
    }

    /**
     * Test that valid XML without entities parses correctly.
     */
    @Test
    void testValidXmlWithoutEntities() throws Exception {
        String validXml = "<?xml version=\"1.0\"?><root><child>Content</child></root>";

        ByteArrayInputStream bais = new ByteArrayInputStream(validXml.getBytes(StandardCharsets.UTF_8));

        Document doc = XMLUtils.read(bais, true);
        assertNotNull(doc);
        assertEquals("root", doc.getDocumentElement().getNodeName());
        assertEquals("Content", doc.getDocumentElement().getFirstChild().getTextContent());
    }

    /**
     * Test that internal entities can be used when allowed.
     */
    @Test
    void testInternalEntityAllowed() throws Exception {
        String xml = "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE root [" +
            "<!ENTITY safe \"SafeContent\">" +
            "]>" +
            "<root>&safe;</root>";

        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));

        // Internal entities should work when DTDs are allowed
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        assertNotNull(doc.getDocumentElement());
    }
}
