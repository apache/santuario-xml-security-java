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
 * Tests for XML parsing edge cases and error handling including null inputs,
 * malformed XML, invalid data, and extreme values.
 */
class XMLParserEdgeCasesTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public XMLParserEdgeCasesTest() {
        // Public constructor for JUnit
    }

    /**
     * Test that null InputStream is rejected.
     */
    @Test
    void testNullInputStreamRejected() {
        assertThrows(Exception.class, () -> {
            XMLUtils.read((java.io.InputStream) null, false);
        }, "Null InputStream should be rejected");
    }

    /**
     * Test that empty input is handled gracefully.
     */
    @Test
    void testEmptyInput() {
        ByteArrayInputStream emptyStream = new ByteArrayInputStream(new byte[0]);
        
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(emptyStream, false);
        }, "Empty input should throw XMLParserException");
    }

    /**
     * Test invalid UTF-8 byte sequences are rejected.
     */
    @Test
    void testInvalidUTF8() {
        // Invalid UTF-8 sequence
        byte[] invalidUtf8 = new byte[]{(byte) 0xFF, (byte) 0xFE, (byte) 0xFD};
        ByteArrayInputStream bais = new ByteArrayInputStream(invalidUtf8);
        
        assertThrows(Exception.class, () -> {
            XMLUtils.read(bais, false);
        }, "Invalid UTF-8 should be rejected");
    }

    /**
     * Test malformed XML without closing tag.
     */
    @Test
    void testMalformedXMLUnclosedTag() {
        String malformed = "<?xml version=\"1.0\"?><root><child>text";
        ByteArrayInputStream bais = new ByteArrayInputStream(malformed.getBytes(StandardCharsets.UTF_8));
        
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        }, "Malformed XML should throw exception");
    }

    /**
     * Test XML with mismatched tags.
     */
    @Test
    void testMismatchedTags() {
        String malformed = "<?xml version=\"1.0\"?><root><child>text</wrong></root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(malformed.getBytes(StandardCharsets.UTF_8));
        
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        }, "Mismatched tags should throw exception");
    }

    /**
     * Test XML with invalid characters in element names.
     */
    @Test
    void testInvalidElementName() {
        String invalid = "<?xml version=\"1.0\"?><root><123invalid>text</123invalid></root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(invalid.getBytes(StandardCharsets.UTF_8));
        
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        }, "Invalid element names should be rejected");
    }

    /**
     * Test XML with unclosed attribute quotes.
     */
    @Test
    void testUnclosedAttributeQuote() {
        String invalid = "<?xml version=\"1.0\"?><root attr=\"value><child/></root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(invalid.getBytes(StandardCharsets.UTF_8));
        
        assertThrows(XMLParserException.class, () -> {
            XMLUtils.read(bais, false);
        }, "Unclosed attribute quotes should be rejected");
    }

    /**
     * Test deeply nested XML elements (potential DoS).
     */
    @Test
    void testDeeplyNestedElements() {
        // Create very deeply nested XML
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\"?>");
        int depth = 10000;
        for (int i = 0; i < depth; i++) {
            xml.append("<d").append(i).append('>');
        }
        xml.append("content");
        for (int i = depth - 1; i >= 0; i--) {
            xml.append("</d").append(i).append('>');
        }
        
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.toString().getBytes(StandardCharsets.UTF_8));
        
        // Should either complete or throw stack overflow protection
        assertDoesNotThrow(() -> {
            try {
                XMLUtils.read(bais, false);
            } catch (XMLParserException e) {
                // Stack overflow protection is acceptable
                assertTrue(e.getMessage().contains("depth") || 
                          e.getMessage().contains("stack") ||
                          e.getMessage().contains("nested"),
                          "Deep nesting should trigger protection");
            }
        }, "Parser should handle deep nesting gracefully");
    }

    /**
     * Test XML with very long element names.
     */
    @Test
    void testVeryLongElementName() {
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            longName.append('a');
        }
        String xml = "<?xml version=\"1.0\"?><" + longName + ">text</" + longName + ">";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        // Should either parse or reject gracefully
        assertDoesNotThrow(() -> {
            try {
                Document doc = XMLUtils.read(bais, false);
                assertNotNull(doc);
            } catch (XMLParserException e) {
                // Length limit is acceptable
                assertNotNull(e.getMessage());
            }
        });
    }

    /**
     * Test XML with very long attribute values.
     */
    @Test
    void testVeryLongAttributeValue() {
        StringBuilder longValue = new StringBuilder();
        for (int i = 0; i < 100000; i++) {
            longValue.append('x');
        }
        String xml = "<?xml version=\"1.0\"?><root attr=\"" + longValue + "\">text</root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        // Should handle or reject gracefully
        assertDoesNotThrow(() -> {
            try {
                Document doc = XMLUtils.read(bais, false);
                assertNotNull(doc);
            } catch (XMLParserException e) {
                // Length limit is acceptable
                assertNotNull(e.getMessage());
            }
        });
    }

    /**
     * Test XML with BOM (Byte Order Mark).
     */
    @Test
    void testXMLWithBOM() throws Exception {
        // UTF-8 BOM followed by XML
        byte[] bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] xml = "<?xml version=\"1.0\"?><root>test</root>".getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[bom.length + xml.length];
        System.arraycopy(bom, 0, combined, 0, bom.length);
        System.arraycopy(xml, 0, combined, bom.length, xml.length);
        
        ByteArrayInputStream bais = new ByteArrayInputStream(combined);
        
        // BOM should be handled correctly
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        assertEquals("root", doc.getDocumentElement().getNodeName());
    }

    /**
     * Test XML with CDATA section.
     */
    @Test
    void testXMLWithCDATA() throws Exception {
        String xml = "<?xml version=\"1.0\"?><root><![CDATA[<>&\"']]></root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        String content = doc.getDocumentElement().getTextContent();
        assertEquals("<>&\"'", content);
    }

    /**
     * Test XML with comments.
     */
    @Test
    void testXMLWithComments() throws Exception {
        String xml = "<?xml version=\"1.0\"?><!-- comment --><root><!-- another -->text</root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        assertEquals("text", doc.getDocumentElement().getTextContent());
    }

    /**
     * Test XML with processing instructions.
     */
    @Test
    void testXMLWithProcessingInstructions() throws Exception {
        String xml = "<?xml version=\"1.0\"?><?target data?><root>text</root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        assertEquals("root", doc.getDocumentElement().getNodeName());
    }

    /**
     * Test XML with namespaces.
     */
    @Test
    void testXMLWithNamespaces() throws Exception {
        String xml = "<?xml version=\"1.0\"?>" +
            "<root xmlns=\"http://example.com\" xmlns:ns=\"http://ns.example.com\">" +
            "<ns:child>text</ns:child></root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        assertEquals("http://example.com", doc.getDocumentElement().getNamespaceURI());
    }

    /**
     * Test that whitespace-only content is handled correctly.
     */
    @Test
    void testWhitespaceOnlyContent() throws Exception {
        String xml = "<?xml version=\"1.0\"?><root>   \n\t  </root>";
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
        
        Document doc = XMLUtils.read(bais, false);
        assertNotNull(doc);
        // Whitespace should be preserved or normalized according to XML rules
        assertNotNull(doc.getDocumentElement().getTextContent());
    }
}
