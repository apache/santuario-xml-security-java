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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;

import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecCharacters;
import org.apache.xml.security.stax.ext.stax.XMLSecComment;
import org.apache.xml.security.stax.ext.stax.XMLSecEntityDeclaration;
import org.apache.xml.security.stax.ext.stax.XMLSecEntityReference;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecProcessingInstruction;
import org.apache.xml.security.stax.impl.XMLSecurityEventReader;
import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecCharactersImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecCommentImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEntityDeclarationImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEntityReferenceImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecNamespaceImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecProcessingInstructionImpl;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 */
public class XMLSecEventTest {

    @Test
    public void testWriteCharactersEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecCharacters xmlSecCharacters = new XMLSecCharactersImpl("test", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals("test", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("<", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals("&lt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl(">", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals("&gt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("&", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals("&amp;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("<&>", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals("&lt;&amp;&gt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl(" < & > ", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        assertEquals(" &lt; &amp; &gt; ", stringWriter.toString());
    }

    @Test
    public void testWriteAttributeEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecAttribute xmlSecAttribute = new XMLSecAttributeImpl(new QName("test", "test", "test"), "test");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        assertEquals("test:test=\"test\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), "\"");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        assertEquals("test=\"&quot;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), "&");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        assertEquals("test=\"&amp;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), " & \" > < ");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        assertEquals("test=\" &amp; &quot; &gt; &lt; \"", stringWriter.toString());
    }

    @Test
    public void testWriteComment() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecComment xmlSecAttribute = new XMLSecCommentImpl(" < > & \" '", null);
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        assertEquals("<!-- < > & \" '-->", stringWriter.toString());
    }

    @Test
    public void testWriteEntityDeclaration() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecEntityDeclaration xmlSecEntityDeclaration = new XMLSecEntityDeclarationImpl("test");
        xmlSecEntityDeclaration.writeAsEncodedUnicode(stringWriter);
        assertEquals("<!ENTITY test \"\">", stringWriter.toString());
        assertEquals(XMLStreamConstants.ENTITY_DECLARATION, xmlSecEntityDeclaration.getEventType());
        assertFalse(xmlSecEntityDeclaration.isEntityReference());
    }

    @Test
    public void testWriteEntityReference() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecEntityReference xmlSecEntityReference = new XMLSecEntityReferenceImpl("test", null, null);
        xmlSecEntityReference.writeAsEncodedUnicode(stringWriter);
        assertEquals("&test;", stringWriter.toString());
    }

    @Test
    public void testWriteNamespaceEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecNamespace xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", "test");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        assertEquals("xmlns:test=\"test\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("", "\"");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        assertEquals("xmlns=\"&quot;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", "&");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        assertEquals("xmlns:test=\"&amp;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", " & \" > < ");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        assertEquals("xmlns:test=\" &amp; &quot; &gt; &lt; \"", stringWriter.toString());
    }

    @Test
    public void testWriteProcessingInstruction() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecProcessingInstruction xmlSecProcessingInstruction =
                new XMLSecProcessingInstructionImpl("test", "test", null);
        xmlSecProcessingInstruction.writeAsEncodedUnicode(stringWriter);
        assertEquals("<?test test?>", stringWriter.toString());
    }

    @Test
    public void testwWiteAsEncodedUnicode() throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream(
                        "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));

        Deque<XMLSecEvent> xmlSecEventDeque = new ArrayDeque<>();
        do {
            xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));
            xmlStreamReader.next();
        }
        while (xmlStreamReader.hasNext());
        xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));//EndDocumentEvent

        XMLSecurityEventReader xmlSecurityEventReader = new XMLSecurityEventReader(xmlSecEventDeque, 0);

        XMLEventReader xmlEventReader =
                xmlInputFactory.createXMLEventReader(this.getClass().getClassLoader().getResourceAsStream(
                        "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));

        final StringWriter stdWriter = new StringWriter();
        final StringWriter secWriter = new StringWriter();
        while (xmlEventReader.hasNext()) {
            XMLEvent stdXmlEvent = xmlEventReader.nextEvent();
            XMLEvent secXmlEvent = xmlSecurityEventReader.nextEvent();

            stdXmlEvent.writeAsEncodedUnicode(stdWriter);
            secXmlEvent.writeAsEncodedUnicode(secWriter);
        }

        assertEquals(secWriter.toString(), stdWriter.toString());
    }

    /**
     * writeAsEncodedUnicode must produce well-formed XML that reads back to the same attribute
     * and namespace values, including characters that must be escaped.
     */
    @Test
    void testWriteAsEncodedUnicodeRoundTrip() throws Exception {
        String xml = "<p:root xmlns:p=\"urn:a&amp;b&lt;c&quot;d&#9;e&#10;f\""
            + " attr=\"1&lt;2 &amp; 3&gt;2 &quot;q&quot;&#13;x\"><child/></p:root>";
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
        XMLEventReader reader = xmlInputFactory.createXMLEventReader(
            new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        StringWriter stringWriter = new StringWriter();
        while (reader.hasNext()) {
            ((XMLSecEvent) reader.nextEvent()).writeAsEncodedUnicode(stringWriter);
        }

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(
            new ByteArrayInputStream(stringWriter.toString().getBytes(StandardCharsets.UTF_8)));
        Element root = document.getDocumentElement();
        assertEquals("urn:a&b<c\"d\te\nf", root.getNamespaceURI());
        assertEquals("1<2 & 3>2 \"q\"\rx", root.getAttribute("attr"));
    }
}
