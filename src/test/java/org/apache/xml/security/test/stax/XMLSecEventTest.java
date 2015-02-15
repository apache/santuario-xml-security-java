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

import org.apache.xml.security.stax.ext.stax.*;
import org.apache.xml.security.stax.impl.XMLSecurityEventReader;
import org.apache.xml.security.stax.impl.stax.*;
import org.codehaus.stax2.ri.evt.CharactersEventImpl;
import org.junit.Assert;
import org.junit.Test;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class XMLSecEventTest extends Assert {

    @Test
    public void testWriteCharactersEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecCharacters xmlSecCharacters = new XMLSecCharactersImpl("test", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("test", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("<", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("&lt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl(">", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("&gt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("&", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("&amp;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl("<&>", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("&lt;&amp;&gt;", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecCharacters = new XMLSecCharactersImpl(" < & > ", false, false, false, null);
        xmlSecCharacters.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals(" &lt; &amp; &gt; ", stringWriter.toString());
    }

    @Test
    public void testWriteAttributeEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecAttribute xmlSecAttribute = new XMLSecAttributeImpl(new QName("test", "test", "test"), "test");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("test:test=\"test\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), "\"");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("test=\"&quot;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), "&");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("test=\"&amp;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecAttribute = new XMLSecAttributeImpl(new QName("test"), " & \" > < ");
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("test=\" &amp; &quot; > < \"", stringWriter.toString());
    }

    @Test
    public void testWriteComment() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecComment xmlSecAttribute = new XMLSecCommentImpl(" < > & \" '", null);
        xmlSecAttribute.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("<!-- < > & \" '-->", stringWriter.toString());
    }

    @Test
    public void testWriteEntityDeclaration() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecEntityDeclaration xmlSecEntityDeclaration = new XMLSecEntityDeclarationImpl("test");
        xmlSecEntityDeclaration.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("<!ENTITY test \"\">", stringWriter.toString());
    }

    @Test
    public void testWriteEntityReference() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecEntityReference xmlSecEntityReference = new XMLSecEntityReferenceImpl("test", null, null);
        xmlSecEntityReference.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("&test;", stringWriter.toString());
    }

    @Test
    public void testWriteNamespaceEncoded() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecNamespace xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", "test");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("xmlns:test=\"test\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("", "\"");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("xmlns=\"&quot;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", "&");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("xmlns:test=\"&amp;\"", stringWriter.toString());

        stringWriter = new StringWriter();
        xmlSecNamespace = XMLSecNamespaceImpl.getInstance("test", " & \" > < ");
        xmlSecNamespace.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("xmlns:test=\" &amp; &quot; > < \"", stringWriter.toString());
    }

    @Test
    public void testWriteProcessingInstruction() throws Exception {
        StringWriter stringWriter = new StringWriter();
        XMLSecProcessingInstruction xmlSecProcessingInstruction =
                new XMLSecProcessingInstructionImpl("test", "test", null);
        xmlSecProcessingInstruction.writeAsEncodedUnicode(stringWriter);
        Assert.assertEquals("<?test test?>", stringWriter.toString());
    }

    @Test
    public void testwWiteAsEncodedUnicode() throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        XMLStreamReader xmlStreamReader =
                xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream(
                        "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));

        Deque<XMLSecEvent> xmlSecEventDeque = new ArrayDeque<XMLSecEvent>();
        do {
            xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));
            xmlStreamReader.next();
        }
        while (xmlStreamReader.hasNext());
        xmlSecEventDeque.push((XMLSecEventFactory.allocate(xmlStreamReader, null)));//EndDocumentEvent

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

        Assert.assertEquals(secWriter.toString(), stdWriter.toString());
    }
}
