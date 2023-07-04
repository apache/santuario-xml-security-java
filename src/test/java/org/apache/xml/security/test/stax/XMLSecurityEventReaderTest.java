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

import java.util.ArrayDeque;
import java.util.Deque;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;

import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.impl.XMLSecurityEventReader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 */
public class XMLSecurityEventReaderTest {

    @Test
    public void testConformness() throws Exception {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        final XMLStreamReader xmlStreamReader =
            xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));

        final Deque<XMLSecEvent> xmlSecEventDeque = new ArrayDeque<>();
        do {
            xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));
            xmlStreamReader.next();
        }
        while (xmlStreamReader.hasNext());
        xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));//EndDocumentEvent

        final XMLSecurityEventReader xmlSecurityEventReader = new XMLSecurityEventReader(xmlSecEventDeque, 0);

        final XMLEventReader xmlEventReader =
            xmlInputFactory.createXMLEventReader(this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));
        while (xmlEventReader.hasNext()) {
            assertEquals(xmlEventReader.hasNext(), xmlSecurityEventReader.hasNext());
            final XMLEvent stdXmlEvent = xmlEventReader.nextEvent();
            final XMLEvent secXmlEvent = xmlSecurityEventReader.nextEvent();
            assertEquals(stdXmlEvent.getEventType(), secXmlEvent.getEventType());

            final XMLEvent stdPeekedXMLEvent = xmlEventReader.peek();
            final XMLEvent secPeekedXMLEvent = xmlSecurityEventReader.peek();
            if (stdPeekedXMLEvent == null) {
                assertNull(secPeekedXMLEvent);
            } else {
                assertEquals(stdPeekedXMLEvent.getEventType(), secPeekedXMLEvent.getEventType());
            }
        }

        assertFalse(xmlEventReader.hasNext());
        assertFalse(xmlSecurityEventReader.hasNext());
    }

    @Test
    public void testIndex() throws Exception {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        final XMLStreamReader xmlStreamReader =
            xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));

        final Deque<XMLSecEvent> xmlSecEventDeque = new ArrayDeque<>();
        do {
            xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));
            xmlStreamReader.next();
        }
        while (xmlStreamReader.hasNext());
        xmlSecEventDeque.push(XMLSecEventFactory.allocate(xmlStreamReader, null));//EndDocumentEvent

        final int skip = 100;

        final XMLSecurityEventReader xmlSecurityEventReader = new XMLSecurityEventReader(xmlSecEventDeque, skip);

        final XMLEventReader xmlEventReader =
            xmlInputFactory.createXMLEventReader(this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"));
        int currentIndex = 0;
        while (xmlEventReader.hasNext()) {
            final XMLEvent stdXmlEvent = xmlEventReader.nextEvent();

            if (currentIndex++ < skip) {
                continue;
            }

            final XMLEvent secXmlEvent = xmlSecurityEventReader.nextEvent();
            assertEquals(stdXmlEvent.getEventType(), secXmlEvent.getEventType());

            final XMLEvent stdPeekedXMLEvent = xmlEventReader.peek();
            final XMLEvent secPeekedXMLEvent = xmlSecurityEventReader.peek();
            if (stdPeekedXMLEvent == null) {
                assertNull(secPeekedXMLEvent);
            } else {
                assertEquals(stdPeekedXMLEvent.getEventType(), secPeekedXMLEvent.getEventType());
            }
        }

        assertFalse(xmlEventReader.hasNext());
        assertFalse(xmlSecurityEventReader.hasNext());
    }
}