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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.stax.ext.DocumentContext;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.InputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.impl.XMLSecurityStreamReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that the end-of-document security checks of the inbound StAX reader run when the
 * application reads up to END_DOCUMENT, and not only when it calls close().
 */
class StreamReaderFinalCheckTest {

    private static final String UNSECURED =
        "<?xml version=\"1.0\"?><root><child>content</child></root>";

    private XMLInputFactory xmlInputFactory;

    @BeforeEach
    public void setUp() throws Exception {
        XMLSec.init();
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    }

    private XMLStreamReader secureReader(String xml) throws Exception {
        return secureReader(xml, new XMLSecurityProperties());
    }

    private XMLStreamReader secureReader(String xml, XMLSecurityProperties properties) throws Exception {
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(
            new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return inboundXMLSec.processInMessage(reader);
    }

    /**
     * Reading an unsecured document to END_DOCUMENT must fail without the caller calling close().
     */
    @Test
    void testUnsecuredDocumentFailsAtEndDocument() throws Exception {
        XMLStreamReader securityReader = secureReader(UNSECURED);
        XMLStreamException ex = assertThrows(XMLStreamException.class, () -> {
            while (securityReader.hasNext()) {
                securityReader.next();
            }
        });
        assertFalse(securityReader.hasNext(), "reader must report end of stream after the final check");
        // The failure must not be lost if the caller ignores it and closes the reader.
        assertThrows(XMLStreamException.class, securityReader::close);
        assertNotNull(ex.getCause());
    }

    /**
     * A caller that stops early still gets the verdict from close().
     */
    @Test
    void testUnsecuredDocumentFailsOnCloseWhenReadPartially() throws Exception {
        XMLStreamReader securityReader = secureReader(UNSECURED);
        while (securityReader.next() != XMLStreamConstants.START_ELEMENT) {
            // advance to the root element
        }
        assertThrows(XMLStreamException.class, securityReader::close);
    }

    /**
     * An unexpected RuntimeException from the final checks must not let a later close() succeed.
     */
    @Test
    void testRuntimeExceptionInFinalCheckRethrownOnClose() throws Exception {
        // A minimal chain that yields START_DOCUMENT, END_DOCUMENT and whose doFinal() fails unexpectedly
        InputProcessorChain chain = new FailingFinalCheckChain();
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSkipDocumentEvents(false);
        // closed below by assertThrows(..., securityReader::close), which PMD cannot see
        XMLSecurityStreamReader securityReader = new XMLSecurityStreamReader(chain, properties); //NOPMD

        assertThrows(IllegalStateException.class, () -> {
            while (securityReader.hasNext()) {
                securityReader.next();
            }
        });
        assertFalse(securityReader.hasNext(), "reader must report end of stream after the final check");
        XMLStreamException ex = assertThrows(XMLStreamException.class, securityReader::close);
        assertTrue(ex.getCause() instanceof IllegalStateException);
    }

    /**
     * Minimal InputProcessorChain stub: delivers START_DOCUMENT then END_DOCUMENT, and its
     * doFinal() fails with an unexpected RuntimeException. A concrete class is used rather than
     * java.lang.reflect.Proxy, because on some JDKs a proxy is generated outside the xmlsec
     * module and cannot access the non-exported XMLSecEvent type.
     */
    private static final class FailingFinalCheckChain implements InputProcessorChain {

        private final Iterator<XMLSecEvent> events = Arrays.<XMLSecEvent>asList(
            XMLSecEventFactory.createXmlSecStartDocument(null, null, null, "1.0"),
            XMLSecEventFactory.createXMLSecEndDocument()).iterator();

        @Override
        public XMLSecEvent processEvent() {
            return events.next();
        }

        @Override
        public XMLSecEvent processHeaderEvent() {
            return events.next();
        }

        @Override
        public void doFinal() {
            throw new IllegalStateException("unexpected failure in final check");
        }

        @Override
        public void reset() {
            // nothing to reset
        }

        @Override
        public void addProcessor(InputProcessor inputProcessor) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeProcessor(InputProcessor inputProcessor) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<InputProcessor> getProcessors() {
            return Collections.emptyList();
        }

        @Override
        public InboundSecurityContext getSecurityContext() {
            return null;
        }

        @Override
        public DocumentContext getDocumentContext() {
            return null;
        }

        @Override
        public InputProcessorChain createSubChain(InputProcessor inputProcessor) {
            throw new UnsupportedOperationException();
        }

        @Override
        public InputProcessorChain createSubChain(InputProcessor inputProcessor, boolean clone) {
            throw new UnsupportedOperationException();
        }
    }
}
