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

import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.NamespaceContext;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.XMLSecurityStreamWriter;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xmlunit.matchers.CompareMatcher;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 */
public class XMLSecurityStreamWriterTest {

    @BeforeEach
    public void setUp() throws Exception {
        Init.init(this.getClass().getClassLoader().getResource("security-config.xml").toURI(),
                this.getClass());
    }

    @Test
    public void testIdentityTransformResult() throws Exception {
        StringWriter securityStringWriter = new StringWriter();
        OutboundSecurityContextImpl securityContext = new OutboundSecurityContextImpl();
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        outputProcessorChain.addProcessor(new EventWriterProcessor(securityStringWriter));
        XMLSecurityStreamWriter xmlSecurityStreamWriter = new XMLSecurityStreamWriter(outputProcessorChain);

        StringWriter stdStringWriter = new StringWriter();
        XMLStreamWriter stdXmlStreamWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(stdStringWriter);

        NamespaceContext namespaceContext = new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                if ("t3".equals(prefix)) {
                    return "test3ns";
                }
                return null;
            }

            @Override
            public String getPrefix(String namespaceURI) {
                if ("test2ns".equals(namespaceURI)) {
                    return "t2";
                } else if ("test3ns".equals(namespaceURI)) {
                    return "t3";
                }
                return null;
            }

            @Override
            public Iterator<String> getPrefixes(String namespaceURI) {
                List<String> ns = new ArrayList<>();
                ns.add(getPrefix(namespaceURI));
                return ns.iterator();
            }
        };

        xmlSecurityStreamWriter.setNamespaceContext(namespaceContext);
        stdXmlStreamWriter.setNamespaceContext(namespaceContext);
        xmlSecurityStreamWriter.writeStartDocument(StandardCharsets.UTF_8.name(), "1.0");
        stdXmlStreamWriter.writeStartDocument(StandardCharsets.UTF_8.name(), "1.0");

        xmlSecurityStreamWriter.writeDTD("<!DOCTYPE foobar [\n\t<!ENTITY x0 \"hello\">\n]>");
        stdXmlStreamWriter.writeDTD("<!DOCTYPE foobar [\n\t<!ENTITY x0 \"hello\">\n]>");

        xmlSecurityStreamWriter.writeStartElement("test1");
        stdXmlStreamWriter.writeStartElement("test1");

        xmlSecurityStreamWriter.writeDefaultNamespace("defaultns");
        stdXmlStreamWriter.writeDefaultNamespace("defaultns");

        xmlSecurityStreamWriter.writeNamespace("t2new", "test2ns");
        stdXmlStreamWriter.writeNamespace("t2new", "test2ns");

        xmlSecurityStreamWriter.writeStartElement("test2ns", "test2");
        stdXmlStreamWriter.writeStartElement("test2ns", "test2");

        xmlSecurityStreamWriter.writeNamespace("t2", "test2ns");
        stdXmlStreamWriter.writeNamespace("t2", "test2ns");

        xmlSecurityStreamWriter.writeStartElement("t3", "test3", "test3ns");
        stdXmlStreamWriter.writeStartElement("t3", "test3", "test3ns");

        xmlSecurityStreamWriter.writeNamespace("t3", "test3ns");
        stdXmlStreamWriter.writeNamespace("t3", "test3ns");

        xmlSecurityStreamWriter.writeNamespace("t4", "test4ns");
        stdXmlStreamWriter.writeNamespace("t4", "test4ns");

        xmlSecurityStreamWriter.writeStartElement("test4ns", "test4");
        stdXmlStreamWriter.writeStartElement("test4ns", "test4");

        xmlSecurityStreamWriter.writeAttribute("attr1", "attr1val");
        stdXmlStreamWriter.writeAttribute("attr1", "attr1val");

        xmlSecurityStreamWriter.writeAttribute("t2", "test2ns", "attr2", "attr2val");
        stdXmlStreamWriter.writeAttribute("t2", "test2ns", "attr2", "attr2val");

        xmlSecurityStreamWriter.writeAttribute("test3ns", "attr3", "attr3val");
        stdXmlStreamWriter.writeAttribute("test3ns", "attr3", "attr3val");

        xmlSecurityStreamWriter.writeEmptyElement("test1");
        stdXmlStreamWriter.writeEmptyElement("test1");

        xmlSecurityStreamWriter.setPrefix("t2new", "test2ns");
        stdXmlStreamWriter.setPrefix("t2new", "test2ns");

        xmlSecurityStreamWriter.writeEmptyElement("test2ns", "test2");
        stdXmlStreamWriter.writeEmptyElement("test2ns", "test2");

        xmlSecurityStreamWriter.writeEmptyElement("t2", "test2ns", "test2");
        stdXmlStreamWriter.writeEmptyElement("t2", "test2ns", "test2");

        xmlSecurityStreamWriter.writeEmptyElement("test2ns", "test2");
        stdXmlStreamWriter.writeEmptyElement("test2ns", "test2");

        xmlSecurityStreamWriter.writeEmptyElement("t3", "test3", "test3ns");
        stdXmlStreamWriter.writeEmptyElement("t3", "test3", "test3ns");

        xmlSecurityStreamWriter.writeCharacters("\n");
        stdXmlStreamWriter.writeCharacters("\n");

        xmlSecurityStreamWriter.writeCData("Hi");
        stdXmlStreamWriter.writeCData("Hi");

        xmlSecurityStreamWriter.writeComment("this is a comment");
        stdXmlStreamWriter.writeComment("this is a comment");

        xmlSecurityStreamWriter.writeCharacters("abcdcba".toCharArray(), 3, 1);
        stdXmlStreamWriter.writeCharacters("abcdcba".toCharArray(), 3, 1);

        xmlSecurityStreamWriter.writeEntityRef("x0");
        stdXmlStreamWriter.writeEntityRef("x0");

        xmlSecurityStreamWriter.writeEndElement();
        stdXmlStreamWriter.writeEndElement();

        xmlSecurityStreamWriter.writeProcessingInstruction("PI");
        stdXmlStreamWriter.writeProcessingInstruction("PI");

        xmlSecurityStreamWriter.writeProcessingInstruction("PI", "there");
        stdXmlStreamWriter.writeProcessingInstruction("PI", "there");

        assertEquals(xmlSecurityStreamWriter.getPrefix("test4ns"), stdXmlStreamWriter.getPrefix("test4ns"));

        stdXmlStreamWriter.close();
        xmlSecurityStreamWriter.close();

        MatcherAssert.assertThat(stdStringWriter.toString(), CompareMatcher.isSimilarTo(securityStringWriter.toString()));
    }

    // @see https://issues.apache.org/jira/browse/SANTUARIO-433
    @Test
    public void testNullPrefix() throws Exception {
        StringWriter securityStringWriter = new StringWriter();
        OutboundSecurityContextImpl securityContext = new OutboundSecurityContextImpl();
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        outputProcessorChain.addProcessor(new EventWriterProcessor(securityStringWriter));
        XMLSecurityStreamWriter xmlSecurityStreamWriter = new XMLSecurityStreamWriter(outputProcessorChain);

        xmlSecurityStreamWriter.writeStartElement(null, "element", "http://element.ns");
        xmlSecurityStreamWriter.writeDefaultNamespace("http://element.ns");
        xmlSecurityStreamWriter.writeStartElement("childElement");
    }

    class EventWriterProcessor implements OutputProcessor {

        private XMLEventWriter xmlEventWriter;

        EventWriterProcessor(Writer writer) throws Exception {
            XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(writer);
        }

        @Override
        public void setXMLSecurityProperties(XMLSecurityProperties xmlSecurityProperties) {
        }

        @Override
        public void setAction(XMLSecurityConstants.Action action, int actionOrder) {
        }

        @Override
        public XMLSecurityConstants.Action getAction() {
            return null;
        }

        @Override
        public int getActionOrder() {
            return -1;
        }

        @Override
        public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        }

        @Override
        public void addBeforeProcessor(Class<? extends OutputProcessor> processor) {
        }

        @Override
        public Set<Class<? extends OutputProcessor>> getBeforeProcessors() {
            return new HashSet<>();
        }

        @Override
        public void addAfterProcessor(Class<? extends OutputProcessor> processor) {
        }

        @Override
        public Set<Class<? extends OutputProcessor>> getAfterProcessors() {
            return new HashSet<>();
        }

        @Override
        public XMLSecurityConstants.Phase getPhase() {
            return XMLSecurityConstants.Phase.POSTPROCESSING;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.reset();
            xmlEventWriter.add(xmlSecEvent);
        }

        @Override
        public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        }
    }
}
