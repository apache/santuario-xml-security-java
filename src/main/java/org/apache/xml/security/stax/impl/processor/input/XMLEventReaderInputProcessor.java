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
package org.apache.xml.security.stax.impl.processor.input;

import java.util.NoSuchElementException;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.ConfigurationProperties;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * The XMLEventReaderInputProcessor reads requested XMLEvents from the original XMLEventReader
 * and returns them to the requester
 *
 */
public class XMLEventReaderInputProcessor extends AbstractInputProcessor {

    private static final Integer maximumAllowedXMLStructureDepth =
            Integer.valueOf(ConfigurationProperties.getProperty("MaximumAllowedXMLStructureDepth"));
    private int currentXMLStructureDepth;
    private final boolean rejectDTD;
    private final XMLStreamReader xmlStreamReader;
    private XMLSecStartElement parentXmlSecStartElement;
    private boolean EOF = false;

    public XMLEventReaderInputProcessor(XMLSecurityProperties securityProperties, XMLStreamReader xmlStreamReader) {
        super(securityProperties);
        setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        this.xmlStreamReader = xmlStreamReader;
        this.rejectDTD = !Boolean.parseBoolean(ConfigurationProperties.getProperty("AllowDTD"))
            && !isDTDSupportDisabled(xmlStreamReader);
    }

    /**
     * A reader created with XMLInputFactory.SUPPORT_DTD=false still reports a DOCTYPE as a DTD event,
     * but neither processes the internal subset nor fetches an external one, and leaves entity
     * references unexpanded. Such a document is passed through as before. Any other reader
     * (DTD support enabled, or not reported) would process the DTD while we pull events from it.
     */
    private static boolean isDTDSupportDisabled(XMLStreamReader xmlStreamReader) {
        try {
            return Boolean.FALSE.equals(xmlStreamReader.getProperty(XMLInputFactory.SUPPORT_DTD));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        return processEventInternal();
    }

    @Override
    public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        return processEventInternal();
    }

    private XMLSecEvent processEventInternal() throws XMLStreamException {
        if (rejectDTD) {
            // The XMLStreamReader is supplied by the caller and was created by a factory with
            // DTD support enabled (or doesn't say). Pulling further events would make it process
            // the DTD of the untrusted input (entity expansion, external fetches), so reject any
            // document type declaration or entity reference before reading it, as the DOM code
            // does when secure validation is enabled.
            int eventType = xmlStreamReader.getEventType();
            if (XMLStreamConstants.DTD == eventType || XMLStreamConstants.ENTITY_REFERENCE == eventType) {
                throw new XMLStreamException(new XMLSecurityException("secureProcessing.AllowDTD"));
            }
        }
        XMLSecEvent xmlSecEvent = XMLSecEventFactory.allocate(xmlStreamReader, parentXmlSecStartElement);
        if (XMLStreamConstants.START_ELEMENT == xmlSecEvent.getEventType()) {
            currentXMLStructureDepth++;
            if (currentXMLStructureDepth > maximumAllowedXMLStructureDepth) {
                XMLSecurityException xmlSecurityException = new XMLSecurityException(
                                                                                     "secureProcessing.MaximumAllowedXMLStructureDepth",
                                                                                     new Object[] {maximumAllowedXMLStructureDepth}
                    );
                throw new XMLStreamException(xmlSecurityException);
            }

            parentXmlSecStartElement = (XMLSecStartElement) xmlSecEvent;
        } else if (XMLStreamConstants.END_ELEMENT == xmlSecEvent.getEventType()) {
            currentXMLStructureDepth--;

            if (parentXmlSecStartElement != null) {
                parentXmlSecStartElement = parentXmlSecStartElement.getParentXMLSecStartElement();
            }
        }
        if (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        } else {
            if (EOF) {
                throw new NoSuchElementException();
            }
            EOF = true;
        }
        return xmlSecEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //nothing to-do. Also don't call super.doFinal() we are the last processor
    }
}
