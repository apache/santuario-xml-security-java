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
package org.apache.xml.security.stax.impl.processor.output;

import java.io.OutputStream;

import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.XMLSecurityEventWriter;

/**
 * Processor which outputs the XMLEvents to an outputStream
 * This Processor can be extended to allow to write to a StAX writer instead of directly to an output stream
 *
 */
public class FinalOutputProcessor extends AbstractOutputProcessor {

    private XMLEventWriter xmlEventWriter;

    public FinalOutputProcessor(OutputStream outputStream, String encoding) throws XMLSecurityException {
        super();
        setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        try {
            xmlEventWriter = new XMLSecurityEventWriter(XMLSecurityConstants.xmlOutputFactory.createXMLStreamWriter(outputStream, encoding));
        } catch (XMLStreamException e) {
            throw new XMLSecurityException(e);
        }
    }

    public FinalOutputProcessor(XMLStreamWriter xmlStreamWriter) throws XMLSecurityException {
        super();
        setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        this.xmlEventWriter = new XMLSecurityEventWriter(xmlStreamWriter);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        xmlEventWriter.add(xmlSecEvent);
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        try {
            xmlEventWriter.flush();
            xmlEventWriter.close();
        } catch (XMLStreamException e) {
            throw new XMLSecurityException(e);
        }
    }
}
