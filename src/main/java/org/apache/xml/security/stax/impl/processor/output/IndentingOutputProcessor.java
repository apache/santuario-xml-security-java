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

import java.util.Objects;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecCharacters;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import static java.lang.Math.max;

/**
 * This output processor applies the indentation detected by {@link IndentationDetectingOutputProcessor} to the
 * generated security elements.
 */
public class IndentingOutputProcessor extends AbstractOutputProcessor {

    private int depth = 0;
    private int previousEventType = -1;
    private IndentationContext indentationContext;

    public IndentingOutputProcessor() throws XMLSecurityException {
        addAfterProcessor(IndentationDetectingOutputProcessor.class);
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        indentationContext = outputProcessorChain.getSecurityContext().get(XMLSecurityConstants.INDENTATION_CONTEXT);
        Objects.requireNonNull("No indentation context. Did you maybe forget to initialize an IndentationDetectingOutputProcessor?");
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        int eventType = xmlSecEvent.getEventType();
        switch (eventType) {
            case XMLStreamConstants.START_ELEMENT: {
                indentationContext.popIndentation(xmlSecEvent);
                createIndentationAndOutputAsEvent(xmlSecEvent, outputProcessorChain);
                depth++;
                break;
            }
            case XMLStreamConstants.END_ELEMENT: {
                indentationContext.popIndentation(xmlSecEvent);
                depth--;
                if (previousEventType == XMLStreamConstants.END_ELEMENT) {
                    createIndentationAndOutputAsEvent(xmlSecEvent, outputProcessorChain);
                }
                break;
            }
            default:
                break;
        }
        outputProcessorChain.processEvent(xmlSecEvent);
        previousEventType = eventType;
    }

    private void createIndentationAndOutputAsEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLSecurityException, XMLStreamException {
        Indentation activeIndentation = indentationContext.getActiveIndentation(xmlSecEvent, getActionOrder());
        if (activeIndentation != null) {
            StringBuilder characters = append(null, activeIndentation.getLineSeparator(), 1);
            characters = append(characters, activeIndentation.getIncrement(), depth - activeIndentation.getOffset());
            if (characters != null) {
                // Add an indentation event before the current event.
                XMLSecCharacters xmlSecCharacters = createCharacters(characters.toString());
                xmlSecCharacters.setParentXMLSecStartElement(xmlSecEvent.getParentXMLSecStartElement());
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                subOutputProcessorChain.processEvent(xmlSecCharacters);
            }
        }
    }

    static StringBuilder append(StringBuilder builder, String toAppend, int times) {
        if (toAppend != null) {
            if (times > 0) {
                builder = builder != null ? builder.append(toAppend) : new StringBuilder(toAppend);
                for (int i = 1; i < times; i++) {
                    builder.append(toAppend);
                }
            } else if (times < 0 && builder != null) {
                builder.setLength(max(builder.length() + times * toAppend.length(), 0));
            }
        }
        return builder;
    }
}
