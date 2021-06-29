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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

/**
 * Continuously detects indentation of the input XML, buffering events if needed (up to a limit of 10).
 */
public class IndentationDetectingOutputProcessor extends AbstractOutputProcessor {

    private static final Pattern INDENTATION_PATTERN = Pattern.compile("(\\s+?)([ \t]*)");
    @SuppressWarnings("PMD")
    private static final String DO_NOT_SET = new String(); // Private sentinel value, MUST be a new object.
    private int previousEventType = -1;
    private int depth = 0;
    private String previousWhitespace = "";
    private String currentWhitespace;
    private boolean bufferingXmlSecEvents;
    private List<XMLSecEvent> xmlSecEventBuffer = new ArrayList<>(10);
    private IndentationContext indentationContext;

    public IndentationDetectingOutputProcessor() throws XMLSecurityException {
        addBeforeProcessor(SignatureIndentingOutputProcessor.class);
        addBeforeProcessor(IndentingOutputProcessor.class);
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        indentationContext = new IndentationContext();
        outputProcessorChain.getSecurityContext().put(XMLSecurityConstants.INDENTATION_CONTEXT, indentationContext);
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        int eventType = xmlSecEvent.getEventType();
        // For the purpose of detecting indentation, there are two interesting sequences of events :
        // - Whitespace CHARACTERS followed by START_ELEMENT.
        // - END_ELEMENT followed by whitespace CHARACTERS.
        // On top of that, we need to compensate for a couple of properties of the XML event reader which is feeding
        // this processor:
        // - XmlReaderToWriter collapses SPACE into CHARACTERS events.
        //   That means we can't tell the difference here and we need to detect ourselves if a CHARACTERS event is in
        //   fact ignorable whitespace or not.
        int newOffset = -1;
        String newLineSeparator = DO_NOT_SET;
        String newIncrement = DO_NOT_SET;
        switch (eventType) {
            case XMLStreamConstants.SPACE:
            case XMLStreamConstants.CHARACTERS:
                String characters = xmlSecEvent.asCharacters().getData();
                currentWhitespace = Indentation.isWhitespace(characters) ? characters : null;
                break;
            case XMLStreamConstants.START_ELEMENT:
                newOffset = depth;
                newLineSeparator = currentWhitespace;
                if (currentWhitespace != null) {
                    // START_ELEMENT preceded by whitespace.
                    // START_ELEMENT preceded by whitespace following a previous START_ELEMENT preceded by whitespace.
                    if (previousWhitespace != null && eventType == previousEventType && currentWhitespace.startsWith(previousWhitespace)) {
                        // This is the regular case of all but the first START_ELEMENT, where the code style is
                        // consistent and the previous whitespace is a prefix of the current followed by the indent.
                        newIncrement = currentWhitespace.substring(previousWhitespace.length());
                        bufferingXmlSecEvents = false;
                    } else if (eventType != previousEventType && currentWhitespace.equals(previousWhitespace)) {
                        // START_ELEMENT preceded by whitespace following a previous END_ELEMENT preceded by whitespace.
                        // => no need to change anything.
                        newOffset = -1;
                        newLineSeparator = DO_NOT_SET;
                        newIncrement = DO_NOT_SET;
                        bufferingXmlSecEvents = false;
                    } else {
                        flushXmlSecEventBufferIfNotBuffering(outputProcessorChain);
                        // This is the regular case of the first START_ELEMENT or the first START_ELEMENT after
                        // having switched code styles.
                        newOffset = 0;
                        if (depth > 0) {
                            Matcher matcher = INDENTATION_PATTERN.matcher(currentWhitespace);
                            if (matcher.matches()) {
                                newLineSeparator = matcher.group(1);
                                newIncrement = matcher.group(2);
                                newIncrement = newIncrement.substring(0, newIncrement.length() / depth);
                            }
                        } else {
                            newLineSeparator = currentWhitespace;
                        }
                        bufferingXmlSecEvents = true;
                    }
                } else if (previousWhitespace == null) {
                    // If we have two nested START_ELEMENTS without any indentation, we can conclude there is no
                    // indentation and we can stop buffering.
                    newIncrement = null;
                    bufferingXmlSecEvents = false;
                } else {
                    // First indication of code style change from indentation (previous) to no indentation (current).
                    // Start buffering and let the next event decide what to do.
                    flushXmlSecEventBufferIfNotBuffering(outputProcessorChain);
                    bufferingXmlSecEvents = true;
                }
                previousWhitespace = currentWhitespace;
                previousEventType = eventType;
                currentWhitespace = null;
                depth++;
                break;
            case XMLStreamConstants.END_ELEMENT:
                depth--;
                newOffset = depth;
                newLineSeparator = currentWhitespace;
                if (currentWhitespace != null) {
                    if (previousWhitespace != null && eventType == previousEventType && previousWhitespace.startsWith(currentWhitespace)) {
                        newIncrement = previousWhitespace.substring(currentWhitespace.length());
                        bufferingXmlSecEvents = false;
                    } else if (previousWhitespace != null && eventType != previousEventType && previousWhitespace.equals(currentWhitespace)) {
                        newOffset = -1;
                        newLineSeparator = DO_NOT_SET;
                        newIncrement = DO_NOT_SET;
                        bufferingXmlSecEvents = false;
                    } else {
                        // First indication of code style switch from no indentation to indentation.
                        // Start by flushing all current events so that they get the old code style.
                        flushXmlSecEventBufferIfNotBuffering(outputProcessorChain);
                        // Make an educated guess based on a regex pattern but start buffering and wait for the
                        // next event to take a final decision.
                        // Our educated guess will take effect only if the buffer is full (which happens if there
                        // are insufficient nested elements).
                        newOffset = 0;
                        if (depth > 0) {
                            Matcher matcher = INDENTATION_PATTERN.matcher(currentWhitespace);
                            if (matcher.matches()) {
                                newLineSeparator = matcher.group(1);
                                newIncrement = matcher.group(2);
                                newIncrement = newIncrement.substring(0, newIncrement.length() / depth);
                            }
                        } else {
                            newLineSeparator = currentWhitespace;
                        }
                        bufferingXmlSecEvents = true;
                    }
                } else if (previousWhitespace == null) {
                    // If we have two nested END_ELEMENTS without any indentation, we can conclude there is no
                    // indentation and we can stop buffering.
                    newIncrement = null;
                    bufferingXmlSecEvents = false;
                } else {
                    // First indication of code style switch from indentation to no indentation.
                    // Start buffering and wait for the next event before detecting the code style.
                    flushXmlSecEventBufferIfNotBuffering(outputProcessorChain);
                    bufferingXmlSecEvents = true;
                }
                previousWhitespace = currentWhitespace;
                previousEventType = eventType;
                currentWhitespace = null;
                break;
            default:
                currentWhitespace = null;
                break;
        }
        if (newOffset >= 0) {
            indentationContext.updateOffset(newOffset);
        }
        if (newLineSeparator != DO_NOT_SET) {
            indentationContext.updateLineSeparator(newLineSeparator);
        }
        if (newIncrement != DO_NOT_SET) {
            indentationContext.updateIncrement(newIncrement);
        }
        if (bufferingXmlSecEvents) {
            // To keep memory use under control, never buffer more than 10 events.
            if (xmlSecEventBuffer.size() > 10) {
                // We tolerate that some events might have messed up indentations, but only if the input indentations
                // are messed up to begin with, so that's an acceptable trade-off.
                flushXmlSecEventBuffer(outputProcessorChain);
            }
            xmlSecEventBuffer.add(xmlSecEvent);
        } else {
            flushXmlSecEventBuffer(outputProcessorChain);
            if (eventType == XMLStreamConstants.START_ELEMENT
                    || eventType == XMLStreamConstants.END_ELEMENT) {
                indentationContext.pushIndentation(xmlSecEvent);
            }
            outputProcessorChain.processEvent(xmlSecEvent);
        }
    }

    private void flushXmlSecEventBuffer(OutputProcessorChain outputProcessorChain) throws XMLSecurityException, XMLStreamException {
        if (!xmlSecEventBuffer.isEmpty()) {
            OutputProcessorChain subOutputProcessorChain = null;
            for (XMLSecEvent xmlSecEvent : xmlSecEventBuffer) {
                if (subOutputProcessorChain == null) {
                    subOutputProcessorChain = outputProcessorChain.createSubChain(this, xmlSecEvent.getParentXMLSecStartElement());
                }
                subOutputProcessorChain.reset();
                if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT
                        || xmlSecEvent.getEventType() == XMLStreamConstants.END_ELEMENT) {
                    indentationContext.pushIndentation(xmlSecEvent);
                }
                subOutputProcessorChain.processEvent(xmlSecEvent);
            }
            xmlSecEventBuffer.clear();
        }
    }

    private void flushXmlSecEventBufferIfNotBuffering(OutputProcessorChain outputProcessorChain) throws XMLSecurityException, XMLStreamException {
        if (!bufferingXmlSecEvents) {
            flushXmlSecEventBuffer(outputProcessorChain);
        }
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        flushXmlSecEventBuffer(outputProcessorChain);
        super.doFinal(outputProcessorChain);
    }
}
