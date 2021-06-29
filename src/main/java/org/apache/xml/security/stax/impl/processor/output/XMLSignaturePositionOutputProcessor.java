/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.stax.XMLSecSignaturePositionImpl;

/**
 * This output processor analyzes the input events, looking for the insertion position of the signature.
 * When found, it marks the position with a custom {@link XMLSecSignaturePositionImpl} event.
 * This processor does not need to know the actual signature, and because of that, it can be early in the chain, more
 * specifically <i>before</i> the processor that computes the digest.
 * Output processors that come after this one can then look for this event to know where to insert the XML signature.
 * The (optional) {@link SignatureIndentingOutputProcessor} uses the signature position event to know where to insert
 * the additional indentation event, which has to come <i>before</i> the digest computation because it needs to be part
 * of it.
 * The {@link XMLSignatureEndingOutputProcessor} uses the signature position event to know where to insert the actual
 * signature.
 */
public class XMLSignaturePositionOutputProcessor extends AbstractOutputProcessor {

    private QName signaturePositionQName;
    private boolean signaturePositionStart;
    private int signaturePosition;
    // We start at depth -1, after we've processed the root element we'll be at depth 0.
    private int depth = -1;
    private int position = 0;
    private final List<XMLSecEvent> xmlSecEventBuffer = new ArrayList<>();
    private boolean signaturePositionFound = false;

    public XMLSignaturePositionOutputProcessor() throws XMLSecurityException {
        addBeforeProcessor(XMLSignatureOutputProcessor.class);
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        signaturePositionQName = getSecurityProperties().getSignaturePositionQName();
        signaturePositionStart = getSecurityProperties().isSignaturePositionStart();
        signaturePosition = getSecurityProperties().getSignaturePosition();
        if (signaturePosition == -1) {
            signaturePosition = 0;
        }
        signaturePositionFound = false;
    }

    @Override
    @SuppressWarnings("PMD.CollapsibleIfStatements")
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        boolean isBuffering = false;
        int eventType = xmlSecEvent.getEventType();
        boolean insertSignaturePositionAfterwards = false;
        switch (eventType) {
            case XMLStreamConstants.CHARACTERS:
            case XMLStreamConstants.SPACE:
                // Worst case, all subsequent CHARACTERS and SPACE events between two other events will be buffered.
                // These two other events are typically two START_ELEMENT events or a START_ELEMENT and END_ELEMENT
                // event.
                xmlSecEventBuffer.add(xmlSecEvent);
                isBuffering = true;
                break;
            case XMLStreamConstants.START_ELEMENT:
                if (signaturePositionQName != null) {
                    if (signaturePositionStart && xmlSecEvent.asStartElement().getName().equals(signaturePositionQName)) {
                        insertSignaturePositionAfterwards = true;
                    }
                } else if (depth == 0 && position == signaturePosition) {
                    // @see SANTUARIO-405
                    // Enhances SANTUARIO-324
                    // Output the signature at a specific position.
                    // By default, this is just after the root element
                    outputProcessorChain.createSubChain(this).processEvent(new XMLSecSignaturePositionImpl(xmlSecEvent));
                    signaturePositionFound = true;
                }
                depth++;
                break;
            case XMLStreamConstants.END_ELEMENT:
                depth--;
                if (depth == 0) {
                    position++;
                }
                if (depth < 0) {
                    if (!signaturePositionFound) {
                        // root-end-element reached
                        outputProcessorChain.createSubChain(this).processEvent(new XMLSecSignaturePositionImpl(xmlSecEvent));
                        signaturePositionFound = true;
                    }
                } else if (signaturePositionQName != null) {
                    // These if-statements can be collapsed, but I prefer to keep them separate for symmetry with the
                    // if (signaturePositionQName != null) check in the START_ELEMENT.
                    if (!signaturePositionStart && xmlSecEvent.asEndElement().getName().equals(signaturePositionQName)) {
                        insertSignaturePositionAfterwards = true;
                    }
                }
                break;
        }
        if (!isBuffering) {
            processBufferedXmlSecEvents(outputProcessorChain);
            outputProcessorChain.processEvent(xmlSecEvent);
            if (insertSignaturePositionAfterwards) {
                outputProcessorChain.createSubChain(this).processEvent(new XMLSecSignaturePositionImpl(xmlSecEvent));
                signaturePositionFound = true;
            }
        }
    }

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        processBufferedXmlSecEvents(outputProcessorChain);
        super.doFinal(outputProcessorChain);
    }

    private void processBufferedXmlSecEvents(OutputProcessorChain outputProcessorChain) throws XMLSecurityException, XMLStreamException {
        if (!xmlSecEventBuffer.isEmpty()) {
            OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
            for (XMLSecEvent bufferedXmlSecEvent : xmlSecEventBuffer) {
                subOutputProcessorChain.reset();
                subOutputProcessorChain.processEvent(bufferedXmlSecEvent);
            }
            xmlSecEventBuffer.clear();
        }
    }
}
