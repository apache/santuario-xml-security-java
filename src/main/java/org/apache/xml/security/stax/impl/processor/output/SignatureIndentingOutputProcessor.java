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

import java.util.Objects;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecCharacters;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecSignaturePosition;

/**
 * This processor generates the indentation event for the signature element, ahead of the signature element itself.
 * It does not need to know the signature element itself, only where it will be inserted (its signature position).
 * The reason we need to generate this indentation event early is because it needs to be included in the digest,
 * contrary to the signature element itself which needs to be excluded from the digest (for the obvious reason that the
 * signature is computed based on the digest, hence cannot be included in it).
 */
public class SignatureIndentingOutputProcessor extends AbstractOutputProcessor {

    private IndentationContext indentationContext;
    private int depth;

    public SignatureIndentingOutputProcessor() throws XMLSecurityException {
        addAfterProcessor(IndentationDetectingOutputProcessor.class);
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        super.init(outputProcessorChain);
        indentationContext = outputProcessorChain.getSecurityContext().get(XMLSecurityConstants.INDENTATION_CONTEXT);
        Objects.requireNonNull("No indentation context. Did you maybe forget to initialize an IndentationDetectingOutputProcessor?");
        depth = 0;
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        switch (xmlSecEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                depth++;
                break;
            case XMLStreamConstants.END_ELEMENT:
                depth--;
                break;
            case XMLSecurityConstants.SIGNATURE_POSITION:
                XMLSecSignaturePosition signaturePosition = (XMLSecSignaturePosition) xmlSecEvent;
                XMLSecEvent context = signaturePosition.getContext();
                Indentation indentation = indentationContext.getIndentation(context);
                // IndentationDetectingOutputProcessor MUST have put an indentation in the context for this event,
                // so if the indentation is null here it's a bug and this will rightfully throw NPE.
                StringBuilder characters = IndentingOutputProcessor.append(null, indentation.getLineSeparator(), 1);
                characters = IndentingOutputProcessor.append(characters, indentation.getIncrement(), depth - indentation.getOffset());
                if (characters != null) {
                    // Add an indentation event before the current event.
                    XMLSecCharacters xmlSecCharacters = createCharacters(characters.toString());
                    xmlSecCharacters.setParentXMLSecStartElement(context.getParentXMLSecStartElement());
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    subOutputProcessorChain.processEvent(xmlSecCharacters);
                }
                break;
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }
}
