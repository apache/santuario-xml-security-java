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

import java.util.ArrayDeque;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Processor for XML Security.
 *
 */
public class XMLSecurityInputProcessor extends AbstractInputProcessor {

    private int startIndexForProcessor;
    private InternalBufferProcessor internalBufferProcessor;
    private boolean signatureElementFound = false;
    private boolean encryptedDataElementFound = false;
    private boolean decryptOnly = false;

    public XMLSecurityInputProcessor(XMLSecurityProperties securityProperties) {
        super(securityProperties);
        setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);

        // For decrypt only mode we misuse the actions that are normally only used for outbound processing.
        // In decrypt only mode we can save a lot of memory because we don't have to buffer anything and
        // can process the document sequentially.
        // for backward compatibility:
        // If no actions are set (default behaviour) we do signature and decryption processing
        // If the only action is XMLSecurityConstants.ENCRYPT then we only do decryption and skip signature processing
        decryptOnly = securityProperties.getActions().size() == 1 &&
                securityProperties.getActions().contains(XMLSecurityConstants.ENCRYPTION);
    }

    @Override
    public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {
        return null;
    }

    @Override
    public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
            throws XMLStreamException, XMLSecurityException {

        //add the buffer processor (for signature) when this processor is called for the first time
        if (!decryptOnly && internalBufferProcessor == null) {
            internalBufferProcessor = new InternalBufferProcessor(getSecurityProperties());
            inputProcessorChain.addProcessor(internalBufferProcessor);
        }

        XMLSecEvent xmlSecEvent = inputProcessorChain.processEvent();
        if (XMLStreamConstants.START_ELEMENT == xmlSecEvent.getEventType()) {
            final XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

            if (!decryptOnly && xmlSecStartElement.getName().equals(XMLSecurityConstants.TAG_dsig_Signature)) {
                if (signatureElementFound) {
                    throw new XMLSecurityException("stax.multipleSignaturesNotSupported");
                }
                signatureElementFound = true;
                startIndexForProcessor = internalBufferProcessor.getXmlSecEventList().size() - 1;
            } else if (xmlSecStartElement.getName().equals(XMLSecurityConstants.TAG_xenc_EncryptedData)) {
                encryptedDataElementFound = true;

                XMLDecryptInputProcessor decryptInputProcessor = new XMLDecryptInputProcessor(getSecurityProperties());
                decryptInputProcessor.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
                decryptInputProcessor.addAfterProcessor(XMLEventReaderInputProcessor.class.getName());
                decryptInputProcessor.addBeforeProcessor(XMLSecurityInputProcessor.class.getName());
                decryptInputProcessor.addBeforeProcessor(XMLSecurityInputProcessor.InternalBufferProcessor.class.getName());
                inputProcessorChain.addProcessor(decryptInputProcessor);

                if (!decryptOnly) {
                    final ArrayDeque<XMLSecEvent> xmlSecEventList = internalBufferProcessor.getXmlSecEventList();
                    //remove the last event (EncryptedData)
                    xmlSecEventList.pollFirst();
                }

                // temporary processor to return the EncryptedData element for the DecryptionProcessor
                AbstractInputProcessor abstractInputProcessor = new AbstractInputProcessor(getSecurityProperties()) {
                    @Override
                    public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
                        throws XMLStreamException, XMLSecurityException {
                        return processEvent(inputProcessorChain);
                    }

                    @Override
                    public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
                        throws XMLStreamException, XMLSecurityException {
                        inputProcessorChain.removeProcessor(this);
                        return xmlSecStartElement;
                    }
                };
                abstractInputProcessor.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
                abstractInputProcessor.addBeforeProcessor(decryptInputProcessor);
                inputProcessorChain.addProcessor(abstractInputProcessor);

                //fetch the next event from the original chain
                inputProcessorChain.reset();
                xmlSecEvent = inputProcessorChain.processEvent();

                // no need to catch a possible signature element here because the decrypt processor
                // is installed before this processor and therefore the decrypted signature element will
                // flow as normal through this processor.
                // for safety we do a check if this really true
                //check if the decrypted element is a Signature element
                if (!decryptOnly && xmlSecEvent.isStartElement() &&
                    xmlSecEvent.asStartElement().getName().equals(XMLSecurityConstants.TAG_dsig_Signature) &&
                    !signatureElementFound) {
                    throw new XMLSecurityException("Internal error");
                }
            }
        } else  if (XMLStreamConstants.END_ELEMENT == xmlSecEvent.getEventType()) {
            XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
            // Handle the signature
            if (signatureElementFound
                && xmlSecEndElement.getName().equals(XMLSecurityConstants.TAG_dsig_Signature)) {
                XMLSignatureInputHandler inputHandler = new XMLSignatureInputHandler();

                final ArrayDeque<XMLSecEvent> xmlSecEventList = internalBufferProcessor.getXmlSecEventList();
                inputHandler.handle(inputProcessorChain, getSecurityProperties(),
                                    xmlSecEventList, startIndexForProcessor);

                inputProcessorChain.removeProcessor(internalBufferProcessor);

                //add the replay processor to the chain...
                InternalReplayProcessor internalReplayProcessor =
                    new InternalReplayProcessor(getSecurityProperties(), xmlSecEventList);
                internalReplayProcessor.addBeforeProcessor(XMLSignatureReferenceVerifyInputProcessor.class.getName());
                inputProcessorChain.addProcessor(internalReplayProcessor);

                //...and let the SignatureVerificationProcessor process the buffered events (enveloped signature).
                InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this, false);
                while (!xmlSecEventList.isEmpty()) {
                    subInputProcessorChain.reset();
                    subInputProcessorChain.processEvent();
                }

                // copy all processor back to main chain for finalization
                inputProcessorChain.getProcessors().clear();
                inputProcessorChain.getProcessors().addAll(subInputProcessorChain.getProcessors());
            }
        }

        return xmlSecEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (!signatureElementFound && !encryptedDataElementFound) {
            throw new XMLSecurityException("stax.unsecuredMessage");
        }
        super.doFinal(inputProcessorChain);
    }

    /**
     * Temporary Processor to buffer all events until the end of the required actions
     */
    public class InternalBufferProcessor extends AbstractInputProcessor {

        private final ArrayDeque<XMLSecEvent> xmlSecEventList = new ArrayDeque<>();

        InternalBufferProcessor(XMLSecurityProperties securityProperties) {
            super(securityProperties);
            setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
            addBeforeProcessor(XMLSecurityInputProcessor.class.getName());
        }

        public ArrayDeque<XMLSecEvent> getXmlSecEventList() {
            return xmlSecEventList;
        }

        @Override
        public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return null;
        }

        @Override
        public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            XMLSecEvent xmlSecEvent = inputProcessorChain.processEvent();
            xmlSecEventList.push(xmlSecEvent);
            return xmlSecEvent;
        }
    }

    /**
     * Temporary processor to replay the buffered events
     */
    public static class InternalReplayProcessor extends AbstractInputProcessor {

        private final ArrayDeque<XMLSecEvent> xmlSecEventList;

        public InternalReplayProcessor(XMLSecurityProperties securityProperties, ArrayDeque<XMLSecEvent> xmlSecEventList) {
            super(securityProperties);
            this.xmlSecEventList = xmlSecEventList;
        }

        @Override
        public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return null;
        }

        @Override
        public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            if (!xmlSecEventList.isEmpty()) {
                return xmlSecEventList.pollLast();
            } else {
                inputProcessorChain.removeProcessor(this);
                return inputProcessorChain.processEvent();
            }
        }
    }
}
