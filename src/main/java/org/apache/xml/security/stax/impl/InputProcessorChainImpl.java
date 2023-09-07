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
package org.apache.xml.security.stax.impl;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.DocumentContext;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.InputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

/**
 * Implementation of a InputProcessorChain
 *
 */
public class InputProcessorChainImpl implements InputProcessorChain {

    private static final Logger LOG = System.getLogger(InputProcessorChainImpl.class.getName());

    private List<InputProcessor> inputProcessors;
    private int startPos;
    private int curPos;

    private final InboundSecurityContext inboundSecurityContext;
    private final DocumentContextImpl documentContext;

    public InputProcessorChainImpl(InboundSecurityContext inboundSecurityContext) {
        this(inboundSecurityContext, 0);
    }

    public InputProcessorChainImpl(InboundSecurityContext inboundSecurityContext, int startPos) {
        this(inboundSecurityContext, new DocumentContextImpl(), startPos, new ArrayList<>(20));
    }

    public InputProcessorChainImpl(InboundSecurityContext inboundSecurityContext, DocumentContextImpl documentContext) {
        this(inboundSecurityContext, documentContext, 0, new ArrayList<>(20));
    }

    protected InputProcessorChainImpl(InboundSecurityContext inboundSecurityContext, DocumentContextImpl documentContextImpl,
                                      int startPos, List<InputProcessor> inputProcessors) {
        this.inboundSecurityContext = inboundSecurityContext;
        this.curPos = this.startPos = startPos;
        this.documentContext = documentContextImpl;
        this.inputProcessors = inputProcessors;
    }

    @Override
    public void reset() {
        this.curPos = startPos;
    }

    @Override
    public InboundSecurityContext getSecurityContext() {
        return this.inboundSecurityContext;
    }

    @Override
    public DocumentContext getDocumentContext() {
        return this.documentContext;
    }

    @Override
    public synchronized void addProcessor(InputProcessor newInputProcessor) {
        int startPhaseIdx = 0;
        int endPhaseIdx = inputProcessors.size();

        XMLSecurityConstants.Phase targetPhase = newInputProcessor.getPhase();

        for (int i = inputProcessors.size() - 1; i >= 0; i--) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() > targetPhase.ordinal()) {
                startPhaseIdx = i + 1;
                break;
            }
        }
        for (int i = startPhaseIdx; i < inputProcessors.size(); i++) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() < targetPhase.ordinal()) {
                endPhaseIdx = i;
                break;
            }
        }

        //just look for the correct phase and append as last
        if (newInputProcessor.getBeforeProcessors().isEmpty()
                && newInputProcessor.getAfterProcessors().isEmpty()) {
            inputProcessors.add(startPhaseIdx, newInputProcessor);
        } else if (newInputProcessor.getBeforeProcessors().isEmpty()) {
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getAfterProcessors().contains(inputProcessor)
                        || newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else if (newInputProcessor.getAfterProcessors().isEmpty()) {
            int idxToInsert = endPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getBeforeProcessors().contains(inputProcessor)
                        || newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else {
            boolean found = false;
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getAfterProcessors().contains(inputProcessor)
                        || newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    found = true;
                    break;
                }
            }
            if (found) {
                inputProcessors.add(idxToInsert, newInputProcessor);
            } else {
                for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                    InputProcessor inputProcessor = inputProcessors.get(i);
                    if (newInputProcessor.getBeforeProcessors().contains(inputProcessor)
                            || newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                        idxToInsert = i + 1;
                        break;
                    }
                }
                inputProcessors.add(idxToInsert, newInputProcessor);
            }
        }
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(Level.DEBUG, "Added {0} to input chain: ", newInputProcessor.getClass().getName());
            for (InputProcessor inputProcessor : inputProcessors) {
                LOG.log(Level.DEBUG, "Name: {0} phase: {1}", inputProcessor.getClass().getName(), inputProcessor.getPhase());
            }
        }
    }

    @Override
    public synchronized void removeProcessor(InputProcessor inputProcessor) {
        LOG.log(Level.DEBUG, "Removing processor {0} from input chain", inputProcessor.getClass().getName());
        if (this.inputProcessors.indexOf(inputProcessor) <= curPos) {
            this.curPos--;
        }
        this.inputProcessors.remove(inputProcessor);
    }

    @Override
    public List<InputProcessor> getProcessors() {
        return this.inputProcessors;
    }

    @Override
    public XMLSecEvent processHeaderEvent() throws XMLStreamException, XMLSecurityException {
        return inputProcessors.get(this.curPos++).processHeaderEvent(this);
    }

    @Override
    public XMLSecEvent processEvent() throws XMLStreamException, XMLSecurityException {
        return inputProcessors.get(this.curPos++).processEvent(this);
    }

    @Override
    public void doFinal() throws XMLStreamException, XMLSecurityException {
        inputProcessors.get(this.curPos++).doFinal(this);
    }

    @Override
    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, XMLSecurityException {
        return createSubChain(inputProcessor, true);
    }

    @Override
    public InputProcessorChain createSubChain(InputProcessor inputProcessor, boolean clone) throws XMLStreamException, XMLSecurityException {
        InputProcessorChainImpl inputProcessorChain;
        try {
            final DocumentContextImpl docContext = clone ? documentContext.clone() : documentContext;
            inputProcessorChain = new InputProcessorChainImpl(inboundSecurityContext, docContext,
                    inputProcessors.indexOf(inputProcessor) + 1, new ArrayList<>(this.inputProcessors));
        } catch (CloneNotSupportedException e) {
            throw new XMLSecurityException(e);
        }
        return inputProcessorChain;
    }
}
