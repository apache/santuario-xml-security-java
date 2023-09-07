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

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.DocumentContext;
import org.apache.xml.security.stax.ext.OutboundSecurityContext;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Implementation of a OutputProcessorChain
 *
 */
public class OutputProcessorChainImpl implements OutputProcessorChain {

    private static final Logger LOG = System.getLogger(OutputProcessorChainImpl.class.getName());

    private List<OutputProcessor> outputProcessors;
    private int startPos;
    private int curPos;
    private XMLSecStartElement parentXmlSecStartElement;

    private final OutboundSecurityContext outboundSecurityContext;
    private final DocumentContextImpl documentContext;

    public OutputProcessorChainImpl(OutboundSecurityContext outboundSecurityContext) {
        this(outboundSecurityContext, 0);
    }

    public OutputProcessorChainImpl(OutboundSecurityContext outboundSecurityContext, int startPos) {
        this(outboundSecurityContext, new DocumentContextImpl(), startPos, new ArrayList<>(20));
    }

    public OutputProcessorChainImpl(OutboundSecurityContext outboundSecurityContext, DocumentContextImpl documentContext) {
        this(outboundSecurityContext, documentContext, 0, new ArrayList<>(20));
    }

    protected OutputProcessorChainImpl(OutboundSecurityContext outboundSecurityContext, DocumentContextImpl documentContextImpl,
                                       int startPos, List<OutputProcessor> outputProcessors) {
        this.outboundSecurityContext = outboundSecurityContext;
        this.curPos = this.startPos = startPos;
        documentContext = documentContextImpl;
        this.outputProcessors = outputProcessors;
    }

    @Override
    public void reset() {
        this.curPos = startPos;
    }

    @Override
    public OutboundSecurityContext getSecurityContext() {
        return this.outboundSecurityContext;
    }

    @Override
    public DocumentContext getDocumentContext() {
        return this.documentContext;
    }

    private static int compare(OutputProcessor o1, OutputProcessor o2) {
        int d = o1.getPhase().compareTo(o2.getPhase());
        if (d != 0) {
            // If the phases differ, then we don't need to look further.
            return d;
        }
        if (o1.getActionOrder() >= 0 && o2.getActionOrder() >= 0) {
            d = o1.getActionOrder() - o2.getActionOrder();
            if (d != 0) {
                // If both action indexes are defined and they differ, we don't need to look further.
                return d;
            }
        }
        if (o1.getBeforeProcessors().contains(o2.getClass()) || o2.getAfterProcessors().contains(o1.getClass())) {
            if (o1.getAfterProcessors().contains(o2.getClass()) || o2.getBeforeProcessors().contains(o1.getClass())) {
                throw new IllegalArgumentException(String.format("Conflicting order of processors %s and %s", o1, o2));
            }
            return -1;
        }
        if (o1.getAfterProcessors().contains(o2.getClass()) || o2.getBeforeProcessors().contains(o1.getClass())) {
            if (o2.getAfterProcessors().contains(o1.getClass())) {
                throw new IllegalArgumentException(String.format("Conflicting order of processors %s and %s", o1, o2));
            }
            return 1;
        }
        return 0;
    }

    @Override
    public void addProcessor(OutputProcessor newOutputProcessor) {
        int idxToInsert = outputProcessors.size();
        // In case of no particular order, we want to preserve list order: the current new output processor is added last.
        // For that reason, we start at the tail of the list.
        boolean pointOfNoReturn = false;
        for (int idx = outputProcessors.size(); --idx >= 0;) {
            OutputProcessor outputProcessor = outputProcessors.get(idx);
            int d = compare(newOutputProcessor, outputProcessor);
            if (d < 0) {
                if (pointOfNoReturn) {
                    throw new IllegalArgumentException(String.format("Conflicting order of processors %s and %s",
                            newOutputProcessor, outputProcessor));
                }
                // Remember we're starting from the tail of the list.
                // As long as we find an output processor in the list which comes definitely AFTER the new processor,
                // we can keep on backing up the idxToInsert as well.
                idxToInsert = idx;
            } else if (d > 0) {
                // The order defined on output processors is a partial order - it means the comparison is not defined
                // for ALL output processors against ALL OTHERS, but only for SOME against SOME others.
                // For that reason, we can only stop looking if we find one that comes most definitely BEFORE the new
                // one.
                // As long as we haven't found that one, we need to keep backing up in the list.
                pointOfNoReturn = true;
            }
        }
        outputProcessors.add(idxToInsert, newOutputProcessor);
        if (idxToInsert < this.curPos) {
            this.curPos++;
        }
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(Level.DEBUG, "Added {0} to output chain: ", newOutputProcessor.getClass().getName());
            for (OutputProcessor outputProcessor : outputProcessors) {
                LOG.log(Level.DEBUG, "Name: {0} phase: {1}", outputProcessor.getClass().getName(), outputProcessor.getPhase());
            }
        }
    }

    @Override
    public void removeProcessor(OutputProcessor outputProcessor) {
        LOG.log(Level.DEBUG, "Removing processor {0} from output chain", outputProcessor.getClass().getName());
        if (this.outputProcessors.indexOf(outputProcessor) <= this.curPos) {
            this.curPos--;
        }
        this.outputProcessors.remove(outputProcessor);
    }

    @Override
    public List<OutputProcessor> getProcessors() {
        return this.outputProcessors;
    }

    private void setParentXmlSecStartElement(XMLSecStartElement xmlSecStartElement) {
        this.parentXmlSecStartElement = xmlSecStartElement;
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent) throws XMLStreamException, XMLSecurityException {
        boolean reparent = false;
        if (this.curPos == this.startPos) {
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    if (xmlSecEvent == parentXmlSecStartElement) {
                        parentXmlSecStartElement = null;
                    }
                    xmlSecEvent.setParentXMLSecStartElement(parentXmlSecStartElement);
                    parentXmlSecStartElement = xmlSecEvent.asStartElement();
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    xmlSecEvent.setParentXMLSecStartElement(parentXmlSecStartElement);
                    reparent = true;
                    break;
                default:
                    xmlSecEvent.setParentXMLSecStartElement(parentXmlSecStartElement);
                    break;
            }
        }
        outputProcessors.get(this.curPos++).processEvent(xmlSecEvent, this);
        if (reparent && parentXmlSecStartElement != null) {
            parentXmlSecStartElement = parentXmlSecStartElement.getParentXMLSecStartElement();
        }
    }

    @Override
    public void doFinal() throws XMLStreamException, XMLSecurityException {
        outputProcessors.get(this.curPos++).doFinal(this);
    }

    @Override
    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException {
        return createSubChain(outputProcessor, null);
    }

    @Override
    public OutputProcessorChain createSubChain(OutputProcessor outputProcessor, XMLSecStartElement parentXMLSecStartElement) throws XMLStreamException, XMLSecurityException {
        //we don't clone the processor-list to get updates in the sublist too!
        OutputProcessorChainImpl outputProcessorChain;
        try {
            outputProcessorChain = new OutputProcessorChainImpl(outboundSecurityContext, documentContext.clone(),
                    outputProcessors.indexOf(outputProcessor) + 1, this.outputProcessors);
        } catch (CloneNotSupportedException e) {
            throw new XMLSecurityException(e);
        }
        if (parentXMLSecStartElement != null) {
            outputProcessorChain.setParentXmlSecStartElement(parentXMLSecStartElement);
        } else {
            outputProcessorChain.setParentXmlSecStartElement(this.parentXmlSecStartElement);
        }
        return outputProcessorChain;
    }
}
