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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.DocumentContext;
import org.apache.xml.security.stax.ext.OutboundSecurityContext;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

class IndentationContext {

    enum Instruction {START, STOP}
    enum When {BEFORE_CURRENT, AFTER_CURRENT, AFTER_NEXT}

    private final Map<Pair<XMLSecEvent, Integer>, Pair<Instruction, When>> indentingInstructions = new LinkedHashMap<>();
    private final Map<XMLSecEvent, Indentation> indentations = new LinkedHashMap<>();
    private final Map<Integer, Indentation> activeIndentations = new LinkedHashMap<>();
    private final Map<Integer, Indentation> previousActiveIndentations = new LinkedHashMap<>();
    private Indentation indentation = Indentation.DEFAULT;
    private String lineSeparator = indentation.getLineSeparator();
    private String increment = indentation.getIncrement();
    private int offset = indentation.getOffset();

    /**
     * Phase 1: detect the indentation.
     * To be called by {@link IndentationDetectingOutputProcessor}.
     */
    void updateLineSeparator(String lineSeparator) {
        if (!Objects.equals(this.lineSeparator, lineSeparator)) {
            this.lineSeparator = lineSeparator;
            indentation = null;
        }
    }

    /**
     * Phase 1: detect the indentation.
     * To be called by {@link IndentationDetectingOutputProcessor}.
     */
    void updateIncrement(String increment) {
        if (!Objects.equals(this.increment, increment)) {
            this.increment = increment;
            indentation = null;
        }
    }

    /**
     * Phase 1: detect the indentation.
     * To be called by {@link IndentationDetectingOutputProcessor}.
     */
    void updateOffset(int offset) {
        if (this.offset != offset) {
            this.offset = offset;
            indentation = null;
        }
    }

    /**
     * Phase 4: give instruction to start or stop indenting before or after a given event.
     * To be called by the encryption/signature output processors.
     */
    void giveIndentingInstruction(XMLSecEvent xmlSecEvent, int actionOrder, Instruction instruction, When when) {
        indentingInstructions.put(new Pair(xmlSecEvent, actionOrder), new Pair(instruction, when));
    }

    /**
     * Phase 2: push the detected indentation for a given event in the queue.
     * To be called by {@link IndentationDetectingOutputProcessor}.
     */
    void pushIndentation(XMLSecEvent xmlSecEvent) {
        if (indentation == null) {
            // If any of the parameters have changed, the indentation will be null and we need to create a new one.
            indentation = new Indentation(lineSeparator, increment, offset);
        }
        indentations.put(xmlSecEvent, indentation);
    }

    /**
     * Phase 3: pop the detected indentation for a given event from the queue if any, and use it as current.
     * To be called by the encryption/signature output processors before calling
     * {@link #giveIndentingInstruction(XMLSecEvent, int, Instruction, When)}.
     */
    void popIndentation(XMLSecEvent xmlSecEvent) {
        Indentation indentation = indentations.remove(xmlSecEvent);
        if (indentation != null) {
            this.indentation = indentation;
        }
    }

    Indentation getIndentation(XMLSecEvent xmlSecEvent) {
        return indentations.get(xmlSecEvent);
    }

    /**
     * Phase 4: apply indentation if active.
     * To be called by {@link IndentingOutputProcessor}.
     */
    @SuppressWarnings("PMD.MissingBreakInSwitch")
    Indentation getActiveIndentation(XMLSecEvent xmlSecEvent, int actionOrder) {
        Pair<XMLSecEvent, Integer> key = new Pair(xmlSecEvent, actionOrder);
        Pair<Instruction, When> value = indentingInstructions.remove(key);
        Indentation activeIndentation = activeIndentations.get(actionOrder);
        Indentation previousActiveIndentation = previousActiveIndentations.remove(actionOrder);
        if (value == null) {
            if (previousActiveIndentation != null) {
                return previousActiveIndentation;
            }
            // If we were already indenting, and we're not instructed to start or stop, we continue what we were doing.
            return activeIndentation;
        }
        previousActiveIndentation = activeIndentation;
        if (value.first == Instruction.START) {
            activeIndentations.put(actionOrder, activeIndentation = indentation);
        } else if (value.first == Instruction.STOP) {
            activeIndentations.remove(actionOrder);
        }
        switch (value.second) {
            case BEFORE_CURRENT:
                // The indentation instruction is active BEFORE the CURRENT event, it thus already applies.
                return activeIndentation;
            case AFTER_NEXT:
                // The indentation instruction is active AFTER the NEXT event,
                // thus the previous indentation instruction still applies to the CURRENT event (hence the fall-through
                // to the next case), and in addition we hold on to the previous indentation instruction to apply to
                // even the NEXT event (unless it is overridden by another instruction for the NEXT event).
                previousActiveIndentations.put(actionOrder, previousActiveIndentation);
                // INTENTIONAL fall-through to next case.
            case AFTER_CURRENT:
                // The indentation instruction is active AFTER the CURRENT event,
                // thus the previous indention instruction still applies to the CURRENT event.
                return previousActiveIndentation;
        }
        // Impossible - all possible combinations of value.second have been handled above.
        throw new IllegalStateException();
    }

    static OutputProcessorChain giveIndentingInstruction(OutputProcessorChain outputProcessorChain, int actionOrder, Instruction instruction, When when) {
        // The sole purpose of this wrapper is to intercept the XMLSecEvent upon processing.
        // It is the surefire way to get hold of the event without refactoring a whole bunch of code.
        return new OutputProcessorChain() {

            @Override
            public void doFinal() throws XMLStreamException, XMLSecurityException {
                outputProcessorChain.doFinal();
            }

            @Override
            public void reset() {
                outputProcessorChain.reset();
            }

            @Override
            public OutputProcessorChain createSubChain(OutputProcessor outputProcessor, XMLSecStartElement parentXMLSecStartElement) throws XMLStreamException, XMLSecurityException {
                return outputProcessorChain.createSubChain(outputProcessor, parentXMLSecStartElement);
            }

            @Override
            public OutputProcessorChain createSubChain(OutputProcessor outputProcessor) throws XMLStreamException, XMLSecurityException {
                return outputProcessorChain.createSubChain(outputProcessor);
            }

            @Override
            public DocumentContext getDocumentContext() {
                return outputProcessorChain.getDocumentContext();
            }

            @Override
            public OutboundSecurityContext getSecurityContext() {
                return outputProcessorChain.getSecurityContext();
            }

            @Override
            public List<OutputProcessor> getProcessors() {
                return outputProcessorChain.getProcessors();
            }

            @Override
            public void removeProcessor(OutputProcessor outputProcessor) {
                outputProcessorChain.removeProcessor(outputProcessor);
            }

            @Override
            public void addProcessor(OutputProcessor outputProcessor) {
                outputProcessorChain.addProcessor(outputProcessor);
            }

            @Override
            public void processEvent(XMLSecEvent xmlSecEvent) throws XMLStreamException, XMLSecurityException {
                OutboundSecurityContext securityContext = getSecurityContext();
                IndentationContext indentationContext = securityContext.get(XMLSecurityConstants.INDENTATION_CONTEXT);
                if (indentationContext != null) {
                    indentationContext.giveIndentingInstruction(xmlSecEvent, actionOrder, instruction, when);
                }
                outputProcessorChain.processEvent(xmlSecEvent);
            }
        };
    }

    private static class Pair<K, V> {

        private final K first;

        private final V second;

        public Pair(K first, V second) {
            this.first = first;
            this.second = second;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Pair<?, ?> other = (Pair<?, ?>) o;
            return Objects.equals(first, other.first) &&
                    Objects.equals(second, other.second);
        }

        @Override
        public int hashCode() {
            return Objects.hash(first, second);
        }

        @Override
        public String toString() {
            return "[" + first + ", " + second + "]";
        }
    }
}
