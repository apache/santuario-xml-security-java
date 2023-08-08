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
package org.apache.xml.security.test.stax;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 */
class OutputProcessorChainTest {

    @BeforeEach
    public void setUp() throws Exception {
        Init.init(this.getClass().getClassLoader().getResource("security-config.xml").toURI(),
                this.getClass());
    }

    static abstract class AbstractOutputProcessor implements OutputProcessor {

        private XMLSecurityConstants.Phase phase = XMLSecurityConstants.Phase.PROCESSING;
        private Set<Class<? extends OutputProcessor>> beforeProcessors = new HashSet<>();
        private Set<Class<? extends OutputProcessor>> afterProcessors = new HashSet<>();
        private XMLSecurityConstants.Action action;
        private int actionOrder = -1;

        @Override
        public void setXMLSecurityProperties(XMLSecurityProperties xmlSecurityProperties) {
        }

        @Override
        public void setAction(XMLSecurityConstants.Action action, int actionOrder) {
            this.action = action;
            this.actionOrder = actionOrder;
        }

        @Override
        public XMLSecurityConstants.Action getAction() {
            return action;
        }

        @Override
        public int getActionOrder() {
            return actionOrder;
        }

        @Override
        public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        }

        @Override
        public void addBeforeProcessor(Class<? extends OutputProcessor> processor) {
            this.beforeProcessors.add(processor);
        }

        @Override
        public Set<Class<? extends OutputProcessor>> getBeforeProcessors() {
            return beforeProcessors;
        }

        @Override
        public void addAfterProcessor(Class<? extends OutputProcessor> processor) {
            this.afterProcessors.add(processor);
        }

        @Override
        public Set<Class<? extends OutputProcessor>> getAfterProcessors() {
            return afterProcessors;
        }

        @Override
        public XMLSecurityConstants.Phase getPhase() {
            return phase;
        }

        public void setPhase(XMLSecurityConstants.Phase phase) {
            this.phase = phase;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        }

        @Override
        public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        }
    }

    @Test
    void testAddProcessorPhase1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor3);

        assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor1);
        assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor3);
    }

    @Test
    void testAddProcessorPhase2() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor6);

        assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor2);
        assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor5);
        assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor1);
        assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor3);
        assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }

    @Test
    void testAddProcessorBefore1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessor4.addBeforeProcessor(outputProcessor3.getClass());
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessor5.addBeforeProcessor(outputProcessor2.getClass());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.addBeforeProcessor(outputProcessor1.getClass());
        outputProcessorChain.addProcessor(outputProcessor6);

        assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor5);
        assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor6);
        assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor1);
        assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor4);
        assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor3);
    }

    @Test
    void testAddProcessorAfter1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessor4.setPhase(XMLSecurityConstants.Phase.POSTPROCESSING);
        outputProcessor4.addAfterProcessor(outputProcessor3.getClass());
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.setPhase(XMLSecurityConstants.Phase.PREPROCESSING);
        outputProcessor5.addAfterProcessor(outputProcessor2.getClass());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.addAfterProcessor(outputProcessor1.getClass());
        outputProcessorChain.addProcessor(outputProcessor6);

        assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor2);
        assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor5);
        assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor1);
        assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor3);
        assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }

    @Test
    void testAddProcessorBeforeAndAfter1() {
        OutputProcessorChainImpl outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());

        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor1);

        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor2);

        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor3);

        AbstractOutputProcessor outputProcessor4 = new AbstractOutputProcessor() {
        };
        outputProcessorChain.addProcessor(outputProcessor4);

        AbstractOutputProcessor outputProcessor5 = new AbstractOutputProcessor() {
        };
        outputProcessor5.addBeforeProcessor(outputProcessor4.getClass());
        outputProcessor5.addAfterProcessor(outputProcessor3.getClass());
        outputProcessorChain.addProcessor(outputProcessor5);

        AbstractOutputProcessor outputProcessor6 = new AbstractOutputProcessor() {
        };
        outputProcessor6.addBeforeProcessor(outputProcessor5.getClass());
        outputProcessor6.addAfterProcessor(outputProcessor3.getClass());
        outputProcessorChain.addProcessor(outputProcessor6);

        assertEquals(outputProcessorChain.getProcessors().get(0), outputProcessor1);
        assertEquals(outputProcessorChain.getProcessors().get(1), outputProcessor2);
        assertEquals(outputProcessorChain.getProcessors().get(2), outputProcessor3);
        assertEquals(outputProcessorChain.getProcessors().get(3), outputProcessor6);
        assertEquals(outputProcessorChain.getProcessors().get(4), outputProcessor5);
        assertEquals(outputProcessorChain.getProcessors().get(5), outputProcessor4);
    }

    @Test
    void testOrderOfProcessorsIsIndependentOfWhenTheyAreAddedToTheChain() {
        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor1.addBeforeProcessor(outputProcessor3.getClass());
        outputProcessor2.addBeforeProcessor(outputProcessor3.getClass());
        outputProcessor2.addAfterProcessor(outputProcessor1.getClass());
        outputProcessor3.addAfterProcessor(outputProcessor1.getClass());

        OutputProcessorChain outputProcessorChain1 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain1.addProcessor(outputProcessor1);
        outputProcessorChain1.addProcessor(outputProcessor2);
        outputProcessorChain1.addProcessor(outputProcessor3);

        List<OutputProcessor> processors1 = outputProcessorChain1.getProcessors();
        assertEquals(outputProcessor1, processors1.get(0));
        assertEquals(outputProcessor2, processors1.get(1));
        assertEquals(outputProcessor3, processors1.get(2));

        OutputProcessorChain outputProcessorChain2 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain2.addProcessor(outputProcessor1);
        outputProcessorChain2.addProcessor(outputProcessor3);
        outputProcessorChain2.addProcessor(outputProcessor2);

        List<OutputProcessor> processors2 = outputProcessorChain1.getProcessors();
        assertEquals(outputProcessor1, processors2.get(0));
        assertEquals(outputProcessor2, processors2.get(1));
        assertEquals(outputProcessor3, processors2.get(2));
    }

    @Test
    void testActionOrderOfProcessorsGroupsThemTogether() {
        AbstractOutputProcessor finalOutputProcessor = new AbstractOutputProcessor() {
        };
        finalOutputProcessor.setAction(null, -1);

        AbstractOutputProcessor initialEncryptionOutputProcessor = new AbstractOutputProcessor() {
        };
        initialEncryptionOutputProcessor.setAction(XMLSecurityConstants.ENCRYPTION, 0);
        initialEncryptionOutputProcessor.addBeforeProcessor(finalOutputProcessor.getClass());

        AbstractOutputProcessor myEncryptionOutputProcessor = new AbstractOutputProcessor() {
        };
        myEncryptionOutputProcessor.setAction(XMLSecurityConstants.ENCRYPTION, 0);
        myEncryptionOutputProcessor.addBeforeProcessor(finalOutputProcessor.getClass());
        myEncryptionOutputProcessor.addAfterProcessor(initialEncryptionOutputProcessor.getClass());

        AbstractOutputProcessor initialSignatureOutputProcessor = new AbstractOutputProcessor() {
        };
        initialSignatureOutputProcessor.setAction(XMLSecurityConstants.SIGNATURE, 1);
        initialSignatureOutputProcessor.addBeforeProcessor(finalOutputProcessor.getClass());

        AbstractOutputProcessor mySignatureOutputProcessor = new AbstractOutputProcessor() {
        };
        mySignatureOutputProcessor.setAction(XMLSecurityConstants.SIGNATURE, 1);
        mySignatureOutputProcessor.addBeforeProcessor(finalOutputProcessor.getClass());
        mySignatureOutputProcessor.addAfterProcessor(initialSignatureOutputProcessor.getClass());

        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain.addProcessor(finalOutputProcessor);
        outputProcessorChain.addProcessor(initialSignatureOutputProcessor);
        outputProcessorChain.addProcessor(mySignatureOutputProcessor);
        outputProcessorChain.addProcessor(myEncryptionOutputProcessor);
        outputProcessorChain.addProcessor(initialEncryptionOutputProcessor);

        List<OutputProcessor> outputProcessors = outputProcessorChain.getProcessors();
        assertEquals(initialEncryptionOutputProcessor, outputProcessors.get(0));
        assertEquals(myEncryptionOutputProcessor, outputProcessors.get(1));
        assertEquals(initialSignatureOutputProcessor, outputProcessors.get(2));
        assertEquals(mySignatureOutputProcessor, outputProcessors.get(3));
        assertEquals(finalOutputProcessor, outputProcessors.get(4));
    }

    @Test
    void testConflictingOrderOfProcessors1() {
        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessor1.setAction(null, -1);
        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setAction(null, -1);
        outputProcessor2.addBeforeProcessor(outputProcessor1.getClass());
        outputProcessor2.addAfterProcessor(outputProcessor1.getClass());

        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain.addProcessor(outputProcessor1);
        assertThrows(IllegalArgumentException.class, () -> outputProcessorChain.addProcessor(outputProcessor2));

        List<OutputProcessor> outputProcessors = outputProcessorChain.getProcessors();
        assertEquals(1, outputProcessors.size());
        assertEquals(outputProcessor1, outputProcessors.get(0));
    }

    @Test
    void testConflictingOrderOfProcessors2() {
        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessor1.setAction(null, -1);
        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setAction(null, -1);
        outputProcessor1.addBeforeProcessor(outputProcessor2.getClass());
        outputProcessor1.addAfterProcessor(outputProcessor2.getClass());

        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain.addProcessor(outputProcessor1);
        assertThrows(IllegalArgumentException.class, () -> outputProcessorChain.addProcessor(outputProcessor2));

        List<OutputProcessor> outputProcessors = outputProcessorChain.getProcessors();
        assertEquals(1, outputProcessors.size());
        assertEquals(outputProcessor1, outputProcessors.get(0));
    }

    @Test
    void testConflictingOrderOfProcessors3() {
        AbstractOutputProcessor outputProcessor1 = new AbstractOutputProcessor() {
        };
        outputProcessor1.setAction(null, -1);
        AbstractOutputProcessor outputProcessor2 = new AbstractOutputProcessor() {
        };
        outputProcessor2.setAction(null, -1);
        AbstractOutputProcessor outputProcessor3 = new AbstractOutputProcessor() {
        };
        outputProcessor3.setAction(null, -1);
        outputProcessor1.addBeforeProcessor(outputProcessor2.getClass());
        outputProcessor2.addBeforeProcessor(outputProcessor3.getClass());
        outputProcessor3.addBeforeProcessor(outputProcessor1.getClass());

        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl());
        outputProcessorChain.addProcessor(outputProcessor1);
        outputProcessorChain.addProcessor(outputProcessor2);
        assertThrows(IllegalArgumentException.class, () -> outputProcessorChain.addProcessor(outputProcessor3));

        List<OutputProcessor> outputProcessors = outputProcessorChain.getProcessors();
        assertEquals(2, outputProcessors.size());
        assertEquals(outputProcessor1, outputProcessors.get(0));
        assertEquals(outputProcessor2, outputProcessors.get(1));
    }
}