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
package org.apache.xml.security.stax.ext;

import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

/**
 * This is the Interface which every OutputProcessor must implement.
 * The order of processors is defined by:
 * <ol>
 *     <li>{@link org.apache.xml.security.stax.ext.XMLSecurityConstants.Phase} (required)</li>
 *     <li>
 *         Action order (optional): allows grouping processors per action without them accidentally being reordered
 *         incorrectly by processors of unrelated other action.
 *         It helps grouping processors where before/after processor classes doesn't cut it:
 *         signature-after-encryption is a valid use case, but also encryption-after-signature.
 *         There is no absolute ordering of signature processors versus encryption processors.
 *         That is where the action order comes in: whichever action comes first, it groups those processors together
 *         such they can't accidentally get mingled in between processors of unrelated actions.
 *         It's optional, if you set the action order to {@code -1} it will be ignored.
 *         The action order thus only defines the order between two processors if <i>both</i> these processors have an
 *         action order != {@code -1}.
 *     </li>
 *     <li>
 *         Before/after processors based on processor classes (optional): this allows ordering of processors typically
 *         belonging to a single action.</li>
 * </ol>
 */
public interface OutputProcessor {

    /**
     * setter for the XMLSecurityProperties after instantiation of the processor
     *
     * @param xmlSecurityProperties
     */
    void setXMLSecurityProperties(XMLSecurityProperties xmlSecurityProperties);

    /**
     * setter for the Action after instantiation of the processor
     *
     * @param action The action this processor belongs to, possibly {@code null} for no particular action.
     * @param actionOrder The action order of this processor, possibly {@code -1} for no particular action order.
     */
    void setAction(XMLSecurityConstants.Action action, int actionOrder);

    /**
     * @return The action to which this processor belongs, if any, else {@code null}.
     */
    XMLSecurityConstants.Action getAction();

    /**
     * @return The action order of this processor, or {@code -1}.
     */
    int getActionOrder();

    /**
     * Method will be called after setting the properties
     */
    void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException;

    /**
     * Add this processor before the given processor
     *
     * @param processor
     */
    void addBeforeProcessor(Class<? extends OutputProcessor> processor);

    /**
     * This OutputProcessor will be added before the processors in this set
     *
     * @return The set with the named OutputProcessor
     */
    Set<Class<? extends OutputProcessor>> getBeforeProcessors();

    /**
     * Add this processor after the given processor
     *
     * @param processor
     */
    void addAfterProcessor(Class<? extends OutputProcessor> processor);

    /**
     * This OutputProcessor will be added after the processors in this set
     *
     * @return The set with the named OutputProcessor
     */
    Set<Class<? extends OutputProcessor>> getAfterProcessors();

    /**
     * The Phase in which this OutputProcessor should be applied
     *
     * @return The Phase
     */
    XMLSecurityConstants.Phase getPhase();

    /**
     * Will be called from the framework for every XMLEvent
     *
     * @param xmlSecEvent          The next XMLEvent to process
     * @param outputProcessorChain
     * @throws XMLStreamException   thrown when a streaming error occurs
     * @throws XMLSecurityException thrown when a Security failure occurs
     */
    void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

    /**
     * Will be called when the whole document is processed.
     *
     * @param outputProcessorChain
     * @throws XMLStreamException   thrown when a streaming error occurs
     * @throws XMLSecurityException thrown when a Security failure occurs
     */
    void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;
}
