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

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * An element selector defines <i>which</i> elements to secure, based on a given element and in the context provided by
 * the output processor chain.
 * An implementation may cooperate with a specific output processor implementation, which can be installed on the output
 * processor chain using {@link #init(OutputProcessorChain)}.
 * Implementations must be stateless, operating solely based on constructor parameters and parameters in the context
 * provided by the output processor chain.
 * If at all, parameters are typically passed from the cooperating output processor to the element selector (and further
 * on the secure part factory) in the security context on the output processor chain, which can be accessed with
 * {@link OutputProcessorChain#getSecurityContext()}.
 */
public interface ElementSelector {

    /**
     * Initializes an output processor chain with an output processor, allowing implementations to install a cooperating
     * output processor.
     * Such an output processor may populate the context with additional parameters to be used upon
     * Implementations that don't need extra parameters beyond what's provided by {@link XMLSecStartElement} don't need
     * a cooperating output processor, and can leave this method unimplemented.
     * This method will be called upon initialization of document processing.
     *
     * @param outputProcessorChain The output processor chain to initialize, never {@code null}.
     */
    default void init(OutputProcessorChain outputProcessorChain) {}

    /**
     * Selects a given element for securing, or {@code null} to indicate the document element (the document as a whole).
     * In practice, the element {@code null} is used to select secure parts that define external references to be
     * digested.
     *
     * @param element The element to select, possibly {@code null}.
     * @param outputProcessorChain The output processor chain providing security context and document context,
     *                             never {@code null}.
     * @return {@code true} to select the given element for securing, {@code false} otherwise.
     */
    boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain);
}
