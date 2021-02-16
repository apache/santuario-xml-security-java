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
 * This factory lets implementations create a secure part for a given selected element and context.
 * It defines <i>how</i> elements must be secured.
 * An example of a typical implementation:
 * <pre>
 * {@code
 * SecurePartFactory securePartFactory = (element, context) -> new SecurePart(element.getName(), SecurePart.Modifier.Content);
 * }
 * </pre>
 */
public interface SecurePartFactory {

    /**
     * Creates a secure part given a selected element and context.
     * The framework calls this method when and right after
     * {@link ElementSelector#select(XMLSecStartElement, OutputProcessorChain)} returns {@code true}.
     * The returned secure part contains the instructions <i>how</i> to secure the element.
     * It may be {@code null} to deselect the element for securing after all, overriding the selector's decision.
     *
     * @param element The selected element to create a secure part for, possibly {@code null}.
     * @return A secure part, or {@code null} to override the selection and skip this element after all.
     * @see ElementSelector#select(XMLSecStartElement, OutputProcessorChain)
     */
    SecurePart createSecurePart(XMLSecStartElement element, OutputProcessorChain outputProcessorChain);
}
