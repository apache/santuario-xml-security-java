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
package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import static java.util.Objects.requireNonNull;

/**
 * This class is used by the framework to group an element selector, a secure part factory and a required number of
 * occurrences.
 * It is not intended to be used by callers of the framework, hence the package-private constructor and methods.
 */
public class SecurePartSelector {

    private final ElementSelector elementSelector;
    private final SecurePartFactory securePartFactory;
    private final int requiredNumOccurrences;

    SecurePartSelector(ElementSelector elementSelector, SecurePartFactory securePartFactory, int requiredNumOccurrences) {
        requireNonNull(elementSelector, "element selector is null");
        requireNonNull(securePartFactory, "secure part factory is null");
        this.elementSelector = elementSelector;
        this.securePartFactory = securePartFactory;
        this.requiredNumOccurrences = requiredNumOccurrences;
    }

    public int getRequiredNumOccurrences() {
        return requiredNumOccurrences;
    }

    public void init(OutputProcessorChain outputProcessorChain) {
        elementSelector.init(outputProcessorChain);
    }

    public SecurePart select(XMLSecStartElement element, OutputProcessorChain processorChain) {
        if (elementSelector.select(element, processorChain)) {
            return securePartFactory.createSecurePart(element, processorChain);
        }
        return null;
    }

    @Override
    public String toString() {
        return elementSelector + " # " + requiredNumOccurrences + " -> " + securePartFactory;
    }
}
