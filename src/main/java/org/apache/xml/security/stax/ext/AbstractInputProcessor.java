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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * An abstract InputProcessor class for reusabilty
 *
 */
public abstract class AbstractInputProcessor implements InputProcessor {

    private final XMLSecurityProperties securityProperties;

    private XMLSecurityConstants.Phase phase = XMLSecurityConstants.Phase.PROCESSING;
    private Set<Object> beforeProcessors;
    private Set<Object> afterProcessors;

    public AbstractInputProcessor(XMLSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public XMLSecurityConstants.Phase getPhase() {
        return phase;
    }

    public void setPhase(XMLSecurityConstants.Phase phase) {
        this.phase = phase;
    }

    @Override
    public void addBeforeProcessor(Object processor) {
        this.beforeProcessors = new HashSet<>();
        this.beforeProcessors.add(processor);
    }

    @Override
    public Set<Object> getBeforeProcessors() {
        if (this.beforeProcessors == null) {
            return Collections.emptySet();
        }
        return this.beforeProcessors;
    }

    @Override
    public void addAfterProcessor(Object processor) {
        this.afterProcessors = new HashSet<>();
        this.afterProcessors.add(processor);
    }

    @Override
    public Set<Object> getAfterProcessors() {
        if (this.afterProcessors == null) {
            return Collections.emptySet();
        }
        return this.afterProcessors;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        inputProcessorChain.doFinal();
    }

    public XMLSecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public Attribute getReferenceIDAttribute(XMLSecStartElement xmlSecStartElement) {
        return xmlSecStartElement.getAttributeByName(securityProperties.getIdAttributeNS());
    }
}
