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
package org.apache.xml.security.stax.impl.transformer.canonicalizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 */
public abstract class Canonicalizer20010315_Excl extends CanonicalizerBase {

    public static final String INCLUSIVE_NAMESPACES_PREFIX_LIST = "inclusiveNamespacePrefixList";
    public static final String PROPAGATE_DEFAULT_NAMESPACE = "propagateDefaultNamespace";

    protected List<String> inclusiveNamespaces;
    protected boolean propagateDefaultNamespace = false;

    public Canonicalizer20010315_Excl(boolean includeComments) {
        super(includeComments);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
        this.inclusiveNamespaces = getPrefixList((List<String>)properties.get(INCLUSIVE_NAMESPACES_PREFIX_LIST));
        final Boolean propagateDfltNs = (Boolean)properties.get(PROPAGATE_DEFAULT_NAMESPACE);
        if (propagateDfltNs != null) {
            propagateDefaultNamespace = propagateDfltNs;
        }
    }

    protected static List<String> getPrefixList(List<String> inclusiveNamespaces) {

        if (inclusiveNamespaces == null || inclusiveNamespaces.isEmpty()) {
            return null;
        }

        final List<String> prefixes = new ArrayList<>(inclusiveNamespaces.size());

        for (int i = 0; i < inclusiveNamespaces.size(); i++) {
            final String s = inclusiveNamespaces.get(i).intern();
            if ("#default".equals(s)) {
                prefixes.add("");
            } else {
                prefixes.add(s);
            }
        }
        return prefixes;
    }

    @Override
    protected List<XMLSecNamespace> getCurrentUtilizedNamespaces(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {
        List<XMLSecNamespace> utilizedNamespaces = Collections.emptyList();

        final XMLSecNamespace elementNamespace = xmlSecStartElement.getElementNamespace();
        final XMLSecNamespace found = (XMLSecNamespace) outputStack.containsOnStack(elementNamespace);
        //found means the prefix matched. so check the ns further
        if (found == null || found.getNamespaceURI() == null || !found.getNamespaceURI().equals(elementNamespace.getNamespaceURI())) {
            utilizedNamespaces = new ArrayList<>(2);
            utilizedNamespaces.add(elementNamespace);
            outputStack.peek().add(elementNamespace);
        }

        final List<XMLSecAttribute> comparableAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        for (int i = 0; i < comparableAttributes.size(); i++) {
            final XMLSecAttribute comparableAttribute = comparableAttributes.get(i);
            final XMLSecNamespace attributeNamespace = comparableAttribute.getAttributeNamespace();
            if ("xml".equals(attributeNamespace.getPrefix())) {
                continue;
            }
            if (attributeNamespace.getNamespaceURI() == null || attributeNamespace.getNamespaceURI().isEmpty()) {
                continue;
            }
            final XMLSecNamespace resultNamespace = (XMLSecNamespace) outputStack.containsOnStack(attributeNamespace);
            //resultNamespace means the prefix matched. so check the ns further
            if (resultNamespace == null || resultNamespace.getNamespaceURI() == null
                    || !resultNamespace.getNamespaceURI().equals(attributeNamespace.getNamespaceURI())) {

                if (utilizedNamespaces == Collections.<XMLSecNamespace>emptyList()) {
                    utilizedNamespaces = new ArrayList<>(2);
                }
                utilizedNamespaces.add(attributeNamespace);
                outputStack.peek().add(attributeNamespace);
            }
        }

        if (this.inclusiveNamespaces != null) {
            for (int i = 0; i < inclusiveNamespaces.size(); i++) {
                final String prefix = inclusiveNamespaces.get(i);
                String ns = xmlSecStartElement.getNamespaceURI(prefix);
                if (ns == null && prefix.isEmpty()) {
                    ns = "";
                } else if (ns == null) {
                    continue;
                }

                final XMLSecNamespace comparableNamespace = XMLSecEventFactory.createXMLSecNamespace(prefix, ns);

                final XMLSecNamespace resultNamespace = (XMLSecNamespace)outputStack.containsOnStack(comparableNamespace);
                //resultNamespace means the prefix matched. so check the ns further
                if (resultNamespace == null || resultNamespace.getNamespaceURI() == null
                        || !resultNamespace.getNamespaceURI().equals(comparableNamespace.getNamespaceURI())
                        || firstCall && propagateDefaultNamespace && !utilizedNamespaces.contains(comparableNamespace)) {

                    if (utilizedNamespaces == Collections.<XMLSecNamespace>emptyList()) {
                        utilizedNamespaces = new ArrayList<>(2);
                    }
                    utilizedNamespaces.add(comparableNamespace);
                    outputStack.peek().add(comparableNamespace);
                }
            }
        }

        return utilizedNamespaces;
    }

    @Override
    protected List<XMLSecNamespace> getInitialUtilizedNamespaces(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {
        return getCurrentUtilizedNamespaces(xmlSecStartElement, outputStack);
    }

    @Override
    protected List<XMLSecAttribute> getInitialUtilizedAttributes(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {
        List<XMLSecAttribute> utilizedAttributes = Collections.emptyList();
        final List<XMLSecAttribute> comparableAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        for (int i = 0; i < comparableAttributes.size(); i++) {
            final XMLSecAttribute comparableAttribute = comparableAttributes.get(i);
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(comparableAttribute);
        }
        return utilizedAttributes;
    }
}
