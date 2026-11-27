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

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.xml.security.c14n.implementations.XmlAttrStack;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;

/**
 */
public class Canonicalizer11 extends CanonicalizerBase {

    private static final Logger LOG = System.getLogger(Canonicalizer11.class.getName());

    public Canonicalizer11(boolean includeComments) {
        super(includeComments);
    }

    /**
     * Returns the attributes to output on the apex element of the canonicalized subtree. Its
     * ancestors are not output, so as required by Canonical XML 1.1: xml:lang, xml:space and
     * other xml:* attributes are inherited from the ancestors; xml:id is not inherited but the
     * element's own xml:id is output; and xml:base is output as the element's own value resolved
     * against the ancestors' xml:base values ("xml:base fixup"), as the DOM implementation does.
     */
    @Override
    protected List<XMLSecAttribute> getInitialUtilizedAttributes(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {

        List<XMLSecAttribute> utilizedAttributes = Collections.emptyList();

        // the element's own attributes first, then those of its ancestors, nearest first
        List<XMLSecAttribute> visibleAttributes = new ArrayList<>();
        xmlSecStartElement.getAttributesFromCurrentScope(visibleAttributes);
        String base = null;
        XMLSecAttribute baseAttribute = null;
        for (int i = 0; i < visibleAttributes.size(); i++) {
            XMLSecAttribute comparableAttribute = visibleAttributes.get(i);
            final QName comparableAttributeName = comparableAttribute.getName();
            if (!XML.equals(comparableAttributeName.getPrefix())) {
                continue;
            }
            //xml:id attributes must be handled like other attributes: emit but dont inherit
            if ("id".equals(comparableAttributeName.getLocalPart())) {
                continue;
            }
            if ("base".equals(comparableAttributeName.getLocalPart())) {
                if (base == null) {
                    base = comparableAttribute.getValue();
                    baseAttribute = comparableAttribute;
                } else {
                    try {
                        base = XmlAttrStack.joinURI(comparableAttribute.getValue(), base);
                    } catch (URISyntaxException e) {
                        LOG.log(Level.DEBUG, e.getMessage(), e);
                    }
                }
                continue;
            }
            if (outputStack.containsOnStack(comparableAttribute) != null) {
                continue;
            }
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(comparableAttribute);
            outputStack.peek().add(comparableAttribute);
        }
        if (base != null && !base.isEmpty()) {
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(new XMLSecAttributeImpl(baseAttribute.getName(), base));
        }

        List<XMLSecAttribute> elementAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        for (int i = 0; i < elementAttributes.size(); i++) {
            XMLSecAttribute comparableAttribute = elementAttributes.get(i);
            //xml:* attributes other than xml:id are already processed in the loop above
            final QName attributeName = comparableAttribute.getName();
            if (XML.equals(attributeName.getPrefix()) && !"id".equals(attributeName.getLocalPart())) {
                continue;
            }
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(comparableAttribute);
        }

        return utilizedAttributes;
    }
}
