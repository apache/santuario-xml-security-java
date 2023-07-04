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
package org.apache.xml.security.stax.impl.resourceResolvers;

import java.io.InputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.events.Attribute;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.ext.ResourceResolverLookup;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Resolver for references in the same document.
 *
 */
public class ResolverSameDocument implements ResourceResolver, ResourceResolverLookup {

    private String id;
    private boolean firstElementOccured = false;

    public ResolverSameDocument() {
    }

    public ResolverSameDocument(String uri) {
        this.id = XMLSecurityUtils.dropReferenceMarker(uri);
    }

    public String getId() {
        return id;
    }

    @Override
    public ResourceResolverLookup canResolve(String uri, String baseURI) {
        if (uri != null && (uri.isEmpty() || uri.charAt(0) == '#')) {
            if (uri.startsWith("#xpointer")) {
                return null;
            }
            return this;
        }
        return null;
    }

    @Override
    public ResourceResolver newInstance(String uri, String baseURI) {
        return new ResolverSameDocument(uri);
    }

    @Override
    public boolean isSameDocumentReference() {
        return true;
    }

    @Override
    public boolean matches(XMLSecStartElement xmlSecStartElement) {
        return this.matches(xmlSecStartElement, XMLSecurityConstants.ATT_NULL_Id);
    }

    public boolean matches(XMLSecStartElement xmlSecStartElement, QName idAttributeNS) {
        if (id.isEmpty()) {
            if (firstElementOccured) {
                return false;
            }
            firstElementOccured = true;
            return true;
        } else {
            final Attribute attribute = xmlSecStartElement.getAttributeByName(idAttributeNS);
            if (attribute != null && attribute.getValue().equals(id)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public InputStream getInputStreamFromExternalReference() throws XMLSecurityException {
        return null;
    }
}
