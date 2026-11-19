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
package org.apache.xml.security.extension.xades;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Abstract base class for XAdES v1.3.2 DOM element proxies.
 *
 * <p>All root elements are created in the {@link XAdESConstants#XADES_V132_NS} namespace
 * with the {@link XAdESConstants#XADES_V132_PREFIX} prefix and an explicit
 * {@code xmlns:xades132} declaration.
 *
 * <p>Child elements within an XAdES structure are created via
 * {@link #createXAdESChild(String)} (no xmlns re-declaration) or
 * {@link #createDsChild(String)} for elements in the XML Signature namespace.
 */
public abstract class XAdESElementProxy extends ElementProxy {

    protected XAdESElementProxy(Document doc) {
        super(doc);
    }

    protected XAdESElementProxy(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    @Override
    public String getBaseNamespace() {
        return XAdESConstants.XADES_V132_NS;
    }

    /**
     * Creates the root element with an explicit {@code xmlns:xades132} declaration.
     * Overrides the base class to always use the XAdES prefix rather than consulting
     * the global prefix map.
     */
    @Override
    protected Element createElementForFamilyLocal(String namespace, String localName) {
        Document doc = getDocument();
        String prefix = XAdESConstants.XADES_V132_PREFIX;
        Element e = doc.createElementNS(namespace, prefix + ":" + localName);
        e.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix, namespace);
        return e;
    }

    /**
     * Creates a child element in the XAdES v1.3.2 namespace without adding
     * a redundant {@code xmlns:xades132} declaration (inherited from the ancestor root).
     */
    protected Element createXAdESChild(String localName) {
        return getDocument().createElementNS(
                XAdESConstants.XADES_V132_NS,
                XAdESConstants.XADES_V132_PREFIX + ":" + localName);
    }

    /**
     * Creates a child element in the XML Signature namespace using the globally
     * registered {@code ds:} prefix (set by {@link XMLUtils#setDsPrefix}).
     */
    protected Element createDsChild(String localName) {
        return XMLUtils.createElementInSignatureSpace(getDocument(), localName);
    }
}
