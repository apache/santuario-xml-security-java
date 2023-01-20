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
package org.apache.xml.security.signature;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.SignatureElementProxy;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Handles <code>&lt;ds:SignatureProperty&gt;</code> elements
 * Additional information item concerning the generation of the signature(s) can
 * be placed in this Element
 *
 */
public class SignatureProperty extends SignatureElementProxy {

    /**
     * Constructs{@link SignatureProperty} using specified <code>target</code> attribute
     *
     * @param doc the {@link Document} in which <code>XMLsignature</code> is placed
     * @param target the <code>target</code> attribute references the <code>Signature</code>
     * element to which the property applies SignatureProperty
     */
    public SignatureProperty(Document doc, String target) {
        this(doc, target, null);
    }

    /**
     * Constructs {@link SignatureProperty} using specified <code>target</code> attribute and
     * <code>id</code> attribute
     *
     * @param doc the {@link Document} in which <code>XMLsignature</code> is placed
     * @param target the <code>target</code> attribute references the <code>Signature</code>
     *  element to which the property applies
     * @param id the <code>id</code> will be specified by {@link Reference#getURI} in validation
     */
    public SignatureProperty(Document doc, String target, String id) {
        super(doc);

        this.setTarget(target);
        this.setId(id);
    }

    /**
     * Constructs a {@link SignatureProperty} from an {@link Element}
     * @param element <code>SignatureProperty</code> element
     * @param baseURI the URI of the resource where the XML instance was stored
     * @throws XMLSecurityException
     */
    public SignatureProperty(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     *   Sets the <code>id</code> attribute
     *
     *   @param id the <code>id</code> attribute
     */
    public void setId(String id) {
        if (id != null) {
            setLocalIdAttribute(Constants._ATT_ID, id);
        }
    }

    /**
     * Returns the <code>id</code> attribute
     *
     * @return the <code>id</code> attribute
     */
    public String getId() {
        return getLocalAttribute(Constants._ATT_ID);
    }

    /**
     * Sets the <code>target</code> attribute
     *
     * @param target the <code>target</code> attribute
     */
    public void setTarget(String target) {
        if (target != null) {
            setLocalAttribute(Constants._ATT_TARGET, target);
        }
    }

    /**
     * Returns the <code>target</code> attribute
     *
     * @return the <code>target</code> attribute
     */
    public String getTarget() {
        return getLocalAttribute(Constants._ATT_TARGET);
    }

    /**
     * Method appendChild
     *
     * @param node
     * @return the node in this element.
     */
    public Node appendChild(Node node) {
        appendSelf(node);
        return node;
    }

    /** {@inheritDoc} */
    public String getBaseLocalName() {
        return Constants._TAG_SIGNATUREPROPERTY;
    }
}
