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
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Handles <code>&lt;ds:SignatureProperties&gt;</code> elements
 * This Element holds {@link SignatureProperty} properties that contain additional information items
 * concerning the generation of the signature.
 * for example, data-time stamp, serial number of cryptographic hardware.
 *
 */
public class SignatureProperties extends SignatureElementProxy {

    /**
     * Constructor SignatureProperties
     *
     * @param doc
     */
    public SignatureProperties(Document doc) {
        super(doc);

        addReturnToSelf();
    }

    /**
     * Constructs {@link SignatureProperties} from {@link Element}
     * @param element <code>SignatureProperties</code> element
     * @param baseURI the URI of the resource where the XML instance was stored
     * @throws XMLSecurityException
     */
    public SignatureProperties(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);

        Attr attr = element.getAttributeNodeNS(null, "Id");
        if (attr != null) {
            element.setIdAttributeNode(attr, true);
        }

        Element[] propertyElems =
                XMLUtils.selectDsNodes(getFirstChild(), Constants._TAG_SIGNATUREPROPERTY);
        for (Element propertyElem : propertyElems) {
            Attr propertyAttr = propertyElem.getAttributeNodeNS(null, "Id");
            if (propertyAttr != null) {
                propertyElem.setIdAttributeNode(propertyAttr, true);
            }
        }
    }

    /**
     * Return the nonnegative number of added SignatureProperty elements.
     *
     * @return the number of SignatureProperty elements
     */
    public int getLength() {
        Element[] propertyElems =
            XMLUtils.selectDsNodes(getFirstChild(), Constants._TAG_SIGNATUREPROPERTY);

        return propertyElems.length;
    }

    /**
     * Return the <i>i</i><sup>th</sup> SignatureProperty. Valid <code>i</code>
     * values are 0 to <code>{link@ getSize}-1</code>.
     *
     * @param i Index of the requested {@link SignatureProperty}
     * @return the <i>i</i><sup>th</sup> SignatureProperty
     * @throws XMLSignatureException
     */
    public SignatureProperty item(int i) throws XMLSignatureException {
        try {
            Element propertyElem =
                XMLUtils.selectDsNode(getFirstChild(), Constants._TAG_SIGNATUREPROPERTY, i);

            if (propertyElem == null) {
                return null;
            }
            return new SignatureProperty(propertyElem, this.baseURI);
        } catch (XMLSecurityException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /**
     * Sets the <code>Id</code> attribute
     *
     * @param Id the <code>Id</code> attribute
     */
    public void setId(String Id) {
        if (Id != null) {
            setLocalIdAttribute(Constants._ATT_ID, Id);
        }
    }

    /**
     * Returns the <code>Id</code> attribute
     *
     * @return the <code>Id</code> attribute
     */
    public String getId() {
        return getLocalAttribute(Constants._ATT_ID);
    }

    /**
     * Method addSignatureProperty
     *
     * @param sp
     */
    public void addSignatureProperty(SignatureProperty sp) {
        appendSelf(sp);
        addReturnToSelf();
    }

    /** {@inheritDoc} */
    @Override
    public String getBaseLocalName() {
        return Constants._TAG_SIGNATUREPROPERTIES;
    }
}
