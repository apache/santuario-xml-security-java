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
package org.apache.xml.security.encryption.keys.content.derivedKey;

import org.apache.xml.security.encryption.KeyDerivationMethod;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Encryption11ElementProxy;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.StringJoiner;

/**
 * Class KeyDerivationMethodImpl is an DOM implementation of the KeyDerivationMethod
 *
 */
public class KeyDerivationMethodImpl extends Encryption11ElementProxy implements KeyDerivationMethod {
    private ConcatKDFParamsImpl concatKDFParams;

    /**
     * Constructor KeyDerivationMethodImpl creates a new KeyDerivationMethodImpl instance.
     *
     * @param doc the Document in which to create the DOM tree
     */
    public KeyDerivationMethodImpl(Document doc) {
        super(doc);
    }

    /**
     * Constructor KeyDerivationMethodImpl from existing XML element
     *
     * @param element the element to use as source
     * @param baseURI the URI of the resource where the XML instance was stored
     * @throws XMLSecurityException if a parsing error occurs
     */
    public KeyDerivationMethodImpl(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     * Sets the <code>Algorithm</code> attribute
     *
     * @param algorithm ID
     */
    public void setAlgorithm(String algorithm) {
        if (algorithm != null) {
            setLocalIdAttribute(EncryptionConstants._ATT_ALGORITHM, algorithm);
        }
    }

    @Override
    public String getAlgorithm() {
        return getLocalAttribute(EncryptionConstants._ATT_ALGORITHM);
    }

    public ConcatKDFParamsImpl getConcatKDFParams() throws XMLSecurityException {

        if (concatKDFParams != null) {
            return concatKDFParams;
        }

        Element concatKDFParamsElement =
                XMLUtils.selectXenc11Node(getElement().getFirstChild(), EncryptionConstants._TAG_CONCATKDFPARAMS, 0);

        if (concatKDFParamsElement == null) {
            return null;
        }
        concatKDFParams = new ConcatKDFParamsImpl(concatKDFParamsElement, getBaseURI());

        return concatKDFParams;
    }

    public void setConcatKDFParams(ConcatKDFParamsImpl concatKDFParams) {
        this.concatKDFParams = concatKDFParams;
        appendSelf(concatKDFParams);
        addReturnToSelf();
    }

    @Override
    public String getBaseLocalName() {
        return EncryptionConstants._TAG_KEYDERIVATIONMETHOD;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", KeyDerivationMethodImpl.class.getSimpleName() + "[", "]")
                .add("concatKDFParams=" + concatKDFParams)
                .toString();
    }
}
