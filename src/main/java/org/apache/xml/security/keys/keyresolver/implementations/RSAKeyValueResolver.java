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
package org.apache.xml.security.keys.keyresolver.implementations;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.keyvalues.RSAKeyValue;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

public class RSAKeyValueResolver extends KeyResolverSpi {

    private static final Logger LOG = System.getLogger(RSAKeyValueResolver.class.getName());

    /** {@inheritDoc} */
    @Override
    protected boolean engineCanResolve(Element element, String baseURI, StorageResolver storage) {
        return XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYVALUE)
            || XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_RSAKEYVALUE);
    }

    /** {@inheritDoc} */
    @Override
    protected PublicKey engineResolvePublicKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        if (element == null) {
            return null;
        }

        LOG.log(Level.DEBUG, "Can I resolve {0}", element.getTagName());

        boolean isKeyValue = XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYVALUE);
        Element rsaKeyElement = null;
        if (isKeyValue) {
            rsaKeyElement =
                XMLUtils.selectDsNode(element.getFirstChild(), Constants._TAG_RSAKEYVALUE, 0);
        } else if (XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_RSAKEYVALUE)) {
            // this trick is needed to allow the RetrievalMethodResolver to eat a
            // ds:RSAKeyValue directly (without KeyValue)
            rsaKeyElement = element;
        }

        if (rsaKeyElement == null) {
            return null;
        }

        try {
            RSAKeyValue rsaKeyValue = new RSAKeyValue(rsaKeyElement, baseURI);

            return rsaKeyValue.getPublicKey();
        } catch (XMLSecurityException ex) {
            LOG.log(Level.DEBUG, "XMLSecurityException", ex);
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected X509Certificate engineResolveX509Certificate(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected javax.crypto.SecretKey engineResolveSecretKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected PrivateKey engineResolvePrivateKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        return null;
    }
}
