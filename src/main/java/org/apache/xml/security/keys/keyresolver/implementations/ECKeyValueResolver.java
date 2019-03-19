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

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.keyvalues.ECKeyValue;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

public class ECKeyValueResolver extends KeyResolverSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ECKeyValueResolver.class);


    /**
     * Method engineResolvePublicKey
     *
     * @param element
     * @param baseURI
     * @param storage
     * @return null if no {@link PublicKey} could be obtained
     */
    public PublicKey engineLookupAndResolvePublicKey(
        Element element, String baseURI, StorageResolver storage
    ) {
        if (element == null) {
            return null;
        }
        Element ecKeyElement = null;
        boolean isKeyValue =
            XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYVALUE);
        if (isKeyValue) {
            ecKeyElement =
                XMLUtils.selectDs11Node(element.getFirstChild(), Constants._TAG_ECKEYVALUE, 0);
        } else if (XMLUtils.elementIsInSignature11Space(element, Constants._TAG_ECKEYVALUE)) {
            // this trick is needed to allow the RetrievalMethodResolver to eat a
            // ds:ECKeyValue directly (without KeyValue)
            ecKeyElement = element;
        }

        if (ecKeyElement == null) {
            return null;
        }

        try {
            ECKeyValue ecKeyValue = new ECKeyValue(ecKeyElement, baseURI);
            return ecKeyValue.getPublicKey();
        } catch (XMLSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            //do nothing
        }

        return null;
    }


    /** {@inheritDoc} */
    public X509Certificate engineLookupResolveX509Certificate(
        Element element, String baseURI, StorageResolver storage
    ) {
        return null;
    }

    /** {@inheritDoc} */
    public javax.crypto.SecretKey engineLookupAndResolveSecretKey(
        Element element, String baseURI, StorageResolver storage
    ) {
        return null;
    }
}
