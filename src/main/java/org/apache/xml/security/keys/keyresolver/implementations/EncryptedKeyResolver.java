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

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

/**
 * The <code>EncryptedKeyResolver</code> is not a generic resolver.  It can
 * only be for specific instantiations, as the key being unwrapped will
 * always be of a particular type and will always have been wrapped by
 * another key which needs to be recursively resolved.
 *
 * The <code>EncryptedKeyResolver</code> can therefore only be instantiated
 * with an algorithm.  It can also be instantiated with a key (the KEK) or
 * will search the static KeyResolvers to find the appropriate key.
 *
 */
public class EncryptedKeyResolver extends KeyResolverSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(RSAKeyValueResolver.class);

    private final Key kek;
    private final String algorithm;
    private final List<KeyResolverSpi> internalKeyResolvers;

    /**
     * Constructor for use when a KEK needs to be derived from a KeyInfo
     * list
     * @param algorithm
     * @param internalKeyResolvers
     */
    public EncryptedKeyResolver(String algorithm, List<KeyResolverSpi> internalKeyResolvers) {
        this(algorithm, null, internalKeyResolvers);
    }

    /**
     * Constructor used for when a KEK has been set
     * @param algorithm
     * @param kek
     * @param internalKeyResolvers
     */
    public EncryptedKeyResolver(String algorithm, Key kek, List<KeyResolverSpi> internalKeyResolvers) {
        this.algorithm = algorithm;
        this.kek = kek;
        if (internalKeyResolvers != null) {
            this.internalKeyResolvers = new ArrayList<>(internalKeyResolvers);
        } else {
            this.internalKeyResolvers = Collections.emptyList();
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean engineCanResolve(Element element, String baseURI, StorageResolver storage) {
        return XMLUtils.elementIsInEncryptionSpace(element, EncryptionConstants._TAG_ENCRYPTEDKEY);
    }


    /** {@inheritDoc} */
    @Override
    protected PublicKey engineResolvePublicKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
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
    protected SecretKey engineResolveSecretKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        if (element == null) {
            return null;
        }

        LOG.debug("EncryptedKeyResolver - Can I resolve {}", element.getTagName());

        SecretKey key = null;
        LOG.debug("Passed an Encrypted Key");
        try {
            XMLCipher cipher = XMLCipher.getInstance();
            cipher.init(XMLCipher.UNWRAP_MODE, kek);
            int size = internalKeyResolvers.size();
            for (int i = 0; i < size; i++) {
                cipher.registerInternalKeyResolver(internalKeyResolvers.get(i));
            }
            EncryptedKey ek = cipher.loadEncryptedKey(element);
            key = (SecretKey) cipher.decryptKey(ek, algorithm);
        } catch (XMLEncryptionException e) {
            LOG.debug(e.getMessage(), e);
        }

        return key;
    }

    /** {@inheritDoc} */
    @Override
    protected PrivateKey engineResolvePrivateKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        return null;
    }
}
