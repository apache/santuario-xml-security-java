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
package org.apache.xml.security.test.dom.encryption;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

/**
 * Test resolver - simply maps a key name to the appropriate key
 *
 */
public class BobKeyResolver extends KeyResolverSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(BobKeyResolver.class);

    private KeyName _kn;

    @Override
    protected boolean engineCanResolve(Element element, String BaseURI, StorageResolver storage) {
        if (element == null) {
            return false;
        }
        LOG.debug("Can I resolve " + element.getTagName());

        boolean isKeyName = XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYNAME);
        try {
            if (isKeyName) {
                _kn = new KeyName(element, "");
                if ("bob".equals(_kn.getKeyName())) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Do nothing
        }

        return false;
    }

    @Override
    protected PublicKey engineResolvePublicKey(
        Element element, String BaseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }

    @Override
    protected X509Certificate engineResolveX509Certificate(
        Element element, String BaseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }

    @Override
    protected SecretKey engineResolveSecretKey(
        Element element, String BaseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        try {
            DESedeKeySpec keySpec =
                new DESedeKeySpec("abcdefghijklmnopqrstuvwx".getBytes(StandardCharsets.US_ASCII));
            SecretKeyFactory keyFactory =
                SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            return key;
        }
        catch (Exception e) {
            throw new KeyResolverException("Something badly wrong in creation of bob's key");
        }
    }

    @Override
    protected PrivateKey engineResolvePrivateKey(
        Element element, String BaseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }
}

