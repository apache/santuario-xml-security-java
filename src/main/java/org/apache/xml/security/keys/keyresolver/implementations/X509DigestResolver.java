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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import javax.crypto.SecretKey;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Digest;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

/**
 * KeyResolverSpi implementation which resolves public keys and X.509 certificates from a
 * <code>dsig11:X509Digest</code> element.
 *
 */
public class X509DigestResolver extends KeyResolverSpi {

    private static final Logger LOG = System.getLogger(X509DigestResolver.class.getName());

    /** {@inheritDoc} */
    @Override
    protected boolean engineCanResolve(Element element, String baseURI, StorageResolver storage) {
        if (XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_X509DATA)) {
            try {
                X509Data x509Data = new X509Data(element, baseURI);
                return x509Data.containsDigest();
            } catch (XMLSecurityException e) {
                return false;
            }
        } else {
            return false;
        }
    }

    /** {@inheritDoc} */
    @Override
    protected PublicKey engineResolvePublicKey(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {

        X509Certificate cert = this.engineResolveX509Certificate(element, baseURI, storage, secureValidation);

        if (cert != null) {
            return cert.getPublicKey();
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected X509Certificate engineResolveX509Certificate(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {

        try {
            return resolveCertificate(element, baseURI, storage);
        } catch (XMLSecurityException e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected SecretKey engineResolveSecretKey(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {
        return null;
    }

    /**
     * Resolves from the storage resolver the actual certificate represented by the digest.
     *
     * @param element
     * @param baseURI
     * @param storage
     * @return the certificate represented by the digest.
     * @throws XMLSecurityException
     */
    private X509Certificate resolveCertificate(Element element, String baseURI, StorageResolver storage)
        throws XMLSecurityException {

        XMLX509Digest x509Digests[] = null;

        Element x509childNodes[] = XMLUtils.selectDs11Nodes(element.getFirstChild(), Constants._TAG_X509DIGEST);

        if (x509childNodes == null || x509childNodes.length <= 0) {
            return null;
        }

        try {
            checkStorage(storage);

            x509Digests = new XMLX509Digest[x509childNodes.length];

            for (int i = 0; i < x509childNodes.length; i++) {
                x509Digests[i] = new XMLX509Digest(x509childNodes[i], baseURI);
            }

            Iterator<Certificate> storageIterator = storage.getIterator();
            while (storageIterator.hasNext()) {
                X509Certificate cert = (X509Certificate) storageIterator.next();

                for (XMLX509Digest keyInfoDigest : x509Digests) {
                    byte[] certDigestBytes = XMLX509Digest.getDigestBytesFromCert(cert, keyInfoDigest.getAlgorithm());

                    if (Arrays.equals(keyInfoDigest.getDigestBytes(), certDigestBytes)) {
                        LOG.log(Level.DEBUG, "Found certificate with: {0}", cert.getSubjectX500Principal().getName());
                        return cert;
                    }

                }
            }

        } catch (XMLSecurityException ex) {
            throw new KeyResolverException(ex);
        }

        return null;
    }

    /**
     * Method checkSrorage
     *
     * @param storage
     * @throws KeyResolverException
     */
    private void checkStorage(StorageResolver storage) throws KeyResolverException {
        if (storage == null) {
            Object[] exArgs = { Constants._TAG_X509DIGEST };
            KeyResolverException ex = new KeyResolverException("KeyResolver.needStorageResolver", exArgs);
            LOG.log(Level.DEBUG, "", ex);
            throw ex;
        }
    }

    /** {@inheritDoc} */
    @Override
    protected PrivateKey engineResolvePrivateKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) {
        return null;
    }
}
