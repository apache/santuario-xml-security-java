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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.SecretKey;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.apache.xml.security.keys.content.x509.XMLX509SubjectName;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

/**
 * Resolves a PrivateKey within a KeyStore based on the KeyInfo hints.
 * For X509Data hints, the certificate associated with the private key entry must match.
 * For a KeyName hint, the KeyName must match the alias of a PrivateKey entry within the KeyStore.
 */
public class PrivateKeyResolver extends KeyResolverSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PrivateKeyResolver.class);

    private final KeyStore keyStore;
    private final char[] password;

    /**
     * Constructor.
     */
    public PrivateKeyResolver(KeyStore keyStore, char[] password) {
        this.keyStore = keyStore;
        this.password = password;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean engineCanResolve(Element element, String baseURI, StorageResolver storage) {
        return XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_X509DATA)
            || XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYNAME);
    }

    /** {@inheritDoc} */
    @Override
    protected PublicKey engineResolvePublicKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected X509Certificate engineResolveX509Certificate(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected SecretKey engineResolveSecretKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKey engineResolvePrivateKey(
        Element element, String baseURI, StorageResolver storage, boolean secureValidation
    ) throws KeyResolverException {

        if (XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_X509DATA)) {
            final PrivateKey privKey = resolveX509Data(element, baseURI);
            if (privKey != null) {
                return privKey;
            }
        } else if (XMLUtils.elementIsInSignatureSpace(element, Constants._TAG_KEYNAME)) {
            LOG.debug("Can I resolve KeyName?");
            final String keyName = element.getFirstChild().getNodeValue();

            try {
                final Key key = keyStore.getKey(keyName, password);
                if (key instanceof PrivateKey) {
                    return (PrivateKey) key;
                }
            } catch (final Exception e) {
                LOG.debug("Cannot recover the key", e);
            }
        }

        return null;
    }

    private PrivateKey resolveX509Data(Element element, String baseURI) {
        LOG.debug("Can I resolve X509Data?");

        try {
            final X509Data x509Data = new X509Data(element, baseURI);

            int len = x509Data.lengthSKI();
            for (int i = 0; i < len; i++) {
                final XMLX509SKI x509SKI = x509Data.itemSKI(i);
                final PrivateKey privKey = resolveX509SKI(x509SKI);
                if (privKey != null) {
                    return privKey;
                }
            }

            len = x509Data.lengthIssuerSerial();
            for (int i = 0; i < len; i++) {
                final XMLX509IssuerSerial x509Serial = x509Data.itemIssuerSerial(i);
                final PrivateKey privKey = resolveX509IssuerSerial(x509Serial);
                if (privKey != null) {
                    return privKey;
                }
            }

            len = x509Data.lengthSubjectName();
            for (int i = 0; i < len; i++) {
                final XMLX509SubjectName x509SubjectName = x509Data.itemSubjectName(i);
                final PrivateKey privKey = resolveX509SubjectName(x509SubjectName);
                if (privKey != null) {
                    return privKey;
                }
            }

            len = x509Data.lengthCertificate();
            for (int i = 0; i < len; i++) {
                final XMLX509Certificate x509Cert = x509Data.itemCertificate(i);
                final PrivateKey privKey = resolveX509Certificate(x509Cert);
                if (privKey != null) {
                    return privKey;
                }
            }
        } catch (final XMLSecurityException e) {
            LOG.debug("XMLSecurityException", e);
        } catch (final KeyStoreException e) {
            LOG.debug("KeyStoreException", e);
        }

        return null;
    }

    /*
     * Search for a private key entry in the KeyStore with the same Subject Key Identifier
     */
    private PrivateKey resolveX509SKI(XMLX509SKI x509SKI) throws XMLSecurityException, KeyStoreException {
        LOG.debug("Can I resolve X509SKI?");

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {

                final Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    final XMLX509SKI certSKI = new XMLX509SKI(x509SKI.getDocument(), (X509Certificate) cert);

                    if (certSKI.equals(x509SKI)) {
                        LOG.debug("match !!! ");

                        try {
                            final Key key = keyStore.getKey(alias, password);
                            if (key instanceof PrivateKey) {
                                return (PrivateKey) key;
                            }
                        } catch (final Exception e) {
                            LOG.debug("Cannot recover the key", e);
                            // Keep searching
                        }
                    }
                }
            }
        }

        return null;
    }

    /*
     * Search for a private key entry in the KeyStore with the same Issuer/Serial Number pair.
     */
    private PrivateKey resolveX509IssuerSerial(XMLX509IssuerSerial x509Serial) throws KeyStoreException {
        LOG.debug("Can I resolve X509IssuerSerial?");

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {

                final Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    final XMLX509IssuerSerial certSerial =
                        new XMLX509IssuerSerial(x509Serial.getDocument(), (X509Certificate) cert);

                    if (certSerial.equals(x509Serial)) {
                        LOG.debug("match !!! ");

                        try {
                            final Key key = keyStore.getKey(alias, password);
                            if (key instanceof PrivateKey) {
                                return (PrivateKey) key;
                            }
                        } catch (final Exception e) {
                            LOG.debug("Cannot recover the key", e);
                            // Keep searching
                        }
                    }
                }
            }
        }

        return null;
    }

    /*
     * Search for a private key entry in the KeyStore with the same Subject Name.
     */
    private PrivateKey resolveX509SubjectName(XMLX509SubjectName x509SubjectName) throws KeyStoreException {
        LOG.debug("Can I resolve X509SubjectName?");

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {

                final Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    final XMLX509SubjectName certSN =
                        new XMLX509SubjectName(x509SubjectName.getDocument(), (X509Certificate) cert);

                    if (certSN.equals(x509SubjectName)) {
                        LOG.debug("match !!! ");

                        try {
                            final Key key = keyStore.getKey(alias, password);
                            if (key instanceof PrivateKey) {
                                return (PrivateKey) key;
                            }
                        } catch (final Exception e) {
                            LOG.debug("Cannot recover the key", e);
                            // Keep searching
                        }
                    }
                }
            }
        }

        return null;
    }

    /*
     * Search for a private key entry in the KeyStore with the same Certificate.
     */
    private PrivateKey resolveX509Certificate(
        XMLX509Certificate x509Cert
    ) throws XMLSecurityException, KeyStoreException {
        LOG.debug("Can I resolve X509Certificate?");
        final byte[] x509CertBytes = x509Cert.getCertificateBytes();

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {

                final Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    byte[] certBytes = null;

                    try {
                        certBytes = cert.getEncoded();
                    } catch (final CertificateEncodingException e1) {
                        LOG.debug("Cannot recover the key", e1);
                    }

                    if (certBytes != null && Arrays.equals(certBytes, x509CertBytes)) {
                        LOG.debug("match !!! ");

                        try {
                            final Key key = keyStore.getKey(alias, password);
                            if (key instanceof PrivateKey) {
                                return (PrivateKey) key;
                            }
                        }
                        catch (final Exception e) {
                            LOG.debug("Cannot recover the key", e);
                            // Keep searching
                        }
                    }
                }
            }
        }

        return null;
    }
}
