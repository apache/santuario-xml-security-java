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

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyInfoReference;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * KeyResolverSpi implementation which resolves public keys, private keys, secret keys, and X.509 certificates from a
 * <code>dsig11:KeyInfoReference</code> element.
 *
 */
public class KeyInfoReferenceResolver extends KeyResolverSpi {

    private static final Logger LOG = System.getLogger(KeyInfoReferenceResolver.class.getName());

    /** {@inheritDoc} */
    @Override
    protected boolean engineCanResolve(Element element, String baseURI, StorageResolver storage) {
        return XMLUtils.elementIsInSignature11Space(element, Constants._TAG_KEYINFOREFERENCE);
    }

    /** {@inheritDoc} */
    @Override
    protected PublicKey engineResolvePublicKey(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {
        try {
            KeyInfo referent = resolveReferentKeyInfo(element, baseURI, storage, secureValidation);
            if (referent != null) {
                return referent.getPublicKey();
            }
        } catch (XMLSecurityException e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected X509Certificate engineResolveX509Certificate(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {
        try {
            KeyInfo referent = resolveReferentKeyInfo(element, baseURI, storage, secureValidation);
            if (referent != null) {
                return referent.getX509Certificate();
            }
        } catch (XMLSecurityException e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected SecretKey engineResolveSecretKey(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {

        try {
            KeyInfo referent = resolveReferentKeyInfo(element, baseURI, storage, secureValidation);
            if (referent != null) {
                return referent.getSecretKey();
            }
        } catch (XMLSecurityException e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKey engineResolvePrivateKey(Element element, String baseURI, StorageResolver storage, boolean secureValidation)
        throws KeyResolverException {

        try {
            KeyInfo referent = resolveReferentKeyInfo(element, baseURI, storage, secureValidation);
            if (referent != null) {
                return referent.getPrivateKey();
            }
        } catch (XMLSecurityException e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
        }

        return null;
    }

    /**
     * Resolve the KeyInfoReference Element's URI attribute into a KeyInfo instance.
     *
     * @param element
     * @param baseURI
     * @param storage
     * @param secureValidation
     * @return the KeyInfo which is referred to by this KeyInfoReference, or null if can not be resolved
     * @throws XMLSecurityException
     */
    private KeyInfo resolveReferentKeyInfo(Element element, String baseURI,
                                           StorageResolver storage, boolean secureValidation) throws XMLSecurityException {
        KeyInfoReference reference = new KeyInfoReference(element, baseURI);
        Attr uriAttr = reference.getURIAttr();

        XMLSignatureInput resource = resolveInput(uriAttr, baseURI, secureValidation);

        Element referentElement = null;
        try {
            referentElement = obtainReferenceElement(resource, secureValidation);
        } catch (Exception e) {
            LOG.log(Level.DEBUG, "XMLSecurityException", e);
            return null;
        }

        if (referentElement == null) {
            LOG.log(Level.DEBUG, "De-reference of KeyInfoReference URI returned null: {0}", uriAttr.getValue());
            return null;
        }

        validateReference(referentElement, secureValidation);

        KeyInfo referent = new KeyInfo(referentElement, baseURI);
        referent.setSecureValidation(secureValidation);
        referent.addStorageResolver(storage);
        return referent;
    }

    /**
     * Validate the Element referred to by the KeyInfoReference.
     *
     * @param referentElement
     * @param secureValidation
     *
     * @throws XMLSecurityException
     */
    private void validateReference(Element referentElement, boolean secureValidation) throws XMLSecurityException {
        if (!XMLUtils.elementIsInSignatureSpace(referentElement, Constants._TAG_KEYINFO)) {
            Object[] exArgs = { new QName(referentElement.getNamespaceURI(), referentElement.getLocalName()) };
            throw new XMLSecurityException("KeyInfoReferenceResolver.InvalidReferentElement.WrongType", exArgs);
        }

        KeyInfo referent = new KeyInfo(referentElement, "");
        if (referent.containsKeyInfoReference() || referent.containsRetrievalMethod()) {
            if (secureValidation) {
                throw new XMLSecurityException("KeyInfoReferenceResolver.InvalidReferentElement.ReferenceWithSecure");
            } else {
                // Don't support chains of references at this time. If do support in the future, this is where the code
                // would go to validate that don't have a cycle, resulting in an infinite loop. This may be unrealistic
                // to implement, and/or very expensive given remote URI references.
                throw new XMLSecurityException("KeyInfoReferenceResolver.InvalidReferentElement.ReferenceWithoutSecure");
            }
        }

    }

    /**
     * Resolve the XML signature input represented by the specified URI.
     *
     * @param uri
     * @param baseURI
     * @param secureValidation
     * @return the XML signature input represented by the specified URI.
     * @throws XMLSecurityException
     */
    private XMLSignatureInput resolveInput(Attr uri, String baseURI, boolean secureValidation)
        throws XMLSecurityException {
        ResourceResolverContext resContext = new ResourceResolverContext(uri, baseURI, secureValidation);
        if (resContext.isURISafeToResolve()) {
            return ResourceResolver.resolve(resContext);
        }
        String uriToResolve = uri != null ? uri.getValue() : null;
        Object[] exArgs = { uriToResolve != null ? uriToResolve : "null", baseURI };

        throw new ResourceResolverException("utils.resolver.noClass", exArgs, uriToResolve, baseURI);
    }

    /**
     * Resolve the Element effectively represented by the XML signature input source.
     *
     * @param resource
     * @param secureValidation
     * @return the Element effectively represented by the XML signature input source.
     * @throws CanonicalizationException
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     * @throws KeyResolverException
     */
    private Element obtainReferenceElement(XMLSignatureInput resource, boolean secureValidation)
        throws CanonicalizationException, ParserConfigurationException,
        IOException, SAXException, KeyResolverException {

        Element e;
        if (resource.isElement()) {
            e = (Element) resource.getSubNode();
        } else if (resource.isNodeSet()) {
            LOG.log(Level.DEBUG, "De-reference of KeyInfoReference returned an unsupported NodeSet");
            return null;
        } else {
            // Retrieved resource is a byte stream
            byte[] inputBytes = resource.getBytes();
            e = getDocFromBytes(inputBytes, secureValidation);
        }
        return e;
    }
}
