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
package org.apache.xml.security.keys.content;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.Signature11ElementProxy;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Provides content model support for the <code>dsig11:DEREncodedKeyvalue</code> element.
 *
 */
public class DEREncodedKeyValue extends Signature11ElementProxy implements KeyInfoContent {

    /** JCA algorithm key types supported by this implementation. */
    private static final String[] supportedKeyTypes = { "RSA", "DSA", "EC"};

    /**
     * Constructor DEREncodedKeyValue
     *
     * @param element
     * @param baseURI
     * @throws XMLSecurityException
     */
    public DEREncodedKeyValue(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     * Constructor DEREncodedKeyValue
     *
     * @param doc
     * @param publicKey
     * @throws XMLSecurityException
     */
    public DEREncodedKeyValue(Document doc, PublicKey publicKey) throws XMLSecurityException {
        super(doc);

        this.addBase64Text(getEncodedDER(publicKey));
    }

    /**
     * Constructor DEREncodedKeyValue
     *
     * @param doc
     * @param encodedKey
     */
    public DEREncodedKeyValue(Document doc, byte[] encodedKey) {
        super(doc);

        this.addBase64Text(encodedKey);
    }

    /**
     * Sets the <code>Id</code> attribute
     *
     * @param id ID
     */
    public void setId(String id) {
        setLocalIdAttribute(Constants._ATT_ID, id);
    }

    /**
     * Returns the <code>Id</code> attribute
     *
     * @return the <code>Id</code> attribute
     */
    public String getId() {
        return getLocalAttribute(Constants._ATT_ID);
    }

    /** {@inheritDoc} */
    @Override
    public String getBaseLocalName() {
        return Constants._TAG_DERENCODEDKEYVALUE;
    }

    /**
     * Method getPublicKey
     *
     * @return the public key
     * @throws XMLSecurityException
     */
    public PublicKey getPublicKey() throws XMLSecurityException {
        final byte[] encodedKey = getBytesFromTextChild();

        // Iterate over the supported key types until one produces a public key.
        for (final String keyType : supportedKeyTypes) {
            try {
                final KeyFactory keyFactory = KeyFactory.getInstance(keyType);
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                final PublicKey publicKey = keyFactory.generatePublic(keySpec);
                if (publicKey != null) {
                    return publicKey;
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) { //NOPMD
                // Do nothing, try the next type
            }
        }
        throw new XMLSecurityException("DEREncodedKeyValue.UnsupportedEncodedKey");
    }

    /**
     * Method getEncodedDER
     *
     * @return the public key
     * @throws XMLSecurityException
     */
    protected byte[] getEncodedDER(PublicKey publicKey) throws XMLSecurityException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(publicKey.getAlgorithm());
            final X509EncodedKeySpec keySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
            return keySpec.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            final Object[] exArgs = { publicKey.getAlgorithm(), publicKey.getFormat(), publicKey.getClass().getName() };
            throw new XMLSecurityException(e, "DEREncodedKeyValue.UnsupportedPublicKey", exArgs);
        }
    }

}
