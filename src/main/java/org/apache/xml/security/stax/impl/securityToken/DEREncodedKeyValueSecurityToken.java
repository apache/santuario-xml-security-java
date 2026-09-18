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
package org.apache.xml.security.stax.impl.securityToken;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.binding.xmldsig11.DEREncodedKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

/**
 * Inbound security token for a {@code dsig11:DEREncodedKeyValue}: the DER-encoded
 * SubjectPublicKeyInfo of a public key, which is the KeyValue form for key types that have no
 * structured KeyValue element (ML-DSA, EdDSA, ...). The StAX counterpart of the DOM
 * {@code DEREncodedKeyValue} support; the public key is rebuilt lazily from the encoding by
 * trying each supported key type's {@link KeyFactory}.
 */
public class DEREncodedKeyValueSecurityToken extends AbstractInboundSecurityToken {

    // Same key types as the DOM DEREncodedKeyValue.supportedKeyTypes
    private static final String[] SUPPORTED_KEY_TYPES = { "RSA", "DSA", "EC",
            "DiffieHellman", "DH", "XDH", "X25519", "X448",
            "EdDSA", "Ed25519", "Ed448",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "RSASSA-PSS"};

    private final byte[] encodedKey;

    public DEREncodedKeyValueSecurityToken(DEREncodedKeyValueType derEncodedKeyValueType,
                                           InboundSecurityContext inboundSecurityContext)
            throws XMLSecurityException {
        super(inboundSecurityContext, IDGenerator.generateID(null), SecurityTokenConstants.KeyIdentifier_KeyValue, true);

        byte[] value = derEncodedKeyValueType.getValue();
        if (value == null || value.length == 0) {
            throw new XMLSecurityException("stax.unsupportedKeyValue");
        }
        this.encodedKey = value.clone();
    }

    private PublicKey buildPublicKey() throws XMLSecurityException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        for (String keyType : SUPPORTED_KEY_TYPES) {
            try {
                PublicKey publicKey = KeyFactory.getInstance(keyType).generatePublic(keySpec);
                if (publicKey != null) {
                    return publicKey;
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | RuntimeException e) { //NOPMD
                // Not this key type; try the next one. Some providers (e.g. BouncyCastle's
                // XDH/EdDSA KeyFactorySpi) throw an unchecked exception such as
                // ArrayIndexOutOfBoundsException instead of InvalidKeySpecException for
                // malformed or short input, which must not propagate since encodedKey here is
                // untrusted, attacker-controlled inbound content.
            }
        }
        throw new XMLSecurityException("stax.unsupportedKeyValue");
    }

    @Override
    public PublicKey getPublicKey() throws XMLSecurityException {
        if (super.getPublicKey() == null) {
            setPublicKey(buildPublicKey());
        }
        return super.getPublicKey();
    }

    @Override
    public boolean isAsymmetric() {
        return true;
    }

    @Override
    public SecurityTokenConstants.TokenType getTokenType() {
        return SecurityTokenConstants.KeyValueToken;
    }
}
