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
package org.apache.xml.security.encryption.params;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is used to pass parameters to the Key Encapsulation Mechanism (KEM) based key
 * transport, as specified in the W3C "XML Security: Generic Hybrid Cipher" note
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/). Unlike Diffie-Hellman key agreement
 * ({@link KeyAgreementParameters}), a KEM has no ephemeral originator key pair: the
 * encapsulating party only needs the recipient's public key, and the decapsulating party
 * only needs the recipient's private key.
 */
public class KeyEncapsulationParameters implements AlgorithmParameterSpec {

    private final String keyEncapsulationAlgorithm;
    private final KeyDerivationParameters keyDerivationParameter;

    private PublicKey recipientPublicKey;
    private PrivateKey recipientPrivateKey;

    public KeyEncapsulationParameters(String keyEncapsulationAlgorithm, KeyDerivationParameters keyDerivationParameter) {
        this.keyEncapsulationAlgorithm = keyEncapsulationAlgorithm;
        this.keyDerivationParameter = keyDerivationParameter;
    }

    public String getKeyEncapsulationAlgorithm() {
        return keyEncapsulationAlgorithm;
    }

    public KeyDerivationParameters getKeyDerivationParameter() {
        return keyDerivationParameter;
    }

    public PublicKey getRecipientPublicKey() {
        return recipientPublicKey;
    }

    public void setRecipientPublicKey(PublicKey recipientPublicKey) {
        this.recipientPublicKey = recipientPublicKey;
    }

    public PrivateKey getRecipientPrivateKey() {
        return recipientPrivateKey;
    }

    public void setRecipientPrivateKey(PrivateKey recipientPrivateKey) {
        this.recipientPrivateKey = recipientPrivateKey;
    }
}
