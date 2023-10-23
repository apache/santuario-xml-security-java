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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is used to pass parameters to the KeyAgreement algorithm.
 */
public class KeyAgreementParameterSpec implements AlgorithmParameterSpec {
    /**
     * This enum defines the actor type of the KeyAgreement algorithm. The actor type defines which public and which
     * private key is expected to be present for the KeyAgreement algorithm to define derived key.
     */
    public enum ActorType {
        ORIGINATOR,
        RECIPIENT
    }

    KeyDerivationParameter KeyDerivationParameter;
    ActorType actorType;
    String keyAgreementAlgorithm;
    PublicKey originatorPublicKey;
    PrivateKey originatorPrivateKey;

    PublicKey recipientPublicKey;
    PrivateKey recipientPrivateKey;


    public KeyAgreementParameterSpec(ActorType actorType, String keyAgreementAlgorithm, KeyDerivationParameter keyDerivationParameter) {
        this.actorType = actorType;
        this.KeyDerivationParameter = keyDerivationParameter;
        this.keyAgreementAlgorithm = keyAgreementAlgorithm;
    }

    public KeyDerivationParameter getKeyDerivationParameter() {
        return KeyDerivationParameter;
    }

    public String getKeyAgreementAlgorithm() {
        return keyAgreementAlgorithm;
    }

    public void setOriginatorKeyPair(KeyPair originatorKeyPair) {
        this.originatorPublicKey = originatorKeyPair.getPublic();
        this.originatorPrivateKey = originatorKeyPair.getPrivate();
    }

    public PublicKey getOriginatorPublicKey() {
        return originatorPublicKey;
    }

    public void setOriginatorPublicKey(PublicKey originatorPublicKey) {
        this.originatorPublicKey = originatorPublicKey;
    }

    public PrivateKey getOriginatorPrivateKey() {
        return originatorPrivateKey;
    }

    public void setOriginatorPrivateKey(PrivateKey originatorPrivateKey) {
        this.originatorPrivateKey = originatorPrivateKey;
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

    public ActorType getActorType() {
        return actorType;
    }

    public PublicKey getAgreementPublicKey() {
        return actorType == ActorType.ORIGINATOR ? recipientPublicKey : originatorPublicKey;
    }

    public PrivateKey getAgreementPrivateKey() {
        return actorType == ActorType.ORIGINATOR ? originatorPrivateKey : recipientPrivateKey;
    }
}
