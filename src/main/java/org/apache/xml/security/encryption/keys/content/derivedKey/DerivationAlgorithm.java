/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.encryption.keys.content.derivedKey;

import org.apache.xml.security.exceptions.XMLSecurityException;

/**
 * Interface is supported by classes to implement key derivation algorithms.
 */
public interface DerivationAlgorithm {

    /**
     * Derives a key from the given secret and other info. The initial derived key is size of
     * offset + keyLength.
     *
     * @param secret    The "shared" secret to use for key derivation (e.g. the secret key)
     * @param otherInfo as specified in [SP800-56A] the optional  attributes:  AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo and SuppPrivInfo attributes  are concatenated to form a bit string “OtherInfo” that is used with the key derivation function.
     * @param offset    the starting position in derived keying material of size: offset + keyLength
     * @param keyLength The length of the key to derive
     * @return The derived key
     * @throws XMLSecurityException if something goes wrong during the key derivation
     */
    byte[] deriveKey(byte[] secret, byte[] otherInfo, int offset,
                     long keyLength) throws XMLSecurityException;


    /**
     * Derives a key from the given secret and other info.
     * @param secret The "shared" secret to use for key derivation (e.g. the secret key)
     * @param otherInfo as specified in [SP800-56A] the optional  attributes:  AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo and SuppPrivInfo attributes  are concatenated to form a bit string “OtherInfo” that is used with the key derivation function.
     * @param keyLength The length of the key to derive
     * @return The derived key
     * @throws XMLSecurityException if something goes wrong during the key derivation
     */
    default byte[] deriveKey(byte[] secret, byte[] otherInfo,
                     long keyLength) throws XMLSecurityException {
        return deriveKey(secret, otherInfo, 0, keyLength);
    }
}
