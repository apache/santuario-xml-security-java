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
package org.apache.xml.security.encryption.params;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.EncryptionConstants;

/**
 * Class HMacKeyDerivationParameter (HKDF parameter) is used to specify parameters for the HMAC-based Extract-and-Expand
 * Key Derivation Function.
 * @see <A HREF="https://datatracker.ietf.org/doc/html/rfc5869">HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</A>
 */
public class HKDFParams extends KeyDerivationParameters {

    private String hmacHashAlgorithm;
    private byte[] salt;
    private byte[] info;

    /**
     * Constructor HMacKeyDerivationParameter with specified digest algorithm
     *
     * @param keyBitLength the length of the derived key in bits
     * @param hmacHashAlgorithm the HMAC hash algorithm to use for the key derivation.
     */
    public HKDFParams(int keyBitLength, String hmacHashAlgorithm) {
        super(EncryptionConstants.ALGO_ID_KEYDERIVATION_HKDF, keyBitLength);
        this.hmacHashAlgorithm = hmacHashAlgorithm;
    }

    /**
     * Method return the digest algorithm. In case of algorithm is not set, the "default"
     * algorithm hmac-sha256 hmac algorithm is returned.
     *
     * @return the hmac algorithm
     */
    public String getHmacHashAlgorithm() {
        return hmacHashAlgorithm == null? XMLSignature.ALGO_ID_MAC_HMAC_SHA256 : hmacHashAlgorithm;
    }

    public void setHmacHashAlgorithm(String hmacHashAlgorithm) {
        this.hmacHashAlgorithm = hmacHashAlgorithm;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public byte[] getInfo() {
        return info;
    }

    public void setInfo(byte[] info) {
        this.info = info;
    }
}
