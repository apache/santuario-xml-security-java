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

import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * The implementation of the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in RFC 5869.
 * <p>
 * The HKDF algorithm is defined as follows:
 * <pre>
 * N = ceil(L/HashLen)
 * T = T(1) | T(2) | T(3) | ... | T(N)
 * OKM = first L bytes of T
 * where:
 * T(0) = empty string (zero length)
 * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 * ...
 * </pre>
 */
public class HKDF implements DerivationAlgorithm {

    private static final System.Logger LOG = System.getLogger(HKDF.class.getName());
    private final String hmacHashAlgorithmURI;
    private final Mac hmac;

    /**
     * Constructor HKDF initializes the Mac object with the given algorithmURI and salt.
     *
     * @param hmacHashAlgorithmURI the Hash algorithm
     * @param salt               the salt value to initialize the MAC algorithm.
     * @throws XMLSecurityException if the key derivation initialization fails for any reason
     */
    public HKDF(String hmacHashAlgorithmURI, byte[] salt) throws XMLSecurityException {
        this.hmacHashAlgorithmURI = hmacHashAlgorithmURI;
        LOG.log(DEBUG, "Init HmacHash AlgorithmURI: [{}]", hmacHashAlgorithmURI);
        hmac = initHMac(salt, true);
    }

    /**
     * Derives a key from the given secret and info. Method extracts the key and then expands it to the keyLength.
     *
     * @param secret    The "shared" secret to use for key derivation
     * @param info      The "info" parameter for key derivation describing purpose or derivation key context
     * @param offset    the starting position in derived keying material of size: offset + keyLength
     * @param keyLength The length of the key to derive
     * @return the derived key using HKDF for the given parameters.
     * @throws XMLSecurityException if the key derivation fails for any reason
     */
    @Override
    public byte[] deriveKey(byte[] secret, byte[] info, int offset, long keyLength) throws XMLSecurityException {

        byte[] prk = extractKey(secret);
        return expandKey(prk, info, offset, keyLength);
    }

    /**
     * The extracted pseudo-random based on HMAC-Hash function. Salt is set at class initialization.
     * Calculation of the  extracted key: <pre>PRK = HMAC-Hash(salt, IKM)</pre>
     *
     * @param secret the shared secret (IKM) to use for key derivation
     * @return the pseudo-random key
     */
    public byte[] extractKey(byte[] secret) {
        hmac.reset();
        return hmac.doFinal(secret);
    }

    /**
     * The method inits Hash-MAC with given PRK (as salt) and output OKM is calculated as follows:
     * <pre>
     *  T(0) = empty string (zero length)
     *  T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
     *  T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
     *  T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
     *  ...
     *  </pre>
     *
     * @param prk       pseudo-random key
     * @param info      used to derive the key
     * @param offset    in bytes of the derived key
     * @param keyLength in bytes of the derived key
     * @return the derived key OKM
     * @throws XMLSecurityException in case the key derivation fails for any reason
     */

    public byte[] expandKey(byte[] prk, byte[] info, int offset, long keyLength) throws XMLSecurityException {
        // prepare for expanding the key
        Mac hMac = initHMac(prk, false);
        int iMacLength = hMac.getMacLength();

        int toGenerateSize = (int) keyLength;
        ByteBuffer result = ByteBuffer.allocate(toGenerateSize);
        byte[] prevResult = new byte[0];
        short counter = 1;
        while (toGenerateSize > 0) {
            hMac.reset();
            hMac.update(prevResult);
            if (info != null && info.length > 0) {
                hMac.update(info);
            }
            hMac.update((byte) counter);
            prevResult = hMac.doFinal();
            result.put(prevResult, 0, Math.min(toGenerateSize, iMacLength));
            // ger ready for next iteration
            toGenerateSize -= iMacLength;
            counter++;
        }
        if (offset > 0) {
            result.position(offset);
            return result.slice().array();
        }
        return result.array();
    }

    /**
     * Method initializes a Message Authentication Code (MAC) object using the
     * init secret/salt or an empty byte array if initSecret parameter is null or empty.
     *
     * @param initSecret the secret/salt to initialize the hmac
     * @param initPRK  if true, the salt is initialized with a string of zero octets as long as the hash function output
     *                 see [RFC5869] Section 2.2
     * @return Initialized Mac object
     * @throws XMLSecurityException if the key derivation initialization fails for any reason
     */
    private Mac initHMac(byte[] initSecret, boolean initPRK) throws XMLSecurityException {
        String jceAlgorithm = null;
        Mac mac;
        try {
            jceAlgorithm = XMLCipherUtil.getJCEMacHashForUri(hmacHashAlgorithmURI);
            LOG.log(DEBUG, "Init Mac with hash algorithm: [{}]", jceAlgorithm);
            mac = Mac.getInstance(jceAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(e, "KeyDerivation.NotSupportedParameter", new Object[]{jceAlgorithm});
        }

        if (initPRK && (initSecret == null || initSecret.length == 0)) {
            //  If "initSecret"/salt is not provided, a string of zero octets as long as the hash function output is used
            LOG.log(DEBUG, "Init Mac with hmac algorithm [{}] and empty salt!", jceAlgorithm);
            initSecret = new byte[mac.getMacLength()];
        }
        SecretKeySpec secret_key = new SecretKeySpec(initSecret, jceAlgorithm);
        try {
            mac.init(secret_key);
        } catch (InvalidKeyException e) {
            throw new XMLSecurityException(e);
        }
        return mac;
    }
}
