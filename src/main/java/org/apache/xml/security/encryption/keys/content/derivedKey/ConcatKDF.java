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

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;

import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Key DerivationAlgorithm implementation, defined in Section 5.8.1 of NIST SP 800-56A [SP800-56A], and is equivalent
 * to the KDF3 function defined in ANSI X9.44-2007 [ANSI-X9-44-2007] when the contents of the OtherInfo parameter
 * is structured as in NIST SP 800-56A.
 * <p>
 * Identifier of the key derivation algorithm:  http://www.w3.org/2009/xmlenc11#ConcatKDF
 */
public class ConcatKDF implements DerivationAlgorithm {

    private static final System.Logger LOG = System.getLogger(ConcatKDF.class.getName());
    private final String algorithmURI;

    /**
     * Constructor ConcatKDF with digest algorithmURI parameter such as http://www.w3.org/2001/04/xmlenc#sha256,
     * http://www.w3.org/2001/04/xmlenc#sha512, etc.
     */
    public ConcatKDF(String algorithmURI) {
        this.algorithmURI = algorithmURI;
    }

    /**
     * Default Constructor which sets the default digest algorithmURI parameter:  http://www.w3.org/2001/04/xmlenc#sha256,
     */
    public ConcatKDF() {
        this(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    }

    /**
     * Key DerivationAlgorithm implementation as defined in Section 5.8.1 of NIST SP 800-56A [SP800-56A]
     * <ul>
     * <li> reps = ⎡ keydatalen / hashlen⎤.</li>
     * <li> If reps > (2>32 −1), then ABORT: output an error indicator and stop.</li>
     * <li> Initialize a 32-bit, big-endian bit string counter as 0000000116.</li>
     * <li> If counter || Z || OtherInfo is more than max_hash_inputlen bits long, then ABORT: output an error indicator and stop.
     * <li> For i = 1 to reps by 1, do the following:<ul>
     *     <li> Compute Hashi = H(counter || Z || OtherInfo).</li>
     *     <li> Increment counter (modulo 232), treating it as an unsigned 32-bit integer.</li>
     * </ul></li>
     * <li> Let Hhash be set to Hashreps if (keydatalen / hashlen) is an integer; otherwise, let Hhash  be set to the
     * (keydatalen mod hashlen) leftmost bits of Hashreps.</li>
     * <li>Set DerivedKeyingMaterial = Hash1 || Hash2 || ... || Hashreps-1 || Hhash</li>
     * </ul>
     *
     * @param secret    The "shared" secret to use for key derivation (e.g. the secret key)
     * @param otherInfo as specified in [SP800-56A] the optional  attributes:  AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo and SuppPrivInfo attributes  are concatenated to form a bit string “OtherInfo” that is used with the key derivation function.
     * @param offset    the offset parameter is ignored by this implementation.
     * @param keyLength The length of the key to derive
     * @return The derived key
     * @throws XMLEncryptionException if the key length is too long to be derived with the given algorithm
     */
    @Override
    public byte[] deriveKey(byte[] secret, byte[] otherInfo, int offset, long keyLength) throws XMLSecurityException {

        MessageDigest digest = MessageDigestAlgorithm.getDigestInstance(algorithmURI);

        long genKeyLength = offset+keyLength;

        int iDigestLength = digest.getDigestLength();
        if (genKeyLength / iDigestLength > (long) Integer.MAX_VALUE) {
            LOG.log(Level.ERROR, "Key size is to long to be derived with hash algorithm [{0}]", algorithmURI);
            throw new XMLEncryptionException("errorInKeyDerivation");
        }
        int toGenerateSize = (int) genKeyLength;

        digest.reset();
        ByteBuffer indexBuffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);

        ByteBuffer result = ByteBuffer.allocate(toGenerateSize);

        int counter = 1;
        while (toGenerateSize > 0) {
            indexBuffer.position(0);
            indexBuffer.putInt(counter++);
            indexBuffer.position(0);
            digest.update(indexBuffer);
            digest.update(secret);
            if (otherInfo != null && otherInfo.length > 0) {
                digest.update(otherInfo);
            }
            result.put(digest.digest(), 0, Math.min(toGenerateSize, iDigestLength));
            toGenerateSize -= iDigestLength;
        }
        if (offset > 0) {
            result.position(offset);
            return result.slice().array();
        }
        return result.array();
    }

    /**
     * Method concatenate the bitstrings in following order {@code algID || partyUInfo || partyVInfo || suppPubInfo || suppPrivInfo}.
     * to crate otherInfo as key derivation function input.
     * If named parameters are null the value is ignored.
     * Method parses the bitstring firs {{@code @See} https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF} and then concatenates them to a byte array.
     *
     * @param sharedSecret The "shared" secret to use for key derivation (e.g. the secret key)
     * @param algID        A bit string that indicates how the derived keying material will be parsed and for which
     *                     algorithm(s) the derived secret keying material will be used.
     * @param partyUInfo   A bit string containing public information that is required by the
     *                     application using this KDF to be contributed by party U to the key derivation
     *                     process. At a minimum, PartyUInfo shall include IDU, the identifier of party U. See
     *                     the notes below..
     * @param partyVInfo   A bit string containing public information that is required by the
     *                     application using this KDF to be contributed by party V to the key derivation
     *                     process. At a minimum, PartyVInfo shall include IDV, the identifier of party V. See
     *                     the notes below.
     * @param suppPubInfo  bit string containing additional, mutually-known public information.
     * @param suppPrivInfo The suppPrivInfo A bit string containing additional, mutually-known public Information.
     * @param keyLength    The length of the key to derive
     * @return The resulting other info.
     */
    public byte[] deriveKey(final byte[] sharedSecret,
                            final String algID,
                            final String partyUInfo,
                            final String partyVInfo,
                            final String suppPubInfo,
                            final String suppPrivInfo,
                            final long keyLength)
            throws XMLSecurityException {

        final byte[] otherInfo = concatParameters(algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);

        return deriveKey(sharedSecret, otherInfo, keyLength);
    }


    /**
     * Simple method to concatenate non-padded bitstream ConcatKDF parameters.
     * If parameters are null the value is ignored.
     *
     * @param parameters the parameters to concatenate
     * @return the concatenated parameters as byte array
     */
    private static byte[] concatParameters(final String... parameters) throws XMLEncryptionException {

        List<byte[]> byteParams = new ArrayList<>();
        for (String parameter : parameters) {
            byte[] bytes = parseBitString(parameter);
            byteParams.add(bytes);
        }
        // get bytearrays size
        int iSize = byteParams.stream().map(ConcatKDF::getSize).reduce(0, Integer::sum);

        ByteBuffer buffer = ByteBuffer
                .allocate(iSize);
        byteParams.forEach(buffer::put);
        return buffer.array();
    }

    /**
     * The method validates the bitstring parameter structure and returns byte array of the parameter.
     * <p/>
     * The bitstring is divided into octets using big-endian encoding. Parameter starts with two characters (hex number)
     * defining the number of padding bits followed by hex-string. The length of the bitstring is not a multiple of 8
     * then add padding bits (value 0) as necessary to the last octet to make it a multiple of 8.
     *
     * @param kdfParameter the parameter to parse
     * @return the parsed parameter as byte array
     */
    private static byte[] parseBitString(final String kdfParameter) throws XMLEncryptionException {
        // ignore empty parameters
        if (kdfParameter == null || kdfParameter.isEmpty()) {
            return new byte[0];
        }
        String kdfP = kdfParameter.trim();
        int paramLen = kdfP.length();
        // bit string must have two chars following by first byte defining the number of padding bits
        if (paramLen < 4) {
            LOG.log(Level.ERROR, "ConcatKDF parameter is to short");
            throw new XMLEncryptionException( "KeyDerivation.TooShortParameter", kdfParameter);
        }
        if (paramLen % 2 != 0) {
            LOG.log(Level.ERROR, "Invalid length of ConcatKDF parameter [{0}]!", kdfP);
            throw new XMLEncryptionException( "KeyDerivation.InvalidParameter", kdfParameter);
        }
        int iPadding;
        String strPadding = kdfP.substring(0, 2);
        try {
            iPadding = Integer.parseInt(strPadding, 16);
        } catch (NumberFormatException e) {
            LOG.log(Level.ERROR, "Invalid padding number: [{0}]! Number is not Hexadecimal!", strPadding);
            throw new XMLEncryptionException(e, "KeyDerivation.InvalidParameter", new Object[]{kdfParameter});
        }

        if (iPadding != 0) {
            LOG.log(Level.ERROR, "Padded ConcatKDF parameters are not supported");
            throw new XMLEncryptionException( "KeyDerivation.NotSupportedParameter", kdfParameter);
        }
        // skip first two chars
        kdfP = kdfP.substring(2);
        paramLen = kdfP.length();
        byte[] data = new byte[paramLen / 2];

        for (int i = 0; i < paramLen; i += 2) {
            data[i / 2] = (byte) ((Character.digit(kdfP.charAt(i), 16) << 4)
                    + Character.digit(kdfP.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Method returns the size of the array or 0 if the array is null.
     * @param array the array to get the size from
     * @return the size of the array or 0 if the array is null.
     */
    private static int getSize(byte[] array) {
        return array == null ? 0 : array.length;
    }
}
