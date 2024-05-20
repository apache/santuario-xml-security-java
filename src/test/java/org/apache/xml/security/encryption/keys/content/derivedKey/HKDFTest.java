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
package org.apache.xml.security.encryption.keys.content.derivedKey;


import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.xml.crypto.dsig.DigestMethod;

import static org.apache.xml.security.encryption.XMLCipherUtil.hexStringToByteArray;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) tests as defined
 * in RFC 5869, Appendix A. Test Vectors
 */
class HKDFTest {
    private static final System.Logger LOG = System.getLogger(HKDFTest.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    @ParameterizedTest(name = "{index}. {0}")
    @CsvSource({
            "'Rfc5869: Test Case 1','http://www.w3.org/2001/04/xmlenc#sha256'," +
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b," +
                    "000102030405060708090a0b0c,f0f1f2f3f4f5f6f7f8f9,42, " +
                    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5," +
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            "'Rfc5869: Test Case 2','http://www.w3.org/2001/04/xmlenc#sha256', " +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f," +
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf," +
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff," +
                    "82, " +
                    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244," +
                    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            "'Rfc5869: Test Case 3','http://www.w3.org/2001/04/xmlenc#sha256', " +
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b," +
                    "''," +
                    "''," +
                    "42, " +
                    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04," +
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            "'Rfc5869: Test Case 4','http://www.w3.org/2000/09/xmldsig#sha1', " +
                    "0b0b0b0b0b0b0b0b0b0b0b," +
                    "000102030405060708090a0b0c," +
                    "f0f1f2f3f4f5f6f7f8f9," +
                    "42, " +
                    "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243," +
                    "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
            "'Rfc5869: Test Case 5','http://www.w3.org/2000/09/xmldsig#sha1', " +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f," +
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf," +
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff," +
                    "82, " +
                    "8adae09a2a307059478d309b26c4115a224cfaf6," +
                    "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
            "'Rfc5869: Test Case 6','http://www.w3.org/2000/09/xmldsig#sha1', " +
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b," +
                    "''," +
                    "''," +
                    "42, " +
                    "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01," +
                    "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
            "'Rfc5869: Test Case 7','http://www.w3.org/2000/09/xmldsig#sha1', " +
                    "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c," +
                    "," +
                    "''," +
                    "42, " +
                    "2adccada18779e7c2077ad2eb19d3f3e731385dd," +
                    "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
    })
    void deriveKey(String name, String hash, String ikm, String salt, String info, int length, String prk, String okm) throws XMLSecurityException {
        LOG.log(System.Logger.Level.DEBUG, "Execute HKDF Test Case: [{0}]", name);
        byte[] saltBytes = hexStringToByteArray(salt);
        byte[] infoBytes = hexStringToByteArray(info);
        byte[] ikmBytes = hexStringToByteArray(ikm);

        byte[] expectedPRK = hexStringToByteArray(prk);
        byte[] expectedOKM = hexStringToByteArray(okm);
        String hmacJCEName = getHMacHashForHashJCEName(hash);
        String hMacHashAlgorithmURI = getHMacHashForHashUri(hash);

        HKDFParams params = HKDFParams.createBuilder(length * 8, hMacHashAlgorithmURI)
                .salt(saltBytes)
                .info(infoBytes)
                .build();

        HKDF testInstance = new HKDF();
        byte[] extractedKey = testInstance.extractKey(hmacJCEName, saltBytes, ikmBytes);
        byte[] derivedKey = testInstance.deriveKey(ikmBytes,  params);

        assertArrayEquals(expectedPRK, extractedKey);
        assertArrayEquals(expectedOKM, derivedKey);
    }

    /**
     * Helper method to get corresponding MacHash algorithm URI for the given hash algorithm URI.
     *
     * @param hashAlgorithm the hash algorithm URI
     * @return the MacHash algorithm URI value.
     * @throws IllegalArgumentException if the hash algorithm is not supported.
     */
    private static String getHMacHashForHashUri(String hashAlgorithm) {

        switch (hashAlgorithm) {
            case DigestMethod.SHA1:
                return XMLSignature.ALGO_ID_MAC_HMAC_SHA1;
            case DigestMethod.SHA224:
                return XMLSignature.ALGO_ID_MAC_HMAC_SHA224;
            case DigestMethod.SHA256:
                return XMLSignature.ALGO_ID_MAC_HMAC_SHA256;
            case DigestMethod.SHA384:
                return XMLSignature.ALGO_ID_MAC_HMAC_SHA384;
            case DigestMethod.SHA512:
                return XMLSignature.ALGO_ID_MAC_HMAC_SHA512;
            case DigestMethod.RIPEMD160:
                return XMLSignature.ALGO_ID_MAC_HMAC_RIPEMD160;
            default:
                throw new IllegalArgumentException("Unknown/not supported hash algorithm: [" + hashAlgorithm + "]  for MacHash algorithm");
        }
    }

    /**
     * Helper method to get corresponding MacHash JCE algorithm name for the
     * given hash algorithm URI.
     *
     * @param hashAlgorithm the hash algorithm URI
     * @return the MacHash algorithm URI value.
     * @throws IllegalArgumentException if the hash algorithm is not supported.
     */
    private static String getHMacHashForHashJCEName(String hashAlgorithm) {

        switch (hashAlgorithm) {
            case DigestMethod.SHA1:
                return "HmacSHA1";
            case DigestMethod.SHA224:
                return "HmacSHA224";
            case DigestMethod.SHA256:
                return "HmacSHA256";
            case DigestMethod.SHA384:
                return "HmacSHA384";
            case DigestMethod.SHA512:
                return "HmacSHA512";
            case DigestMethod.RIPEMD160:
                return "HmacRIPEMD160";
            default:
                throw new IllegalArgumentException("Unknown/not supported hash algorithm: [" + hashAlgorithm + "]  for MacHash algorithm");
        }
    }
}
