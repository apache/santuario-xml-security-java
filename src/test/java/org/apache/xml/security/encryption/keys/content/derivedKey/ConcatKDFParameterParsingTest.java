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

import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The ConcatKDF AlgorithmID / PartyUInfo / PartyVInfo / SuppPubInfo / SuppPrivInfo values are
 * hex-encoded bit strings read from the (untrusted) message. Non-hex input must be rejected rather
 * than silently decoded to wrong bytes.
 */
class ConcatKDFParameterParsingTest {

    private static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final byte[] SHARED_SECRET = new byte[32];

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testHexStringToByteArray() {
        assertNull(XMLCipherUtil.hexStringToByteArray(null));
        assertArrayEquals(new byte[0], XMLCipherUtil.hexStringToByteArray(""));
        assertArrayEquals(new byte[] {0x00, 0x1f, (byte) 0xab, (byte) 0xCD, (byte) 0xff},
            XMLCipherUtil.hexStringToByteArray("001fabCDff"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "0",            // odd length
        "abc",          // odd length
        "zz",           // not hex
        "0g",           // not hex
        "-1",           // sign is not a hex digit
        "٣٣", // ARABIC-INDIC DIGIT THREE: accepted by Character.digit, but not ASCII hex
        "ＡＡ"  // FULLWIDTH LATIN CAPITAL LETTER A: likewise
    })
    void testHexStringToByteArrayRejectsInvalidInput(String hex) {
        assertThrows(IllegalArgumentException.class, () -> XMLCipherUtil.hexStringToByteArray(hex));
    }

    @Test
    void testWellFormedParameterDerivesKey() throws Exception {
        byte[] key = new ConcatKDF().deriveKey(SHARED_SECRET, params("00" + "0102030405"));
        assertEquals(16, key.length);
    }

    @ParameterizedTest
    @ValueSource(strings = {"00zz", "00GG0102", "00٣٣"})
    void testNonHexParameterRejected(String algorithmId) {
        assertThrows(XMLEncryptionException.class,
            () -> new ConcatKDF().deriveKey(SHARED_SECRET, params(algorithmId)));
    }

    private static ConcatKDFParams params(String algorithmId) {
        return ConcatKDFParams.createBuilder(128, SHA256)
            .algorithmID(algorithmId)
            .partyUInfo("")
            .partyVInfo("")
            .build();
    }
}
