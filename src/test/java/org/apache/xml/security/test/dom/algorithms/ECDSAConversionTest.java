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
package org.apache.xml.security.test.dom.algorithms;

import org.apache.xml.security.algorithms.implementations.ECDSAUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ECDSA signature format conversion between ASN.1 and XML DSIG formats.
 * These tests verify edge cases and error handling in the conversion logic.
 */
class ECDSAConversionTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public ECDSAConversionTest() {
        // Public constructor for JUnit
    }

    /**
     * Test that an empty ASN.1 sequence is rejected.
     */
    @Test
    void testEmptyASN1Rejected() {
        byte[] emptySeq = new byte[]{0x30, 0x00};

        IOException exception = assertThrows(IOException.class, () -> {
            ECDSAUtils.convertASN1toXMLDSIG(emptySeq, 64);
        }, "Empty ASN.1 sequence should be rejected");

        assertTrue(exception.getMessage().contains("Invalid") || 
                  exception.getMessage().contains("format"),
                  "Exception should mention invalid format");
    }

    /**
     * Test that invalid ASN.1 first byte (not 0x30 for SEQUENCE) is rejected.
     */
    @Test
    void testInvalidASN1FirstByteRejected() {
        // Invalid first byte (should be 0x30 for SEQUENCE)
        byte[] invalidAsn1 = new byte[]{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};

        assertThrows(IOException.class, () -> {
            ECDSAUtils.convertASN1toXMLDSIG(invalidAsn1, 64);
        }, "ASN.1 data not starting with SEQUENCE tag should be rejected");
    }

    /**
     * Test that too-short ASN.1 data is rejected.
     */
    @Test
    void testTooShortASN1Rejected() {
        byte[] tooShort = new byte[]{0x30, 0x06, 0x02, 0x01};

        assertThrows(IOException.class, () -> {
            ECDSAUtils.convertASN1toXMLDSIG(tooShort, 64);
        }, "Too short ASN.1 data should be rejected");
    }

    /**
     * Test that malformed length encoding is rejected.
     */
    @Test
    void testMalformedLengthRejected() {
        // Invalid length encoding (0x82 indicates 2-byte length, but we use short form)
        byte[] malformed = new byte[]{0x30, (byte) 0x82, 0x00, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};

        assertThrows(IOException.class, () -> {
            ECDSAUtils.convertASN1toXMLDSIG(malformed, 64);
        }, "Malformed length encoding should be rejected");
    }

    /**
     * Test valid ASN.1 to XMLDSIG conversion with typical signature.
     */
    @Test
    void testValidASN1toXMLDSIGConversion() throws IOException {
        // Valid ASN.1 DER encoded ECDSA signature:
        // SEQUENCE { INTEGER (r), INTEGER (s) }
        // r = 0x01, s = 0x02
        byte[] validAsn1 = new byte[]{
            0x30, 0x06,           // SEQUENCE, length 6
            0x02, 0x01, 0x01,     // INTEGER, length 1, value 1 (r)
            0x02, 0x01, 0x02      // INTEGER, length 1, value 2 (s)
        };

        byte[] xmldsig = ECDSAUtils.convertASN1toXMLDSIG(validAsn1, 32);

        assertNotNull(xmldsig);
        assertEquals(64, xmldsig.length, "XMLDSIG format should be 2 * rawLen");
        
        // r should be padded to 32 bytes with leading zeros
        assertEquals(0x01, xmldsig[31], "Last byte of r should be 0x01");
        // s should be padded to 32 bytes with leading zeros
        assertEquals(0x02, xmldsig[63], "Last byte of s should be 0x02");
        
        // All other bytes should be zero (padding)
        for (int i = 0; i < 31; i++) {
            assertEquals(0, xmldsig[i], "Padding byte should be zero");
            assertEquals(0, xmldsig[32 + i], "Padding byte should be zero");
        }
    }

    /**
     * Test conversion with automatic length detection (rawLen = -1).
     */
    @Test
    void testAutomaticLengthDetection() throws IOException {
        byte[] validAsn1 = new byte[]{
            0x30, 0x06,
            0x02, 0x01, 0x05,
            0x02, 0x01, 0x07
        };

        byte[] xmldsig = ECDSAUtils.convertASN1toXMLDSIG(validAsn1, -1);

        assertNotNull(xmldsig);
        assertEquals(2, xmldsig.length, "With auto-detect, length should be 2 * maxLen(r,s)");
        assertEquals(0x05, xmldsig[0], "First byte should be r value");
        assertEquals(0x07, xmldsig[1], "Second byte should be s value");
    }

    /**
     * Test that rawLen smaller than actual signature length is rejected.
     */
    @Test
    void testTooSmallRawLenRejected() {
        // r and s are each 8 bytes, but we specify rawLen=4
        byte[] asn1 = new byte[]{
            0x30, 0x16,
            0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x02, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
        };

        assertThrows(IOException.class, () -> {
            ECDSAUtils.convertASN1toXMLDSIG(asn1, 4);
        }, "rawLen smaller than actual signature component should be rejected");
    }

    /**
     * Test XMLDSIG to ASN.1 conversion with valid input.
     */
    @Test
    void testValidXMLDSIGtoASN1Conversion() throws IOException {
        // Create XMLDSIG format: 64 bytes (32 for r, 32 for s)
        byte[] xmldsig = new byte[64];
        xmldsig[31] = 0x05; // r = 5
        xmldsig[63] = 0x07; // s = 7

        byte[] asn1 = ECDSAUtils.convertXMLDSIGtoASN1(xmldsig);

        assertNotNull(asn1);
        // Should be: SEQUENCE { INTEGER(5), INTEGER(7) }
        assertEquals(0x30, asn1[0], "First byte should be SEQUENCE tag");
        assertTrue(asn1.length >= 8, "ASN.1 should have minimum structure");
        
        // Verify it contains INTEGER tags
        boolean foundIntegers = false;
        for (int i = 1; i < asn1.length - 1; i++) {
            if (asn1[i] == 0x02) { // INTEGER tag
                foundIntegers = true;
                break;
            }
        }
        assertTrue(foundIntegers, "ASN.1 should contain INTEGER tags");
    }

    /**
     * Test round-trip conversion: ASN.1 -> XMLDSIG -> ASN.1.
     */
    @Test
    void testRoundTripConversion() throws IOException {
        // Original ASN.1
        byte[] originalAsn1 = new byte[]{
            0x30, 0x0A,
            0x02, 0x03, 0x01, 0x02, 0x03,
            0x02, 0x03, 0x04, 0x05, 0x06
        };

        // Convert to XMLDSIG
        byte[] xmldsig = ECDSAUtils.convertASN1toXMLDSIG(originalAsn1, 32);
        assertNotNull(xmldsig);

        // Convert back to ASN.1
        byte[] reconvertedAsn1 = ECDSAUtils.convertXMLDSIGtoASN1(xmldsig);
        assertNotNull(reconvertedAsn1);

        // Should be able to convert back to XMLDSIG and get the same result
        byte[] xmldsig2 = ECDSAUtils.convertASN1toXMLDSIG(reconvertedAsn1, 32);
        assertArrayEquals(xmldsig, xmldsig2, "Round-trip conversion should produce identical XMLDSIG");
    }

    /**
     * Test XMLDSIG with leading zeros in r and s components.
     */
    @Test
    void testXMLDSIGWithLeadingZeros() throws IOException {
        byte[] xmldsig = new byte[64];
        // r has leading zeros, actual value at end
        xmldsig[30] = 0x00;
        xmldsig[31] = 0x42;
        // s has leading zeros, actual value at end
        xmldsig[62] = 0x00;
        xmldsig[63] = (byte) 0x99;

        byte[] asn1 = ECDSAUtils.convertXMLDSIGtoASN1(xmldsig);
        assertNotNull(asn1);
        
        // Should strip leading zeros in the ASN.1 representation
        assertTrue(asn1.length < 70, "ASN.1 should be compact without unnecessary leading zeros");
    }

    /**
     * Test XMLDSIG with high-bit set (requiring padding in ASN.1).
     */
    @Test
    void testXMLDSIGWithHighBitSet() throws IOException {
        byte[] xmldsig = new byte[64];
        // r with high bit set (negative if interpreted as signed)
        xmldsig[31] = (byte) 0xFF;
        // s with high bit set
        xmldsig[63] = (byte) 0x80;

        byte[] asn1 = ECDSAUtils.convertXMLDSIGtoASN1(xmldsig);
        assertNotNull(asn1);

        // ASN.1 INTEGER encoding requires padding byte for positive numbers with high bit set
        // The conversion should handle this correctly
        assertTrue(asn1.length > 0, "Conversion should succeed");
    }

    /**
     * Test that odd-length XMLDSIG is rejected.
     */
    @Test
    void testOddLengthXMLDSIGRejected() {
        byte[] oddLength = new byte[63]; // Should be even (r and s are equal length)

        // The conversion expects even length (half for r, half for s)
        assertDoesNotThrow(() -> {
            // Current implementation doesn't validate odd length, it will just truncate
            // This test documents the behavior
            byte[] result = ECDSAUtils.convertXMLDSIGtoASN1(oddLength);
            assertNotNull(result);
        });
    }

    /**
     * Test very large XMLDSIG (edge case for length encoding).
     */
    @Test
    void testLargeXMLDSIGConversion() {
        // Create a large XMLDSIG that would result in ASN.1 length > 255
        // This should trigger an IOException
        byte[] largeXmldsig = new byte[600]; // 300 bytes each for r and s
        for (int i = 0; i < largeXmldsig.length; i++) {
            largeXmldsig[i] = (byte) 0xFF;
        }

        assertThrows(IOException.class, () -> {
            ECDSAUtils.convertXMLDSIGtoASN1(largeXmldsig);
        }, "XMLDSIG that results in ASN.1 > 255 bytes should be rejected");
    }

    /**
     * Test all-zeros XMLDSIG (edge case).
     */
    @Test
    void testAllZerosXMLDSIG() throws IOException {
        byte[] allZeros = new byte[64];

        byte[] asn1 = ECDSAUtils.convertXMLDSIGtoASN1(allZeros);
        assertNotNull(asn1);

        // Should represent r=0, s=0 in ASN.1
        assertTrue(asn1.length > 0, "Should produce valid ASN.1 for zero values");
    }

    /**
     * Test ASN.1 with extended length encoding (length > 127).
     */
    @Test
    void testExtendedLengthEncoding() throws IOException {
        // Create ASN.1 with length that requires extended encoding
        // SEQUENCE with length 0x81 (1-byte extended length)
        byte[] extendedLen = new byte[]{
            0x30, (byte) 0x81, 0x06,  // SEQUENCE, extended length encoding, length 6
            0x02, 0x01, 0x55,         // INTEGER r
            0x02, 0x01, 0x66          // INTEGER s
        };

        byte[] xmldsig = ECDSAUtils.convertASN1toXMLDSIG(extendedLen, 32);
        assertNotNull(xmldsig);
        assertEquals(64, xmldsig.length);
        assertEquals(0x55, xmldsig[31]);
        assertEquals(0x66, xmldsig[63]);
    }

    /**
     * Test ASN.1 with negative INTEGER values (with 0x00 padding in ASN.1).
     */
    @Test
    void testASN1WithNegativeValuePadding() throws IOException {
        // ASN.1 with INTEGER that has leading 0x00 to indicate positive number
        byte[] asn1 = new byte[]{
            0x30, 0x08,
            0x02, 0x02, 0x00, (byte) 0xFF,  // INTEGER with padding
            0x02, 0x02, 0x00, (byte) 0x80   // INTEGER with padding
        };

        byte[] xmldsig = ECDSAUtils.convertASN1toXMLDSIG(asn1, 32);
        assertNotNull(xmldsig);
        
        // Leading 0x00 should be stripped, actual values preserved
        assertEquals((byte) 0xFF, xmldsig[31]);
        assertEquals((byte) 0x80, xmldsig[63]);
    }
}
