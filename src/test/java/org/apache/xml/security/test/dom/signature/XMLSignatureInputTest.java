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
package org.apache.xml.security.test.dom.signature;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureByteInput;
import org.apache.xml.security.signature.XMLSignatureDigestInput;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureInputDebugger;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test for {@link org.apache.xml.security.signature.XMLSignatureInput}
 *
 * @see <A HREF="http://nagoya.apache.org/bugzilla/show_bug.cgi?id=4336">Bug 4336</A>
 */
class XMLSignatureInputTest {

    private static final String _octetStreamTextInput = "Kleiner Test";
    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testSetOctetStreamGetOctetStream()
        throws IOException, CanonicalizationException, InvalidCanonicalizerException {
        XMLSignatureByteInput input = new XMLSignatureByteInput(_octetStreamTextInput.getBytes(UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // NOPMD: Test checks that input has same content as getter
        InputStream res = input.getUnprocessedInput(); // NOPMD
        int off = 0;
        while (res.available() > 0) {
            byte[] array = new byte[1024];
            int len = res.read(array);
            baos.write(array, off, len);
            off += len;
        }

        byte[] resBytes = baos.toByteArray();
        String resString = new String(resBytes, UTF_8);

        assertEquals(resString, _octetStreamTextInput);
    }

    @Test
    void testIsInitializedWithOctetStream() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput(_octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testOctetStreamIsOctetStream() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testOctetStreamIsNotNodeSet() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testToString() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
        assertTrue(input.toString().startsWith("XMLSignatureByteInput"));
    }

    @Test
    void testHTMLRepresentation() throws IOException, XMLSignatureException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
        assertNotNull(new XMLSignatureInputDebugger(input).getHTMLRepresentation());
    }

    @Test
    void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("Hello world!".getBytes());
        XMLSignatureInput input = new XMLSignatureDigestInput(Base64.getEncoder().encodeToString(digest));
        assertNull(input.getBytes());
    }

    /**
     * Test that empty byte array is handled correctly.
     */
    @Test
    void testEmptyByteArray() throws Exception {
        XMLSignatureInput input = new XMLSignatureByteInput(new byte[0]);
        assertTrue(input.hasUnprocessedInput(), "Should have unprocessed input even if empty");
        
        // Read the empty input
        try (InputStream is = input.getUnprocessedInput()) {
            assertEquals(0, is.available(), "Empty array should have 0 bytes available");
            assertEquals(-1, is.read(), "Reading empty input should return -1");
        }
    }

    /**
     * Test handling of very large byte arrays.
     */
    @Test
    void testLargeByteArray() throws Exception {
        // Create a 10MB byte array
        byte[] largeData = new byte[10 * 1024 * 1024];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte)(i % 256);
        }
        
        XMLSignatureInput input = new XMLSignatureByteInput(largeData);
        assertTrue(input.hasUnprocessedInput());
        
        // Read and verify size
        try (InputStream is = input.getUnprocessedInput()) {
            long count = 0;
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                count += read;
            }
            
            assertEquals(largeData.length, count, "Should read all bytes from large array");
        }
    }

    /**
     * Test that special characters in byte arrays are preserved.
     */
    @Test
    void testSpecialCharactersPreserved() throws Exception {
        // Test with various special characters including null bytes
        byte[] specialBytes = new byte[]{
            0x00, 0x01, 0x02, (byte)0xFF, (byte)0xFE, 
            0x0A, 0x0D, 0x20, 0x7F, (byte)0x80
        };
        
        XMLSignatureInput input = new XMLSignatureByteInput(specialBytes);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = input.getUnprocessedInput()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
        }
        
        byte[] result = baos.toByteArray();
        assertEquals(specialBytes.length, result.length, "Length should match");
        
        for (int i = 0; i < specialBytes.length; i++) {
            assertEquals(specialBytes[i], result[i], 
                "Byte at index " + i + " should be preserved");
        }
    }

    /**
     * Test handling of UTF-8 boundary cases.
     */
    @Test
    void testUTF8BoundaryCases() throws Exception {
        // Test with various UTF-8 encodings including multi-byte characters
        String testString = "Test: \u00E9\u00FC\u4E2D\u6587\uD83D\uDE00"; // Latin, Chinese, emoji
        byte[] utf8Bytes = testString.getBytes(UTF_8);
        
        XMLSignatureInput input = new XMLSignatureByteInput(utf8Bytes);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = input.getUnprocessedInput()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
        }
        
        String result = new String(baos.toByteArray(), UTF_8);
        assertEquals(testString, result, "UTF-8 characters should be preserved");
    }

    /**
     * Test that malformed UTF-8 sequences are preserved as bytes.
     */
    @Test
    void testMalformedUTF8Preserved() throws Exception {
        // Invalid UTF-8 sequences
        byte[] malformedUTF8 = new byte[]{
            0x41, 0x42, (byte)0xFF, (byte)0xFE, 0x43  // Valid ASCII + invalid UTF-8 + valid ASCII
        };
        
        XMLSignatureInput input = new XMLSignatureByteInput(malformedUTF8);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = input.getUnprocessedInput()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
        }
        
        byte[] result = baos.toByteArray();
        assertEquals(malformedUTF8.length, result.length);
        
        for (int i = 0; i < malformedUTF8.length; i++) {
            assertEquals(malformedUTF8[i], result[i], 
                "Malformed UTF-8 bytes should be preserved as-is");
        }
    }

    /**
     * Test that input stream can be read multiple times if supported.
     */
    @Test
    void testMultipleReads() throws Exception {
        byte[] data = "Test data for multiple reads".getBytes(UTF_8);
        XMLSignatureInput input = new XMLSignatureByteInput(data);
        
        // First read
        ByteArrayOutputStream baos1 = new ByteArrayOutputStream();
        try (InputStream is1 = input.getUnprocessedInput()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is1.read(buffer)) != -1) {
                baos1.write(buffer, 0, read);
            }
        }
        
        String result1 = new String(baos1.toByteArray(), UTF_8);
        assertEquals("Test data for multiple reads", result1);
        
        // Second read should get fresh stream
        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        try (InputStream is2 = input.getUnprocessedInput()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = is2.read(buffer)) != -1) {
                baos2.write(buffer, 0, read);
            }
        }
        
        String result2 = new String(baos2.toByteArray(), UTF_8);
        assertEquals("Test data for multiple reads", result2, 
            "Multiple reads should return same data");
    }

    /**
     * Test handling of empty digest string.
     */
    @Test
    void testEmptyDigestString() throws Exception {
        XMLSignatureInput input = new XMLSignatureDigestInput("");
        assertNull(input.getBytes(), "Digest input should not have bytes");
    }
}
