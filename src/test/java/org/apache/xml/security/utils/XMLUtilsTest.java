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
package org.apache.xml.security.utils;

import org.apache.xml.security.formatting.FormattingChecker;
import org.apache.xml.security.formatting.FormattingCheckerFactory;
import org.apache.xml.security.formatting.FormattingTest;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This test checks {@link XMLUtils} class methods, responsible for Base64 values formatting in XML documents.
 * This is a {@link FormattingTest}, it is expected to be run with different system properties
 * to check various formatting configurations.
 *
 * There are three methods producing Base64-encoded data in {@code XMLUtils}:
 * <ul>
 *     <li>{@link XMLUtils#encodeToString(byte[])}</li>
 *     <li>{@link XMLUtils#encodeElementValue(byte[])}</li>
 *     <li>{@link XMLUtils#encodeStream(OutputStream)}</li> (creates a wrapper stream, which applies the same encoding
 *         as {@code encodeToString(byte[])})
 * </ul>
 * Output of the first two methods is checked using an appropriate {@link FormattingChecker} implementation.
 * The result of stream encoding is compared to the output of {@code encodeToString} method.
 *
 * There are also tests which check that the corresponding decoding methods can process Base64-encoded data with any
 * formatting regardless of formatting options.
 */
@FormattingTest
public class XMLUtilsTest {

    private FormattingChecker formattingChecker = FormattingCheckerFactory.getFormattingChecker();

    /* Base64 encoding of the following bytes is: AQIDBAUGBwg= */
    private static final byte[] TEST_DATA = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    @Test
    public void testEncodeToString() {
        byte[] data = new byte[60]; // long enough for a line break in MIME encoding
        String encoded = XMLUtils.encodeToString(data);
        formattingChecker.checkBase64Value(encoded);
    }

    @Test
    public void testEncodeToStringShort() {
        byte[] data = new byte[8];
        String encoded = XMLUtils.encodeToString(data);
        formattingChecker.checkBase64Value(encoded);
    }

    @Test
    public void testEncodeElementValue() {
        byte[] data = new byte[60]; // long enough for a line break in MIME encoding
        String encoded = XMLUtils.encodeElementValue(data);
        formattingChecker.checkBase64ValueWithSpacing(encoded);
    }

    @Test
    public void testEncodeElementValueShort() {
        byte[] data = new byte[8];
        String encoded = XMLUtils.encodeElementValue(data);
        formattingChecker.checkBase64ValueWithSpacing(encoded);
    }

    @Test
    public void testEncodeUsingStream() throws IOException {
        byte[] data = new byte[60];
        String expected = XMLUtils.encodeToString(data);
        String encodedWithStream;
        try (ByteArrayOutputStream encoded = new ByteArrayOutputStream();
             OutputStream raw = XMLUtils.encodeStream(encoded)) {
            raw.write(data);
            raw.flush();
            encodedWithStream = encoded.toString(StandardCharsets.US_ASCII);
        }

        assertEquals(expected, encodedWithStream);
    }

    @Test
    public void decodeNoLineBreaks() {
        String encoded = "AQIDBAUGBwg=";

        byte[] data = XMLUtils.decode(encoded);
        assertArrayEquals(TEST_DATA, data);

        data = XMLUtils.decode(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(TEST_DATA, data);
    }

    @Test
    public void decodeCrlfLineBreaks() {
        String encoded = "AQIDBAUG\r\nBwg=";

        byte[] data = XMLUtils.decode(encoded);
        assertArrayEquals(TEST_DATA, data);

        data = XMLUtils.decode(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(TEST_DATA, data);
    }

    @Test
    public void decodeLfLineBreaks() {
        String encoded = "AQIDBAUG\nBwg=";

        byte[] data = XMLUtils.decode(encoded);
        assertArrayEquals(TEST_DATA, data);

        data = XMLUtils.decode(encoded.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(TEST_DATA, data);
    }

    @Test
    public void decodeStream() throws IOException {
        byte[] encodedBytes = "AQIDBAUGBwg=".getBytes(StandardCharsets.US_ASCII);

        try (InputStream decoded = XMLUtils.decodeStream(new ByteArrayInputStream(encodedBytes))) {
            assertArrayEquals(TEST_DATA, decoded.readAllBytes());
        }
    }
}
