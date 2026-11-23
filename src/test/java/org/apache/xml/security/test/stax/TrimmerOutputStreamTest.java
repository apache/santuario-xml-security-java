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
package org.apache.xml.security.test.stax;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import org.apache.xml.security.stax.impl.util.TrimmerOutputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 */
class TrimmerOutputStreamTest {

    private static final String TEST_STR
        = "Within this class we test if the TrimmerOutputStream works correctly under different conditions";

    @Test
    void testWriteSingleBytes() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TrimmerOutputStream trimmerOutputStream = new TrimmerOutputStream(baos, 32, 3, 4);

        byte[] TEST_STRBytes = ("<a>" + TEST_STR + "</a>").getBytes();
        for (byte test_STRByte : TEST_STRBytes) {
            trimmerOutputStream.write(test_STRByte);
        }
        trimmerOutputStream.close();

        assertEquals(baos.size(), TEST_STRBytes.length - 7);
        assertEquals(baos.toString(), TEST_STR);
    }

    @Test
    void testWriteRandomByteSizes() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TrimmerOutputStream trimmerOutputStream = new TrimmerOutputStream(baos, 32, 3, 4);

        StringBuilder stringBuffer = new StringBuilder("<a>");
        for (int i = 0; i < 100; i++) {
            stringBuffer.append(TEST_STR);
        }
        stringBuffer.append("</a>");

        byte[] TEST_STRBytes = stringBuffer.toString().getBytes();

        int written = 0;
        int count = 0;
        do {
            count++;
            trimmerOutputStream.write(TEST_STRBytes, written, count);
            written += count;
        }
        while ((written + count + 1) < TEST_STRBytes.length);

        trimmerOutputStream.write(TEST_STRBytes, written, TEST_STRBytes.length - written);
        trimmerOutputStream.close();

        assertEquals(baos.size(), TEST_STRBytes.length - 7);
        assertEquals(baos.toString(), stringBuffer.toString().substring(3, stringBuffer.length() - 4));
    }

    /**
     * A write shorter than the end trim length that does not fit in the remaining buffer space
     * must keep the trailing bytes across the buffer and the new data.
     */
    @Test
    void testShortWriteWhenBufferNearlyFull() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TrimmerOutputStream trimmerOutputStream = new TrimmerOutputStream(baos, 32, 3, 4);

        byte[] data = ("<a>" + TEST_STR + "</a>").getBytes(StandardCharsets.UTF_8);
        // 3 trimmed + 30 buffered, leaving 2 bytes of space; then write 2 bytes (< end trim length 4)
        trimmerOutputStream.write(data, 0, 33);
        trimmerOutputStream.write(data, 33, 2);
        trimmerOutputStream.write(data, 35, data.length - 35);
        trimmerOutputStream.close();

        assertEquals(TEST_STR, baos.toString(StandardCharsets.UTF_8));
    }

    /**
     * Random chunk sizes, including writes smaller than the end trim length, must always produce
     * the input without its first startTrimLength and last endTrimLength bytes.
     */
    @Test
    void testRandomChunkSizes() throws Exception {
        Random random = new Random(42);
        for (int run = 0; run < 2000; run++) {
            int bufferSize = 4 + random.nextInt(20);
            int startTrim = random.nextInt(5);
            int endTrim = random.nextInt(Math.min(bufferSize, 6) + 1);
            byte[] data = new byte[startTrim + endTrim + random.nextInt(200)];
            random.nextBytes(data);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            TrimmerOutputStream trimmerOutputStream =
                new TrimmerOutputStream(baos, bufferSize, startTrim, endTrim);
            int written = 0;
            while (written < data.length) {
                if (random.nextInt(4) == 0) {
                    trimmerOutputStream.write(data[written++]);
                } else {
                    int len = Math.min(data.length - written, random.nextInt(2 * bufferSize + 1));
                    trimmerOutputStream.write(data, written, len);
                    written += len;
                }
            }
            trimmerOutputStream.close();

            byte[] expected = Arrays.copyOfRange(data, startTrim, data.length - endTrim);
            assertArrayEquals(expected, baos.toByteArray(),
                "bufferSize=" + bufferSize + " startTrim=" + startTrim + " endTrim=" + endTrim);
        }
    }
}
