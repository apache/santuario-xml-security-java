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

import org.junit.jupiter.api.Test;

import org.apache.xml.security.stax.impl.util.TrimmerOutputStream;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 */
public class TrimmerOutputStreamTest {

    private static final String TEST_STR
        = "Within this class we test if the TrimmerOutputStream works correctly under different conditions";

    @Test
    public void testWriteSingleBytes() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TrimmerOutputStream trimmerOutputStream = new TrimmerOutputStream(baos, 32, 3, 4);

        byte[] TEST_STRBytes = ("<a>" + TEST_STR + "</a>").getBytes();
        for (int i = 0; i < TEST_STRBytes.length; i++) {
            trimmerOutputStream.write(TEST_STRBytes[i]);
        }
        trimmerOutputStream.close();

        assertEquals(baos.size(), TEST_STRBytes.length - 7);
        assertEquals(baos.toString(), TEST_STR);
    }

    @Test
    public void testWriteRandomByteSizes() throws Exception {
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
}