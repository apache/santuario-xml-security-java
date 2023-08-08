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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.xml.security.stax.impl.util.IVSplittingOutputStream;
import org.apache.xml.security.stax.impl.util.ReplaceableOuputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
class IVSplittingOutputStreamTest {

    private static final String TEST_STR
        = "Within this class we test if the IVSplittingOutputStream works correctly under different conditions";

    @Test
    void testWriteBytes() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        try (ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream)) {
            ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
            byte[] testBytes = TEST_STR.getBytes();
            for (byte testByte : testBytes) {
                replaceableOuputStream.write(testByte);
            }
        }

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    void testWriteBytesArray() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        try (ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream)) {
            ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
            replaceableOuputStream.write(TEST_STR.getBytes());
        }

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    void testWriteBytesArrayIVLength() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        try (ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream)) {
            ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

            byte[] testBytes = TEST_STR.getBytes();
            for (int i = 0; i < testBytes.length - ivSize; i += ivSize) {
                replaceableOuputStream.write(testBytes, i, ivSize);
            }
            // write last part
            replaceableOuputStream.write(testBytes, testBytes.length - testBytes.length % ivSize,
                testBytes.length % ivSize);
        }

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    void testWriteBytesArrayIVLength2() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        try (ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream)) {
            ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

            byte[] testBytes = TEST_STR.getBytes();
            replaceableOuputStream.write(testBytes, 0, testBytes.length - ivSize);
            // write last part
            replaceableOuputStream.write(testBytes, testBytes.length - ivSize, ivSize);
        }

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    void testWriteBytesArrayWithOffset() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        try (ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream)) {
            ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

            byte[] testBytes = TEST_STR.getBytes();
            for (int i = 0; i < testBytes.length - 4; i += 4) {
                replaceableOuputStream.write(testBytes, i, 4);
            }
            // write last part
            replaceableOuputStream.write(testBytes, testBytes.length - testBytes.length % 4, testBytes.length % 4);
        }

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }
}