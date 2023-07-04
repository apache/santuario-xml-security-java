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
public class IVSplittingOutputStreamTest {

    private static final String TEST_STR
        = "Within this class we test if the IVSplittingOutputStream works correctly under different conditions";

    @Test
    public void testWriteBytes() throws Exception {

        final int ivSize = 16;

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        final ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
        final byte[] testBytes = TEST_STR.getBytes();
        for (final byte testByte : testBytes) {
            replaceableOuputStream.write(testByte);
        }
        replaceableOuputStream.close();

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArray() throws Exception {

        final int ivSize = 16;

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        final ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
        replaceableOuputStream.write(TEST_STR.getBytes());
        replaceableOuputStream.close();

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArrayIVLength() throws Exception {

        final int ivSize = 16;

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        final ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

        final byte[] testBytes = TEST_STR.getBytes();
        for (int i = 0; i < testBytes.length - ivSize; i += ivSize) {
            replaceableOuputStream.write(testBytes, i, ivSize);
        }
        //write last part
        replaceableOuputStream.write(testBytes, testBytes.length - testBytes.length % ivSize, testBytes.length % ivSize);
        replaceableOuputStream.close();

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArrayIVLength2() throws Exception {

        final int ivSize = 16;

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        final ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

        final byte[] testBytes = TEST_STR.getBytes();
        replaceableOuputStream.write(testBytes, 0, testBytes.length - ivSize);
        //write last part
        replaceableOuputStream.write(testBytes, testBytes.length - ivSize, ivSize);
        replaceableOuputStream.close();

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArrayWithOffset() throws Exception {

        final int ivSize = 16;

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        final Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey, ivSize);
        final ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

        final byte[] testBytes = TEST_STR.getBytes();
        for (int i = 0; i < testBytes.length - 4; i += 4) {
            replaceableOuputStream.write(testBytes, i, 4);
        }
        //write last part
        replaceableOuputStream.write(testBytes, testBytes.length - testBytes.length % 4, testBytes.length % 4);
        replaceableOuputStream.close();

        assertEquals(new String(ivSplittingOutputStream.getIv()), TEST_STR.substring(0, ivSize));
        assertEquals(new String(byteArrayOutputStream.toByteArray()), TEST_STR.substring(ivSize));
        assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), TEST_STR);
        assertTrue(ivSplittingOutputStream.isIVComplete());
    }
}