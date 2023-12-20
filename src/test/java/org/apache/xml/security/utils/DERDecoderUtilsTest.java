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
package org.apache.xml.security.utils;

import org.apache.xml.security.exceptions.DERDecodingException;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.KeyTestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DERDecoderUtilsTest {
    static {
        org.apache.xml.security.Init.init();
    }

    @AfterEach
    void tearDown() {
        JDKTestUtils.unregisterAuxiliaryProvider();
    }

    @ParameterizedTest
    @EnumSource(KeyTestUtils.TestKeys.class)
    void testGetAlgorithmIdBytesFromKey(KeyTestUtils.TestKeys testKey) throws DERDecodingException, IOException {

        byte[] bytes;
        try (InputStream keyIS = KeyTestUtils.getKeyResourceAsInputStream(testKey.getFilename());
            InputStream keyDecodedIS = Base64.getMimeDecoder().wrap(keyIS)){
            bytes = DERDecoderUtils.getAlgorithmIdBytes(keyDecodedIS);
        }

        String oid = DERDecoderUtils.decodeOID(bytes);
        assertNotNull(bytes);
        assertEquals(testKey.getOid(), oid);
    }

    @ParameterizedTest
    @EnumSource(value = KeyUtils.KeyType.class)
    void testGetAlgorithmIdBytesForGeneratedKeys(KeyUtils.KeyType testKey) throws DERDecodingException {
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(testKey.getAlgorithm().getJceName())) {
            JDKTestUtils.registerAuxiliaryProvider();
        }
        KeyPair keyPair = KeyTestUtils.generateKeyPairIfSupported(testKey);
        Assumptions.assumeTrue(keyPair != null, "Key algorithm [" + testKey + "] not supported by JDK or auxiliary provider! Skipping test.");

        String oid = DERDecoderUtils.getAlgorithmIdFromPublicKey(keyPair.getPublic());
        assertEquals(testKey.getOid(), oid);
    }

    @Test
    void testKeyAlgorithmAndKeySpecificAlgorithm() throws DERDecodingException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyBase64 = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA/VlZpWEJjRyaFJV8abQQMxLNnaKc77MR4qFXZA3jruVRrJOzUFDD7UjcdA8FVciJY4AaEyVwdALtAM3kq4whzp4Apnp8mipZw/5VKRp3cciBr5q8A7sgPZ9qKd5RijvPsedYHIWKOjDKF0KrTx4TdnmhGR3iKqPtDSoXiRlvEYrqx9Y=";
        byte[] publicKeyBytes = Base64.getDecoder().decode(keyBase64);
        KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        byte[] oid = DERDecoderUtils.getAlgorithmIdBytes(new ByteArrayInputStream(publicKeyBytes));
        String keyAlgorithm = DERDecoderUtils.decodeOID(oid);
        String keySpecificAlgorithm = DERDecoderUtils.getAlgorithmIdFromPublicKey(publicKey);
        // expected algorithms
        assertEquals(KeyUtils.KeyAlgorithmType.EC.getOid(), keyAlgorithm);
        assertEquals(KeyUtils.KeyType.SECP521R1.getOid(), keySpecificAlgorithm);
    }
}
