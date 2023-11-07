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

import org.apache.xml.security.Init;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.KeyTestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Unit test for {@link KeyUtils}
 */
class KeyUtilsTest {
    static {
        Init.init();
    }

    /**
     * Test if the ephemeral key is generated with the same algorithm as the original key
     * @param testKey the enumeration  with exiting  keys in resource folder
     * @throws Exception if the key cannot be loaded
     */
    @ParameterizedTest
    @EnumSource(KeyTestUtils.TestKeys.class)
    void generateEphemeralDHKeyPair(KeyTestUtils.TestKeys testKey) throws Exception {
        String keyAlgorithm = testKey.getAlgorithm();
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupported(keyAlgorithm, true), "Algorithm ["
                + keyAlgorithm + "] not supported by JDK or auxiliary provider! Skipping test.");

        PublicKey publicKey = KeyTestUtils.loadPublicKey(testKey.getFilename(), testKey.getAlgorithm());
        // when
        KeyPair ephenmeralKeyPair = KeyUtils.generateEphemeralDHKeyPair(publicKey, JDKTestUtils.isAlgorithmSupportedByJDK(testKey.getAlgorithm()) ?
                null : JDKTestUtils.getAuxiliaryProvider());
        // then
        Assertions.assertNotNull(ephenmeralKeyPair);
        Assertions.assertNotEquals(publicKey, ephenmeralKeyPair.getPublic());
        Assertions.assertEquals(publicKey.getAlgorithm(), ephenmeralKeyPair.getPublic().getAlgorithm());
    }

    /**
     * Test if the ephemeral key is generated with the same algorithm as the original key. The initial keys are generated
     * @param keyType the enumeration  with most common EC and XEC keys
     * @throws Exception if the key cannot be loaded
     */
    @ParameterizedTest
    @EnumSource(value = KeyUtils.KeyType.class)
    void generateEphemeralDHKeyPair(KeyUtils.KeyType keyType) throws Exception {

        Provider testAuxiliaryProvider = JDKTestUtils.isAlgorithmSupportedByJDK(keyType.name()) ? null : JDKTestUtils.getAuxiliaryProvider();
        KeyPair keyPair = KeyTestUtils.generateKeyPairIfSupported(keyType);
        Assumptions.assumeTrue(keyPair != null, "Key algorithm [" + keyType + "] not supported by JDK or auxiliary provider! Skipping test.");


        // test DH key generation
        KeyPair ephenmeralKeyPair = KeyUtils.generateEphemeralDHKeyPair(keyPair.getPublic(), testAuxiliaryProvider);
        String ephemeralKeyOId = DERDecoderUtils.getAlgorithmIdFromPublicKey(ephenmeralKeyPair.getPublic());

        // test if the ephemeral key is generated with the same algorithm as the original key
        Assertions.assertNotNull(ephenmeralKeyPair);
        Assertions.assertNotEquals(keyPair.getPublic(), ephenmeralKeyPair.getPublic());
        Assertions.assertEquals(keyPair.getPublic().getAlgorithm(), ephenmeralKeyPair.getPublic().getAlgorithm());
        Assertions.assertEquals(keyType.getOid(), ephemeralKeyOId);
    }
}
