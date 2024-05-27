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
package org.apache.xml.security.testutils;

import org.apache.xml.security.utils.KeyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.lang.System.Logger.Level.DEBUG;


/**
 * The class provides testing utility methods to test XMLSEC functionality with various JDK version. Where possible
 * we use JDK provided algorithm implementations. However, some algorithms are not supported in lower JDK versions. For example
 * XDH keys were supported from JDK 11, EdDSA keys from JDK 16, etc. To ensure tests are executed for various JDK versions,
 * we need to know which algorithms are supported from particular JDK version.
 *
 * If the existing JDK  security providers do not support the algorithm, the class provides auxiliary security provider (BouncyCastle) to the test
 * xmlsec functionality.
 *
 */
public class KeyTestUtils {
    private static final System.Logger LOG = System.getLogger(KeyTestUtils.class.getName());
    /**
     * The enum of the prepared test keys in resource folder <code>KEY_RESOURCE_PATH</code>.
     */
    public enum TestKeys {
        DSA("dsa.key", "DSA", "1.2.840.10040.4.1"),
        RSA("rsa.key", "RSA", "1.2.840.113549.1.1.1"),
        EC("ec.key", "EC", "1.2.840.10045.2.1"),
        X25519("x25519.key", "XDH", "1.3.101.110"),
        ED25519("ed25519.key", "EdDSA", "1.3.101.112");

        private final String filename;
        private final String algorithm;
        private final String oid;

        TestKeys(String filename, String algorithm, String oid) {
            this.filename = filename;
            this.algorithm = algorithm;
            this.oid = oid;
        }

        public String getFilename() {
            return filename;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public String getOid() {
            return oid;
        }
    }

    private static final String KEY_RESOURCE_PATH = "/org/apache/xml/security/keys/content/";

    public static KeyPair generateKeyPair(KeyUtils.KeyType keyType) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        String keyAlgorithm = keyType.getAlgorithm().getJceName();
        Provider provider = JDKTestUtils.isAlgorithmSupportedByJDK(keyAlgorithm) ? null : JDKTestUtils.getAuxiliaryProvider();
        KeyPairGenerator keyPairGenerator;

        switch (keyType.getAlgorithm()){
            case EC:{
                keyPairGenerator = provider == null ? KeyPairGenerator.getInstance(keyAlgorithm) :
                        KeyPairGenerator.getInstance(keyAlgorithm, provider);
                ECGenParameterSpec kpgparams = new ECGenParameterSpec(keyType.getName());
                keyPairGenerator.initialize(kpgparams);
                break;
            }
            case DSA:
            case RSA:
            case RSASSA_PSS:
            case EdDSA:
            case DH:
            case XDH:{
                keyPairGenerator = provider == null ? KeyPairGenerator.getInstance(keyType.getName()) :
                        KeyPairGenerator.getInstance(keyType.getName(), provider);
                break;
            }
            default:
                throw new IllegalStateException("Unexpected value: " + keyAlgorithm);

        }
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeyPairIfSupported(KeyUtils.KeyType keyType){
        KeyPair keyPair = null;
        try {
            keyPair = generateKeyPair(keyType);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidParameterSpecException e) {
            LOG.log(DEBUG, "Key algorithm [{0}] is not supported! Error message: [{1}]", keyType, e.getMessage());
        }
        return keyPair;
    }

    public static PublicKey loadPublicKey(String keyName, String algorithm) throws Exception {
        byte[] keyBytes = getKeyResourceAsByteArray(keyName);
        KeyFactory kf = JDKTestUtils.isAlgorithmSupportedByJDK(algorithm) ?
                KeyFactory.getInstance(algorithm) : KeyFactory.getInstance(algorithm, JDKTestUtils.getAuxiliaryProvider());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }

    public static byte[] getKeyResourceAsByteArray(String fileName) throws IOException {
        byte[] keyBytes;
        try (InputStream keyIS = getKeyResourceAsInputStream(fileName)){
            keyBytes = new byte[keyIS.available()];
            keyIS.read(keyBytes);
        }
        return Base64.getMimeDecoder().decode(keyBytes);
    }

    public static InputStream getKeyResourceAsInputStream(String fileName) {
        return KeyTestUtils.class.getResourceAsStream(KEY_RESOURCE_PATH + fileName);
    }

}
