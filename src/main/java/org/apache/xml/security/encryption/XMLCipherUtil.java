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
package org.apache.xml.security.encryption;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.apache.xml.security.utils.ClassLoaderUtils;
import org.apache.xml.security.utils.EncryptionConstants;

public final class XMLCipherUtil {

    private static org.slf4j.Logger log = 
        org.slf4j.LoggerFactory.getLogger(XMLCipherUtil.class);
    
    private static final boolean gcmUseIvParameterSpec =
        AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                return Boolean.getBoolean
                    ("org.apache.xml.security.cipher.gcm.useIvParameterSpec");
            }
        });
    
    /**
     * Build an <code>AlgorithmParameterSpec</code> instance used to initialize a <code>Cipher</code> instance
     * for block cipher encryption and decryption.
     * 
     * @param algorithm the XML encryption algorithm URI
     * @param iv the initialization vector
     * @return the newly constructed AlgorithmParameterSpec instance, appropriate for the
     *         specified algorithm
     */
    public static AlgorithmParameterSpec constructBlockCipherParameters(String algorithm, byte[] iv, Class<?> callingClass) {
        if (EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM.equals(algorithm)
                || EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM.equals(algorithm)
                || EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM.equals(algorithm)) {
            return constructBlockCipherParametersForGCMAlgorithm(algorithm, iv, callingClass);
        } else {
            log.debug("Saw non-AES-GCM mode block cipher, returning IvParameterSpec: {}", algorithm);
            return new IvParameterSpec(iv);
        }
    }

    public static AlgorithmParameterSpec constructBlockCipherParameters(boolean gcmAlgorithm, byte[] iv, Class<?> callingClass) {
        if (gcmAlgorithm) {
            return constructBlockCipherParametersForGCMAlgorithm("AES/GCM/NoPadding", iv, callingClass);
        } else {
            log.debug("Saw non-AES-GCM mode block cipher, returning IvParameterSpec");
            return new IvParameterSpec(iv);
        }
    }
    
    private static AlgorithmParameterSpec constructBlockCipherParametersForGCMAlgorithm(String algorithm, byte[] iv, Class<?> callingClass) {
        if (gcmUseIvParameterSpec) {
            // This override allows to support Java 1.7+ with (usually older versions of) third-party security 
            // providers which support or even require GCM via IvParameterSpec rather than GCMParameterSpec,
            // e.g. BouncyCastle <= 1.49 (really <= 1.50 due to a semi-related bug).
            log.debug("Saw AES-GCM block cipher, using IvParameterSpec due to system property override: {}", algorithm);
            return new IvParameterSpec(iv);
        }
        
        log.debug("Saw AES-GCM block cipher, attempting to create GCMParameterSpec: {}", algorithm);
        
        try {
            // This class only added in Java 1.7. So load reflectively until Santuario starts targeting a minimum of Java 1.7. 
            Class<?> gcmSpecClass = ClassLoaderUtils.loadClass("javax.crypto.spec.GCMParameterSpec", callingClass);
            
            // XML Encryption 1.1 mandates a 128-bit Authentication Tag for AES GCM modes.
            AlgorithmParameterSpec gcmSpec = (AlgorithmParameterSpec) gcmSpecClass.getConstructor(int.class, byte[].class)
                    .newInstance(128, iv);
            log.debug("Successfully created GCMParameterSpec");
            return gcmSpec;
        } catch (Exception e) {
            // This handles the case of Java < 1.7 with a third-party security provider that 
            // supports GCM mode using only an IvParameterSpec, such as BouncyCastle.
            log.debug("Failed to create GCMParameterSpec, falling back to returning IvParameterSpec", e);
            return new IvParameterSpec(iv);
        }
    }
}
