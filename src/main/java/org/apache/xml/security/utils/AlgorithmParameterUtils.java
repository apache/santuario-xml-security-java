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

import org.slf4j.Logger;

import java.security.spec.MGF1ParameterSpec;

/**
 *  Utility class for generating and parsing the {@link java.security.spec.AlgorithmParameterSpec}
 */
public class AlgorithmParameterUtils {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(AlgorithmParameterUtils.class);

    /**
     * Create MGF1ParameterSpec for the given algorithm URI
     * @param mgh1AlgorithmURI the algorithm URI. If null or empty, SHA-1 is used as default MGF1 digest algorithm.
     * @return the MGF1ParameterSpec for the given algorithm URI
     */
    public static MGF1ParameterSpec createMGF1Parameter(String mgh1AlgorithmURI){
        LOG.debug("Creating MGF1ParameterSpec for [{}]", mgh1AlgorithmURI);
        if (mgh1AlgorithmURI == null || mgh1AlgorithmURI.isEmpty()){
            LOG.warn("MGF1 algorithm URI is null or empty. Using SHA-1 as default.");
            return new MGF1ParameterSpec("SHA-1");
        }

        switch (mgh1AlgorithmURI){
            case EncryptionConstants.MGF1_SHA1:
                return new MGF1ParameterSpec("SHA-1");
            case EncryptionConstants.MGF1_SHA224:
                return new MGF1ParameterSpec("SHA-224");
            case EncryptionConstants.MGF1_SHA256:
                return new MGF1ParameterSpec("SHA-256");
            case EncryptionConstants.MGF1_SHA384:
                return new MGF1ParameterSpec("SHA-384");
            case EncryptionConstants.MGF1_SHA512:
                return new MGF1ParameterSpec("SHA-512");
            default:
                LOG.warn("Unsupported MGF algorithm: [{}] Using SHA-1 as default.",  mgh1AlgorithmURI);
                return new MGF1ParameterSpec("SHA-1");
        }
    }

    /**
     * Get the MGF1 algorithm URI for the given MGF1ParameterSpec
     * @param parameterSpec the MGF1ParameterSpec
     * @return the MGF1 algorithm URI for the given MGF1ParameterSpec
     */
    public static String getMgf1URIForParameter(MGF1ParameterSpec parameterSpec) {
        String digestAlgorithm = parameterSpec.getDigestAlgorithm();
        LOG.debug("Get MGF1 URI for digest algorithm [{}]", digestAlgorithm);
        switch (digestAlgorithm) {
            case "SHA-1":
                return EncryptionConstants.MGF1_SHA1;
            case "SHA-224":
                return EncryptionConstants.MGF1_SHA224;
            case "SHA-256":
                return EncryptionConstants.MGF1_SHA256;
            case "SHA-384":
                return EncryptionConstants.MGF1_SHA384;
            case "SHA-512":
                return EncryptionConstants.MGF1_SHA512;
            default:
                LOG.warn("Unknown hash algorithm: [{}]  for MGF1", digestAlgorithm);
                return EncryptionConstants.MGF1_SHA1;
        }
    }

}
