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
package org.apache.xml.security.stax.impl.algorithms;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;

/**
 */
public final class SignatureAlgorithmFactory {

    private static SignatureAlgorithmFactory instance;

    private SignatureAlgorithmFactory() {
    }

    public static synchronized SignatureAlgorithmFactory getInstance() {
        if (instance == null) {
            instance = new SignatureAlgorithmFactory();
        }
        return instance;
    }

    public SignatureAlgorithm getSignatureAlgorithm(String algoURI) throws XMLSecurityException, NoSuchProviderException, NoSuchAlgorithmException {
        String algorithmClass = JCEAlgorithmMapper.getAlgorithmClassFromURI(algoURI);
        if (algorithmClass == null) {
            throw new XMLSecurityException("algorithms.NoSuchMap",
                                           new Object[] {algoURI});
        }
        String jceName = JCEAlgorithmMapper.translateURItoJCEID(algoURI);
        String jceProvider = JCEAlgorithmMapper.getJCEProviderFromURI(algoURI);
        if ("MAC".equalsIgnoreCase(algorithmClass)) {
            return new HMACSignatureAlgorithm(jceName, jceProvider);
        } else if ("Signature".equalsIgnoreCase(algorithmClass)) {
            return new PKISignatureAlgorithm(jceName, jceProvider);
        } else {
            return null;
        }
    }
}
