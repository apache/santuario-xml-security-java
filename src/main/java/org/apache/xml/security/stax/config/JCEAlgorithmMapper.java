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
package org.apache.xml.security.stax.config;

import java.util.List;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.configuration.AlgorithmType;
import org.apache.xml.security.configuration.JCEAlgorithmMappingsType;

/**
 * Mapping between JCE id and xmlsec uri's for algorithms
 */
public final class JCEAlgorithmMapper extends JCEMapper {

    private JCEAlgorithmMapper() {
    }

    protected static synchronized void init(JCEAlgorithmMappingsType jceAlgorithmMappingsType) throws Exception {
        List<AlgorithmType> algorithms = jceAlgorithmMappingsType.getAlgorithm();

        for (AlgorithmType algorithmType : algorithms) {
            int keyLength = 0;
            if (algorithmType.getKeyLength() != null) {
                keyLength = algorithmType.getKeyLength();
            }
            int ivLength = 0;
            if (algorithmType.getIVLength() != null) {
                ivLength = algorithmType.getIVLength();
            }
            Algorithm algorithm =
                new Algorithm(algorithmType.getRequiredKey(), algorithmType.getJCEName(),
                              algorithmType.getAlgorithmClass(), keyLength,
                              ivLength, algorithmType.getJCEProvider());

            register(algorithmType.getURI(), algorithm);
        }
    }

}
