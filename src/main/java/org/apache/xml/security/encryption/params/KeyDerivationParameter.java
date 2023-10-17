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
package org.apache.xml.security.encryption.params;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class contains the basic parameters used for key derivation.
 */
public class KeyDerivationParameter implements AlgorithmParameterSpec {
    protected final String algorithm;
    protected final int keyBitLength;

    public KeyDerivationParameter(String algorithm, int keyLength) {
        this.algorithm = algorithm;
        this.keyBitLength = keyLength;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeyBitLength() {
        return keyBitLength;
    }
}
