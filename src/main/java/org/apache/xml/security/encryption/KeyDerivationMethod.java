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

/**
 * The key derivation is to generate new cryptographic key material from existing key material such as the shared
 * secret and any other (private or public) information. The purpose of the key derivation is an extension of a given
 * but limited set of original key materials and to limit the use (exposure) of such key material.
 *
 * The Schema for KeyDerivationMethod is as follows:
 * <pre>
 * <element name="KeyDerivationMethod" type="xenc:KeyDerivationMethodType"/>
 * <complexType name="KeyDerivationMethodType">
 *   <sequence>
 *     <any namespace="##any" minOccurs="0" maxOccurs="unbounded"/>
 *   </sequence>
 *   <attribute name="Algorithm" type="anyURI" use="required"/>
 * </complexType>
 * </pre>
 */
public interface KeyDerivationMethod {

    /**
     * Returns the algorithm URI of this <code>KeyDerivationMethod</code>.
     *
     * @return the algorithm URI of this <code>KeyDerivationMethod</code>
     */
    String getAlgorithm();
}
