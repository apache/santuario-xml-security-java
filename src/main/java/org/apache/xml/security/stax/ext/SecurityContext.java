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
package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import java.util.List;

/**
 */
public interface SecurityContext extends SecurityEventListener {

    XMLSecurityProperties getSecurityProperties();

    <K, T> void put(K key, T value);

    <K, T> T get(K key);

    <K, T> T remove(K key);

    <K, T extends List> void putList(K key, T value);

    /**
     * Registers a SecurityEventListener to receive Security-Events
     *
     * @param securityEventListener The SecurityEventListener
     */
    void addSecurityEventListener(SecurityEventListener securityEventListener);
}
