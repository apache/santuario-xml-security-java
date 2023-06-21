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

import java.util.List;
import java.util.Map;

import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

/**
 */
public interface SecurityContext extends SecurityEventListener {
    <T> void put(String key, T value);

    <T> T get(String key);

    <T> T remove(String key);

    <T extends List> void putList(Object key, T value);

    <T> void putAsList(Object key, T value);

    <T> List<T> getAsList(Object key);

    <T, U> void putAsMap(Object key, T mapKey, U mapValue);

    <T, U> Map<T, U> getAsMap(Object key);

    /**
     * Registers a SecurityEventListener to receive Security-Events
     *
     * @param securityEventListener The SecurityEventListener
     */
    void addSecurityEventListener(SecurityEventListener securityEventListener);
}
