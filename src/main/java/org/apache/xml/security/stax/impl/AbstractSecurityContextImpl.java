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
package org.apache.xml.security.stax.impl;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import java.util.*;

/**
 */
public class AbstractSecurityContextImpl {
    @SuppressWarnings("unchecked")
    private final Map content = Collections.synchronizedMap(new HashMap());
    private final List<SecurityEventListener> securityEventListeners = new ArrayList<>(2);
    private final XMLSecurityProperties securityProperties;

    public AbstractSecurityContextImpl(XMLSecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    public XMLSecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public void addSecurityEventListener(SecurityEventListener securityEventListener) {
        if (securityEventListener != null) {
            this.securityEventListeners.add(securityEventListener);
        }
    }

    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
        forwardSecurityEvent(securityEvent);
    }

    protected void forwardSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
        for (int i = 0; i < securityEventListeners.size(); i++) {
            SecurityEventListener securityEventListener = securityEventListeners.get(i);
            securityEventListener.registerSecurityEvent(securityEvent);
        }
    }

    @SuppressWarnings("unchecked")
    public <K, T> void put(K key, T value) {
        content.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <K, T> T get(K key) {
        return (T) content.get(key);
    }

    @SuppressWarnings("unchecked")
    public <K, T> T remove(K key) {
        return (T) content.remove(key);
    }

    @SuppressWarnings("unchecked")
    public <K, T extends List> void putList(K key, T value) {
        if (value == null) {
            return;
        }
        List<T> entry = (List<T>) content.get(key);
        if (entry == null) {
            entry = new ArrayList<>();
            content.put(key, entry);
        }
        entry.addAll(value);
    }
}
