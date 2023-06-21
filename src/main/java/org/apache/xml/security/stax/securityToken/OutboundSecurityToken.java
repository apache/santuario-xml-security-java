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
package org.apache.xml.security.stax.securityToken;

import java.security.Key;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessor;
import org.w3c.dom.Element;

/**
 */
public interface OutboundSecurityToken extends SecurityToken {

    /**
     * Returns the processor responsible for this token
     *
     * @return the processor responsible for this token
     */
    OutputProcessor getProcessor();

    /**
     * Returns the secret key
     *
     * @return The key
     * @throws XMLSecurityException if the key can't be loaded
     */
    Key getSecretKey(String algorithmURI) throws XMLSecurityException;

    void addWrappedToken(OutboundSecurityToken securityToken);

    Element getCustomTokenReference();

}
