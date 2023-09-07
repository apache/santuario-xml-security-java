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
package org.apache.xml.security.stax.impl.securityToken;

import java.math.BigInteger;

import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

/**
 */
public class X509IssuerSerialSecurityToken extends X509SecurityToken {
    private String issuerName;
    private BigInteger serialNumber;

    protected X509IssuerSerialSecurityToken(
            SecurityTokenConstants.TokenType tokenType, InboundSecurityContext inboundSecurityContext, String id) {
        super(tokenType, inboundSecurityContext, id, SecurityTokenConstants.KeyIdentifier_IssuerSerial, false);
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }
}
