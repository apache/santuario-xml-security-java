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
package org.apache.xml.security.stax.impl.util;

import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.impl.algorithms.SignatureAlgorithm;

/**
 */
public class SignerOutputStream extends OutputStream {

    private static final Logger LOG = System.getLogger(SignerOutputStream.class.getName());
    protected static final transient boolean isDebugEnabled = LOG.isLoggable(Level.DEBUG);

    private final SignatureAlgorithm signatureAlgorithm;
    private StringBuilder stringBuilder; //NOPMD

    public SignerOutputStream(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        if (isDebugEnabled) {
            stringBuilder = new StringBuilder();
        }
    }

    @Override
    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    @Override
    public void write(int arg0) {
        try {
            byte asByte = (byte) arg0;
            signatureAlgorithm.engineUpdate(asByte);
            if (isDebugEnabled) {
                stringBuilder.append((char)asByte);
            }
        } catch (XMLSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void write(byte[] arg0, int arg1, int arg2) {
        try {
            signatureAlgorithm.engineUpdate(arg0, arg1, arg2);
            if (isDebugEnabled) {
                stringBuilder.append(new String(arg0, arg1, arg2, java.nio.charset.StandardCharsets.UTF_8));
            }
        } catch (XMLSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(byte[] signatureValue) throws XMLSecurityException {
        if (isDebugEnabled) {
            LOG.log(Level.DEBUG, "Pre Signed: ");
            LOG.log(Level.DEBUG, stringBuilder.toString());
            LOG.log(Level.DEBUG, "End pre Signed ");
            stringBuilder = new StringBuilder();
        }
        return signatureAlgorithm.engineVerify(signatureValue);
    }

    public byte[] sign() throws XMLSecurityException {
        if (isDebugEnabled) {
            LOG.log(Level.DEBUG, "Pre Signed: ");
            LOG.log(Level.DEBUG, stringBuilder.toString());
            LOG.log(Level.DEBUG, "End pre Signed ");
            stringBuilder = new StringBuilder();
        }
        return signatureAlgorithm.engineSign();
    }
}
