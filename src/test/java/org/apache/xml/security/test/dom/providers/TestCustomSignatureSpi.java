/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright
 * ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and limitations under the License.
 */
package org.apache.xml.security.test.dom.providers;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fake custom SignatureSpi implementation to make sure Custom SignatureSpis are honored
 */
public class TestCustomSignatureSpi extends SignatureSpi {

    private static AtomicInteger signCallCount = new AtomicInteger(0);
    private static AtomicInteger verifyCallCount = new AtomicInteger(0);

    private static PrivateKey privateKeyCaptured = null;

    public static void reset() {
        signCallCount.set(0);
        verifyCallCount.set(0);
        privateKeyCaptured = null;
    }

    public static void verifyCalls() {
        assertNotNull(privateKeyCaptured, "engineInitSign not invoked");
        if (signCallCount.get() == 0) {
            fail("sign was not invoked");
        }
        if (verifyCallCount.get() == 0) {
            fail("verify was not invoked");
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKeyCaptured == null) {
            privateKeyCaptured = privateKey;
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {

    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signCallCount.incrementAndGet() != 1) {
            fail("engineSign called multiple times");
        }
        return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        verifyCallCount.incrementAndGet();
        return true;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
