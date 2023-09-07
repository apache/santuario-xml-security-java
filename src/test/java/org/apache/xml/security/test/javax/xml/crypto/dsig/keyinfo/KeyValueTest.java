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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.xml.security.test.javax.xml.crypto.dsig.keyinfo;


import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.KeyValue
 *
 */
class KeyValueTest {

    private static final String[] ALGOS = { "DSA", "RSA" };
    private final KeyInfoFactory fac;
    private final PublicKey keys[];

    public KeyValueTest() throws Exception {
        fac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        // generate PublicKey(s) and XMLStructure(s) for DSA and RSA
        keys = new PublicKey[ALGOS.length];

        for (int i = 0; i < ALGOS.length; i++) {
            keys[i] = genPublicKey(ALGOS[i], 2048);
        }
    }

    @Test
    void testgetPublicKey() {
        try {
            KeyValue kv = fac.newKeyValue(keys[0]);
            assertNotNull(kv.getPublicKey());
        } catch (KeyException ke) {
            fail("Should pass instead of throwing KeyException");
        }
    }

    @Test
    void testConstructor() {
        // test newKeyValue(PublicKey pk)
        for (PublicKey key : keys) {
            try {
                KeyValue kv = fac.newKeyValue(key);
                assertEquals(key, kv.getPublicKey());
            } catch (KeyException ke) {
                fail("Should pass instead of throwing KeyException");
            }
        }
    }

    @Test
    void testisFeatureSupported() {
        KeyValue kv = null;
        try {
            kv = fac.newKeyValue(keys[0]);
            kv.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (KeyException ke) {
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(kv.isFeatureSupported("not supported"));
    }

    private PublicKey genPublicKey(String algo, int keysize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);
        kpg.initialize(keysize, new SecureRandom(("Not so random bytes"
            + System.currentTimeMillis() ).getBytes() ));
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic();
    }

}
