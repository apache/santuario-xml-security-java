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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.SignatureMethod
 *
 */
class SignatureMethodTest {

    XMLSignatureFactory factory;

    private static final String[] SIG_ALGOS = {
        SignatureMethod.DSA_SHA1,
        SignatureMethod.RSA_SHA1,
        SignatureMethod.HMAC_SHA1
    };

    public SignatureMethodTest() throws Exception {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @Test
    void testisFeatureSupported() throws Exception {
        SignatureMethod sm;
        for (String algo : SIG_ALGOS) {
            sm = factory.newSignatureMethod(algo, null);
            try {
                sm.isFeatureSupported(null);
                fail("Should raise a NPE for null feature");
            } catch (NullPointerException npe) {}

            assertFalse(sm.isFeatureSupported("not supported"));
        }
    }

    @Test
    void testConstructor() throws Exception {
        // test XMLSignatureFactory.newAlgorithmMethod
        // (String algorithm, AlgorithmParameterSpec params)
        // for generating SignatureMethod objects
        SignatureMethod sm;
        for (String algo : SIG_ALGOS) {
            sm = factory.newSignatureMethod(algo, null);
            assertEquals(sm.getAlgorithm(), algo);

            assertNull(sm.getParameterSpec());
            try {
                sm = factory.newSignatureMethod
                    (algo, new TestUtils.MyOwnSignatureMethodParameterSpec());
                fail("Should raise an IAPE for invalid parameters");
            } catch (InvalidAlgorithmParameterException iape) {
            } catch (Exception ex) {
                fail("Should raise an IAPE instead of " + ex);
            }
        }

        try {
            sm = factory.newSignatureMethod("non-existent", null);
            fail("Should raise an NSAE for non-existent algos");
        } catch (NoSuchAlgorithmException nsae) {
            //
        }

        try {
            sm = factory.newSignatureMethod(null, null);
            fail("Should raise a NPE for null algo");
        } catch (NullPointerException npe) {
            //
        }
    }

}
