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

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.DigestMethod
 *
 */
class DigestMethodTest {

    private final XMLSignatureFactory factory;

    private static final String[] MD_ALGOS = {
        DigestMethod.SHA1
    };

    public DigestMethodTest() {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @Test
    void testisFeatureSupported() throws Exception {
        DigestMethod dm;
        for (String algo : MD_ALGOS) {
            dm = factory.newDigestMethod(algo, null);
            try {
                dm.isFeatureSupported(null);
                fail("Should raise a NPE for null feature");
            } catch (NullPointerException npe) {}
            assertFalse(dm.isFeatureSupported("not supported"));
        }
    }

    @Test
    void testConstructor() throws Exception {
        // test DSigStructureFactory.newDigestMethod
        // (String algorithm, AlgorithmParameterSpec params)
        // for generating DigestMethod objects
        DigestMethod dm;
        for (String algo : MD_ALGOS) {
            dm = factory.newDigestMethod(algo, null);
            assertEquals(dm.getAlgorithm(), algo);

            assertNull(dm.getParameterSpec());
            try {
                dm = factory.newDigestMethod(algo,
                                  new TestUtils.MyOwnDigestMethodParameterSpec());
                fail("Should raise an IAPE for invalid parameters");
            } catch (InvalidAlgorithmParameterException iape) {
            } catch (Exception ex) {
                fail("Should raise an IAPE instead of " + ex);
            }
        }

        try {
            dm = factory.newDigestMethod("non-existent",
                                         null);
            fail("Should raise an NSAE for non-existent algos");
        } catch (NoSuchAlgorithmException nsae) {}

        try {
            dm = factory.newDigestMethod(null, null);
            fail("Should raise a NPE for null algo");
        } catch (NullPointerException npe) {
            //
        }
    }

}
