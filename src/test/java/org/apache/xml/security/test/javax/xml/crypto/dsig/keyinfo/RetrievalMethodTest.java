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


import javax.xml.crypto.dsig.keyinfo.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.RetrievalMethod
 *
 */
public class RetrievalMethodTest {

    private KeyInfoFactory fac;

    public RetrievalMethodTest() throws Exception {
        fac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @org.junit.jupiter.api.Test
    public void testgetURI() {
        RetrievalMethod rm = fac.newRetrievalMethod("#X509Data");
        assertNotNull(rm.getURI());
    }

    @org.junit.jupiter.api.Test
    public void testgetTransforms() {
        RetrievalMethod rm = fac.newRetrievalMethod("#X509Data");
        assertNotNull(rm.getTransforms());
    }

    @org.junit.jupiter.api.Test
    public void testgetType() {
        RetrievalMethod rm = fac.newRetrievalMethod("#X509Data");
        assertNull(rm.getType());
    }

    @org.junit.jupiter.api.Test
    public void testConstructors() {
        final String uri = "#X509CertChain";
        // test RetrievalMethod(String)
        RetrievalMethod rm = fac.newRetrievalMethod(uri);
        assertEquals(uri, rm.getURI());

        try {
            rm = fac.newRetrievalMethod(null);
            fail("Should raise a NullPointerException");
        } catch (NullPointerException npe) {}

        // test RetrievalMethod(String, String, Transform[])
        try {
            rm = fac.newRetrievalMethod(null, null, null);
            fail("Should raise a NullPointerException");
        } catch (NullPointerException npe) {}

        final String type = "http://www.w3.org/2000/09/xmldsig#X509Data";
        rm = fac.newRetrievalMethod(uri, type, null);
        assertEquals(uri, rm.getURI());
        assertEquals(type, rm.getType());
    }

    @org.junit.jupiter.api.Test
    public void testisFeatureSupported() throws Exception {
        String uri = "#X509CertChain";
        String type = "http://www.w3.org/2000/09/xmldsig#X509Data";
        RetrievalMethod rm = null;
        for (int i = 0; i < 2; i++) {
            if (i == 0) {
                rm = fac.newRetrievalMethod(uri);
            } else if (i == 1) {
                rm = fac.newRetrievalMethod(uri, type, null);
            }
            try {
                rm.isFeatureSupported(null);
                fail("Should raise a NPE for null feature");
            } catch (NullPointerException npe) {}

            assertFalse(rm.isFeatureSupported("not supported"));
        }
    }
}
