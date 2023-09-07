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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.X509Data
 *
 */
class X509DataTest {

    private final KeyInfoFactory fac;

    public X509DataTest() throws Exception {
        fac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @Test
    void testgetTypes() {
        X509Data x509 = fac.newX509Data(Collections.singletonList("cn=foo"));
        List<?> li = x509.getContent();
        assertNotNull(li);
        if (!li.isEmpty()) {
            Object[] content = li.toArray();
            for (Object element : content) {
                if (!(element instanceof String) &&
                    !(element instanceof byte[]) &&
                    !(element instanceof X509Certificate) &&
                    !(element instanceof X509CRL) &&
                    !(element instanceof XMLStructure)) {
                    fail("X509 element has the wrong type");
                }
            }
        }
    }

    @Test
    void testConstructor() {
        // test newX509Data()
        X509Data x509 = fac.newX509Data(Collections.singletonList("cn=foo"));
        assertNotNull(x509);
    }

    @Test
    void testisFeatureSupported() {

        X509Data x509 = fac.newX509Data(Collections.singletonList("cn=foo"));
        try {
            x509.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(x509.isFeatureSupported("not supported"));
    }
}
