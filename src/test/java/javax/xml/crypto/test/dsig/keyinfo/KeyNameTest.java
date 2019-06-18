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
package javax.xml.crypto.test.dsig.keyinfo;


import javax.xml.crypto.dsig.keyinfo.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.KeyName
 *
 */
public class KeyNameTest {

    private KeyInfoFactory fac;

    public KeyNameTest() throws Exception {
        fac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @org.junit.jupiter.api.Test
    public void testgetName() {
        KeyName kn = fac.newKeyName("skeleton");
        assertNotNull(kn.getName());
    }

    @org.junit.jupiter.api.Test
    public void testConstructor() {
        final String name = "keyName";
        KeyName kn = fac.newKeyName(name);
        assertEquals(name, kn.getName());
        try {
            kn = fac.newKeyName(null);
            fail("Should raise a NullPointerException");
        } catch (NullPointerException npe) {}
    }

    @org.junit.jupiter.api.Test
    public void testisFeatureSupported() {
        KeyName kn = fac.newKeyName("keyName");
        try {
            kn.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(kn.isFeatureSupported("not supported"));
    }
}
