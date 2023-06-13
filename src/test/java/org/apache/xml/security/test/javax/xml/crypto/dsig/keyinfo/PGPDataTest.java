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


import java.util.ArrayList;
import java.util.List;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.keyinfo.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.PGPData
 *
 */
public class PGPDataTest {

    private KeyInfoFactory fac;
    private byte[][] values = {
        {
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        },
        {
            (byte)0xc6, (byte)0x01, (byte)0x00
        }
    };

    public PGPDataTest() throws Exception {
        fac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @SuppressWarnings("rawtypes")
    @org.junit.jupiter.api.Test
    public void testgetExternalElements() {
        PGPData[] pds = {
            fac.newPGPData(values[0]),
            fac.newPGPData(values[0], values[1], null),
            fac.newPGPData(values[1], null)
        };
        for (int i = 0; i<pds.length; i++) {
            @SuppressWarnings("unchecked")
            List<XMLStructure> li = pds[i].getExternalElements();
            assertNotNull(li);
            if (!li.isEmpty()) {
                Object[] types = li.toArray();
                for (int j = 0; j < types.length; j++) {
                    if (!(types[j] instanceof XMLStructure)) {
                        fail("PGP element has the wrong type");
                    }
                }
            }
        }
        try {
            // use raw List type to test for invalid entries
            List invalidData = new ArrayList();
            addEntryToRawList(invalidData, new Object());
            fac.newPGPData(values[0], invalidData);
            fail("Added PGP element of wrong type");
        } catch (ClassCastException ex) {
            // expected
        }
    }

    @org.junit.jupiter.api.Test
    public void testgetKeyId() {
        PGPData pd = fac.newPGPData(values[0]);
        assertNotNull(pd.getKeyId());
        pd = fac.newPGPData(values[0], values[1], null);
        assertNotNull(pd.getKeyId());
        pd = fac.newPGPData(values[1], null);
    }

    @org.junit.jupiter.api.Test
    public void testgetKeyPacket() {
        PGPData pd = fac.newPGPData(values[0]);
        pd = fac.newPGPData(values[0], values[1], null);
        assertNotNull(pd.getKeyPacket());
        pd = fac.newPGPData(values[1], null);
        assertNotNull(pd.getKeyPacket());
    }

    @org.junit.jupiter.api.Test
    public void testConstructor() {
        // test newPGPKeyData(byte[])
        PGPData pd = fac.newPGPData(values[0]);
        assertArrayEquals(values[0], pd.getKeyId());

        // test newPGPData(byte[], byte[], List)
        pd = fac.newPGPData(values[0], values[1], null);
        assertArrayEquals(values[0], pd.getKeyId());
        assertArrayEquals(values[1], pd.getKeyPacket());

        // test newPGPData(byte[], List)
        pd = fac.newPGPData(values[1], null);
        assertArrayEquals(values[1], pd.getKeyPacket());
    }

    @org.junit.jupiter.api.Test
    public void testisFeatureSupported() {
        PGPData pd = null;
        for (int i = 0; i < 3; i++) {
            if (i == 0) {
                pd = fac.newPGPData(values[0]);
            } else if (i == 1) {
                pd = fac.newPGPData(values[0], values[1], null);
            } else {
                pd = fac.newPGPData(values[1], null);
            }
            try {
                pd.isFeatureSupported(null);
                fail("Should raise a NPE for null feature");
            } catch (NullPointerException npe) {}

            assertFalse(pd.isFeatureSupported("not supported"));
        }
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }
}
