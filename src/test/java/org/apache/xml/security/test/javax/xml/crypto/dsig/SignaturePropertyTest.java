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


import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.SignatureProperty
 *
 */
public class SignaturePropertyTest {

    private final XMLSignatureFactory factory;
    private final String target = "target";
    private final String id = "id";

    public SignaturePropertyTest() throws Exception {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @SuppressWarnings("rawtypes")
    @Test
    public void testConstructor() {
        // test XMLSignatureFactory.newSignatureProperty(List, String, String)
        SignatureProperty prop;

        try {
            prop = factory.newSignatureProperty(null, target, id);
            fail("Should raise a NPE for null content");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should raise a NPE for null content instead of " + ex);
        }
        List<XMLStructure> list = new ArrayList<>();
        try {
            prop = factory.newSignatureProperty(list, target, id);
            fail("Should raise an IAE for empty content");
        } catch (IllegalArgumentException iae) {
        } catch (Exception ex) {
            fail("Should raise an IAE for empty content instead of " + ex);
        }
        String strEntry = "wrong type";
        // use raw List type to test for invalid XMLStructure entries
        List invalidList = new ArrayList();
        addEntryToRawList(invalidList, strEntry);
        try {
            factory.newSignatureProperty(invalidList, target, id);
            fail("Should raise a CCE for content containing " +
                 "invalid, i.e. non-XMLStructure, entries");
        } catch (ClassCastException cce) {
        } catch (Exception ex) {
            fail("Should raise a CCE for content with invalid entries " +
                 "instead of " + ex);
        }
        list.add(new TestUtils.MyOwnXMLStructure());
        try {
            prop = factory.newSignatureProperty(list, null, id);
            fail("Should raise a NPE for null target");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should raise a NPE for null target instead of " + ex);
        }

        prop = factory.newSignatureProperty(list, target, id);
        assertNotNull(prop);
        @SuppressWarnings("unchecked")
        List<XMLStructure> unmodifiable = prop.getContent();
        assertNotNull(unmodifiable);
        try {
            unmodifiable.add(new TestUtils.MyOwnXMLStructure());
            fail("Should return an unmodifiable List object");
        } catch (UnsupportedOperationException uoe) {}
        assertArrayEquals(unmodifiable.toArray(), list.toArray());
        assertEquals(prop.getTarget(), target);
        assertEquals(prop.getId(), id);
        assertNotNull(prop);
    }

    @Test
    public void testisFeatureSupported() {
        List<XMLStructure> list = new ArrayList<>();
        list.add(new TestUtils.MyOwnXMLStructure());
        SignatureProperty prop = factory.newSignatureProperty
            (list, target, id);
        try {
            prop.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(prop.isFeatureSupported("not supported"));
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }
}
