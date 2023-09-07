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
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.XMLObject
 *
 */
class XMLObjectTest {

    private static final String id = "id";
    private static final String mimeType = "mime";
    private static final String encoding = "encoding";
    private final XMLSignatureFactory factory;

    public XMLObjectTest() throws Exception {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @SuppressWarnings("unchecked") // important for the test
    @Test
    void testConstructor() {
        // test XMLSignatureFactory.newXMLObject(List, String, String, String)
        XMLObject obj;

        obj = factory.newXMLObject(null, null, null, null);
        assertNotNull(obj);

        List<XMLStructure> list = new ArrayList<>();
        obj = factory.newXMLObject(list, null, null, null);
        assertNotNull(obj);

        String strEntry = "wrong type";
        // use raw List type to test for invalid XMLStructure entries
        @SuppressWarnings("rawtypes")
        List invalidList = new ArrayList();
        addEntryToRawList(invalidList, strEntry);
        try {
            factory.newXMLObject(invalidList, null, null, null);
            fail("Should raise a ClassCastException for content containing " +
                 "invalid, i.e. non-XMLStructure, entries");
        } catch (ClassCastException cce) {
        } catch (Exception ex) {
            fail("Should raise a ClassCastException for content with invalid entries " +
                 "instead of " + ex);
        }
        list.add(new TestUtils.MyOwnXMLStructure());
        obj = factory.newXMLObject(list, id, mimeType, encoding);
        assertNotNull(obj);
        assertNotNull(obj.getContent());
        assertArrayEquals(obj.getContent().toArray(), list.toArray());
        assertEquals(obj.getId(), id);
        assertEquals(obj.getMimeType(), mimeType);
        assertEquals(obj.getEncoding(), encoding);

        List<XMLStructure> unmodifiable = obj.getContent();
        try {
            unmodifiable.add(new TestUtils.MyOwnXMLStructure());
            fail("Should return an unmodifiable List object");
        } catch (UnsupportedOperationException uoe) {}
        assertArrayEquals(unmodifiable.toArray(), list.toArray());
    }

    @Test
    void testIsFeatureSupported() {
        List<XMLStructure> list = new ArrayList<>();
        list.add(new TestUtils.MyOwnXMLStructure());
        XMLObject obj = factory.newXMLObject(list, id, mimeType, encoding);
        try {
            obj.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {
            // ok
        }

        assertFalse(obj.isFeatureSupported("not supported"));
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }
}
