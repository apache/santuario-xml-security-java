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
package javax.xml.crypto.test.dsig;

import java.util.*;
import javax.xml.crypto.dsig.*;

/**
 * Unit test for javax.xml.crypto.dsig.SignatureProperties
 *
 * @author Valerie Peng
 */
public class SignaturePropertiesTest extends org.junit.Assert {

    private XMLSignatureFactory factory;
    private String id = "id";
    private SignatureProperty prop;

    public SignaturePropertiesTest() throws Exception {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        prop = factory.newSignatureProperty
            (Collections.singletonList(new TestUtils.MyOwnXMLStructure()),
             "propTarget", "propId");
    }

    @SuppressWarnings("rawtypes")
    @org.junit.Test
    public void testConstructor() {
        // test XMLSignatureFactory.newSignatureProperties(List, String)
        SignatureProperties props;

        try {
            props = factory.newSignatureProperties(null, id);
            fail("Should raise a NPE for null content");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should raise a NPE for null content instead of " + ex);
        }

        List<SignatureProperty> list = new ArrayList<SignatureProperty>();
        try {
            props = factory.newSignatureProperties(list, id);
            fail("Should raise an IAE for empty content");
        } catch (IllegalArgumentException iae) {
        } catch (Exception ex) {
            fail("Should raise an IAE for empty content instead of " + ex);
        }

        String strEntry = "wrong type";
        // use raw List type to test for invalid SignatureProperty types
        List invalidList = new ArrayList();
        addEntryToRawList(invalidList, strEntry);
        try {
            factory.newSignatureProperties(invalidList, id);
            fail("Should raise a CCE for content containing " +
                 "invalid, i.e. non-SignatureProperty, entries");
        } catch (ClassCastException cce) {
            // cce.printStackTrace();
        } catch (Exception ex) {
            fail("Should raise a CCE for content with invalid entries " +
                 "instead of " + ex);
        }

        list.add(prop);
        props = factory.newSignatureProperties(list, id);
        assertNotNull(props);
        @SuppressWarnings("unchecked")
        List<SignatureProperty> unmodifiable = props.getProperties();
        assertNotNull(unmodifiable);
        try {
            unmodifiable.add(prop);
            fail("Should return an unmodifiable List object");
        } catch (UnsupportedOperationException uoe) {}
        assertTrue(Arrays.equals(unmodifiable.toArray(), list.toArray()));
        assertNotNull(props);
        assertEquals(props.getId(), id);
    }

    @org.junit.Test
    public void testisFeatureSupported() {
        List<SignatureProperty> list = new ArrayList<SignatureProperty>();
        list.add(prop);
        SignatureProperties props = factory.newSignatureProperties(list, id);
        try {
            props.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertTrue(!props.isFeatureSupported("not supported"));
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }
}
