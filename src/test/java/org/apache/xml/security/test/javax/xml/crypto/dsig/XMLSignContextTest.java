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

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.XMLSignContext
 *
 */
class XMLSignContextTest {

    private final XMLSignContext defContext;
    private final Key[] KEYS;
    private final Document doc;

    public XMLSignContextTest() throws Exception {
        // set up the signingKeys
        KEYS = new Key[3];
        KEYS[0] = TestUtils.getPrivateKey("DSA");
        KEYS[1] = TestUtils.getPrivateKey("RSA");
        KEYS[2] = new SecretKeySpec(new byte[16], "HmacSHA1");
        // set up the default XMLSignContext
        SecretKey sk = new SecretKeySpec(new byte[8], "DES");
        doc = TestUtils.newDocument();
        defContext = new DOMSignContext(sk, doc);
    }

    @Test
    void testsetngetBaseURI() throws Exception {
        assertNull(defContext.getBaseURI());

        String uri = "http://www.w3.org/2000/09/xmldsig#";
        defContext.setBaseURI(uri);
        assertEquals(defContext.getBaseURI(), uri);
        defContext.setBaseURI(null);
        assertNull(defContext.getBaseURI());
    }


    @Test
    void testsetngetProperty() throws Exception {
        String name = "key";
        assertNull(defContext.getProperty(name));
        try {
            defContext.setProperty(null, null);
            fail("Should raise a NPE with a null name");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should raise a NPE instead of " + ex);
        }
        String value1 = "value#1";
        String value2 = "value#2";
        assertNull(defContext.setProperty(name, value1));
        assertEquals(defContext.getProperty(name), value1);
        assertEquals(defContext.setProperty(name, value2), value1);
        assertEquals(defContext.getProperty(name), value2);
        assertEquals(defContext.setProperty(name, null), value2);
        assertNull(defContext.getProperty(name));
    }

    @Test
    void testsetngetURIDereferencer() throws Exception {
        assertNull(defContext.getURIDereferencer());
        byte[] data = "simpleDereferencer".getBytes();
        URIDereferencer deref = new TestUtils.OctetStreamURIDereferencer(data);

        defContext.setURIDereferencer(deref);
        assertEquals(defContext.getURIDereferencer(), deref);
        defContext.setURIDereferencer(null);
        assertNull(defContext.getURIDereferencer());
    }

    @Test
    void testsetngetKeySelector() throws Exception {
        defContext.setKeySelector(null);
        assertNull(defContext.getKeySelector());
        KeySelector ks = KeySelector.singletonKeySelector(KEYS[0]);
        defContext.setKeySelector(ks);
        assertEquals(defContext.getKeySelector(), ks);
    }
}