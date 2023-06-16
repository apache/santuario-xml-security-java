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


import java.math.BigInteger;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.Collections;

import javax.xml.crypto.NoSuchMechanismException;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.PGPData;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.keyinfo.KeyInfoFactory
 *
 */
public class KeyInfoFactoryTest {

    KeyInfoFactory factory;

    public KeyInfoFactoryTest() throws Exception {
        factory = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @Test
    public void testgetInstance() {
        try {
            KeyInfoFactory.getInstance("non-existent");
            fail("Should throw NoSuchMechanismException if no impl found");
        } catch (NoSuchMechanismException ex) {}

        try {
            KeyInfoFactory.getInstance(null);
            fail("Should raise a NPE for null xmltype");
        } catch (NullPointerException npe) {}
    }

    @Test
    public void testgetMechanismType() {
        assertNotNull(factory);
        assertEquals("DOM", factory.getMechanismType());
    }

    @Test
    public void testisFeatureSupported() {
        try {
            factory.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(factory.isFeatureSupported("not supported"));
    }

    @Test
    public void testnewKeyInfo() {
        String id = "keyId";
        // test newKeyInfo(List, String)
        KeyInfo ki = factory.newKeyInfo
            (Collections.singletonList(factory.newKeyName("foo")), id);
        assertEquals(id, ki.getId());
        try {
            ki = factory.newKeyInfo(null, id);
            fail("Should raise a NPE for null key info types");
        } catch (NullPointerException npe) {}
    }

    @Test
    public void testnewKeyName() {
        final String name = "keyName";
        KeyName kn = factory.newKeyName(name);
        assertEquals(name, kn.getName());
        try {
            kn = factory.newKeyName(null);
            fail("Should raise a NPE for null key name");
        } catch (NullPointerException npe) {}
    }

    @Test
    public void testnewKeyValue() {
        // test newKeyValue(PublicKey pk)
        PublicKey myPubKey = new PublicKey() {
            private static final long serialVersionUID = 2756606866185189114L;

                @Override
                public byte[] getEncoded() {
                    return new byte[20];
                }
                @Override
                public String getFormat() {
                    return "none";
                }
                @Override
                public String getAlgorithm() {
                    return "test";
                }
            };
        try {
            KeyValue kv = factory.newKeyValue(myPubKey);
            assertEquals(myPubKey, kv.getPublicKey());
            fail("Should throw a KeyException");
        } catch (KeyException ke) { }

        try {
            factory.newKeyValue(null);
            fail("Should raise a NPE for null key");
        } catch (KeyException ke) {
            fail("Should raise a NPE for null key");
        } catch (NullPointerException npe) {}
    }

    @Test
    public void testnewPGPKeyId() {
        byte[] valid_id = {
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        };
        byte[] invalid_id = {
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09
        };
        byte[] valid_packet = { (byte)0xc6, (byte)0x01, (byte)0x00 };
        byte[] invalid_packet = { (byte)0xc8, (byte)0x01, (byte)0x00 };

        // test newPGPData(byte[])
        PGPData pd = factory.newPGPData(valid_id);
        assertArrayEquals(valid_id, pd.getKeyId());
        try {
            pd = factory.newPGPData(invalid_id);
            fail("Should throw IAE for invalid key id values");
        } catch (IllegalArgumentException ex) {}

        // test newPGPData(byte[], byte[], List)
        pd = factory.newPGPData(valid_id, valid_packet, null);
        assertArrayEquals(valid_id, pd.getKeyId());
        assertArrayEquals(valid_packet, pd.getKeyPacket());
        try {
            pd = factory.newPGPData(invalid_id, valid_packet, null);
            fail("Should throw IAE for invalid key id values");
        } catch (IllegalArgumentException ex) {}
        try {
            pd = factory.newPGPData(valid_id, invalid_packet, null);
            fail("Should throw IAE for invalid key packet values");
        } catch (IllegalArgumentException ex) {}
        try {
            pd = factory.newPGPData(invalid_id, invalid_packet, null);
            fail("Should throw IAE for invalid key id and packet values");
        } catch (IllegalArgumentException ex) {}

        // test newPGPData(byte[], List)
        pd = factory.newPGPData(valid_packet, null);
        assertArrayEquals(valid_packet, pd.getKeyPacket());
        try {
            pd = factory.newPGPData(invalid_packet, null);
            fail("Should throw IAE for invalid key packet values");
        } catch (IllegalArgumentException ex) {}
    }

    @Test
    public void testnewRetrievalMethod() throws Exception {
        final String uri = "#X509CertChain";
        // test RetrievalMethod(String)
        RetrievalMethod rm = factory.newRetrievalMethod(uri);
        assertEquals(uri, rm.getURI());

        try {
            rm = factory.newRetrievalMethod(null);
            fail("Should raise a NPE for null URI");
        } catch (NullPointerException npe) {}

        // test RetrievalMethod(String, String, List)
        try {
            rm = factory.newRetrievalMethod(null, null, null);
            fail("Should raise a NPE for null URI");
        } catch (NullPointerException npe) {}

        String type = "http://www.w3.org/2000/09/xmldsig#X509Data";
        try {
            rm = factory.newRetrievalMethod(null, type, null);
            fail("Should raise a NPE for null URI");
        } catch (NullPointerException npe) {}

        rm = factory.newRetrievalMethod(uri, type, null);
        assertEquals(uri, rm.getURI());
        assertEquals(type, rm.getType());
    }

    @Test
    public void testnewX509Data() {
        // test newX509Data(List)
        X509Data x509 =
            factory.newX509Data(Collections.singletonList("cn=foo"));
        assertNotNull(x509);
    }

    @Test
    public void testnewX509IssuerSerial() {
        String name = "CN=valeriep";
        // test newX509IssuerSerial(String, BigInteger)
        X509IssuerSerial x509is = factory.newX509IssuerSerial(name,
                                                              BigInteger.ONE);
        assertEquals(name, x509is.getIssuerName());
        assertEquals(BigInteger.ONE, x509is.getSerialNumber());
        try {
            x509is = factory.newX509IssuerSerial(null, BigInteger.ZERO);
            fail("Should raise an NPE for null issuer names");
        } catch (NullPointerException ex) {
        } catch (IllegalArgumentException ex2) {
            fail("Should throw NPE instead of IAE for null issuer names");
        }
        try {
            x509is = factory.newX509IssuerSerial(name, null);
            fail("Should raise an NPE for null serial numbers");
        } catch (NullPointerException ex) {
        } catch (IllegalArgumentException ex2) {
            fail("Should throw NPE instead of IAE for null serial numbers");
        }
        try {
            x509is = factory.newX509IssuerSerial(null, null);
            fail("Should raise an NPE for null issuer names/serial numbers");
        } catch (NullPointerException ex) {
        } catch (IllegalArgumentException ex2) {
            fail("Should throw NPE instead of IAE for null issuer " +
                 "names/serial numbers");
        }
        try {
            x509is = factory.newX509IssuerSerial("valeriep", BigInteger.ZERO);
            fail("Should throw IAE for invalid issuer names");
        } catch (IllegalArgumentException ex) {}
    }

}
