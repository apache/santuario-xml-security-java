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


import java.io.File;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NoSuchMechanismException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.XMLSignatureFactory
 *
 */
class XMLSignatureFactoryTest {

    XMLSignatureFactory factory;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public XMLSignatureFactoryTest() throws Exception {
        factory = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @Test
    void testgetInstance() {
        try {
            XMLSignatureFactory.getInstance("non-existent");
            fail("Should throw NoSuchMechanismException if no impl found");
        } catch (NoSuchMechanismException ex) {}

        try {
            XMLSignatureFactory.getInstance(null);
            fail("Should raise a NPE for null mechanismType");
        } catch (NullPointerException npe) {}

        try {
            XMLSignatureFactory.getInstance("DOM", "non-existent");
            fail("Should throw NoSuchProviderException if specified " +
                 "provider is not found");
        } catch (NoSuchProviderException nspe) {
        } catch (NoSuchMechanismException nse) {
            fail("Should raise a NoSuchProviderException instead of " + nse +
                 " if specified provider is not found");
        }

        try {
            XMLSignatureFactory.getInstance(null);
            fail("Should raise a NPE for null mechanismType");
        } catch (NullPointerException npe) {}

        try {
            XMLSignatureFactory.getInstance("DOM", (Provider) null);
            fail("Should raise a NPE for null provider");
        } catch (NullPointerException npe) {}
    }

    @Test
    void testgetMechanismType() {
        assertNotNull(factory);
        assertEquals("DOM", factory.getMechanismType());
    }

    @Test
    void testisFeatureSupported() {
        try {
            factory.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(factory.isFeatureSupported("not supported"));
    }

    @Test
    void testgetKeyInfoFactory() throws Exception {
        KeyInfoFactory kifac = factory.getKeyInfoFactory();
        assertEquals(kifac.getMechanismType(), factory.getMechanismType());
        assertEquals(kifac.getProvider(), factory.getProvider());
    }

    @Test
    void testunmarshalXMLSignature() throws Exception {
        XMLSignature stuff;
        try {
            stuff = factory.unmarshalXMLSignature((XMLValidateContext) null);
            fail("Should raise an NPE for null inputs");
        } catch (NullPointerException ex) {
        } catch (Exception ex) {
            fail("Should throw an NPE instead of " + ex +
                 " for null inputs");
        }

        try {
            stuff = factory.unmarshalXMLSignature(
                new XMLValidateContext() {
                    @Override
                    public Object getProperty(String name) { return null; }
                    @Override
                    public Object setProperty(String name, Object property) {
                        return null;
                    }
                    @Override
                    public String getBaseURI()	{ return null; }
                    @Override
                    public void setBaseURI(String uri)	{ }
                    @Override
                    public KeySelector getKeySelector() { return null; }
                    @Override
                    public void setKeySelector(KeySelector ks) { }
                    @Override
                    public URIDereferencer getURIDereferencer() { return null; }
                    @Override
                    public void setURIDereferencer(URIDereferencer ud) {}
                    @Override
                    public Object get(Object key) {return null;}
                    @Override
                    public Object put(Object key, Object value) {return null;}
                    @Override
                    public void setDefaultNamespacePrefix(String defPrefix) {}
                    @Override
                    public String getDefaultNamespacePrefix() {return null;}
                    @Override
                    public String putNamespacePrefix
                        (String nsURI, String prefix) {return null;}
                    @Override
                    public String getNamespacePrefix
                        (String nsURI, String defPrefix) {return null;}
                    });
            fail("Should throw a CCE for input of wrong type");
        } catch (ClassCastException ex) {
        } catch (Exception ex) {
            fail("Should raise a CCE instead of " + ex + " for wrong inputs");
        }

        File dir = resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples", "merlin-xmldsig-twenty-three");
        Document doc = XMLUtils.read(new File(dir, "signature.xml"), false);
        NodeList nl = doc.getElementsByTagName("KeyInfo");
        try {
            stuff = factory.unmarshalXMLSignature
            (new DOMValidateContext(TestUtils.getPublicKey("RSA"), nl.item(0)));
            fail("Should throw a MarshalException for non-XMLSignature inputs");
        } catch (MarshalException ex) {}

        nl = doc.getElementsByTagName("Signature");
        try {
            stuff = factory.unmarshalXMLSignature
            (new DOMValidateContext(TestUtils.getPublicKey("DSA"), nl.item(0)));
            assertNotNull(stuff);
        } catch (MarshalException ex) {
            fail("Unmarshal failed: " + ex.getMessage());
        }
    }

}
