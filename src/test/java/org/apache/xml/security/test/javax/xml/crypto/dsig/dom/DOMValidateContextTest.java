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
package org.apache.xml.security.test.javax.xml.crypto.dsig.dom;


import java.io.File;

import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.dsig.TestUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.dom.DOMValidateContext
 *
 */
class DOMValidateContextTest {
    private final DOMValidateContext domVC;

    public DOMValidateContextTest() throws Exception {
        File dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples",
            "merlin-xmldsig-twenty-three");
        File input = new File(dir, "signature.xml");
        domVC = (DOMValidateContext) TestUtils.getXMLValidateContext("DOM", input, "Reference");
    }

    @Test
    void testConstructor() throws Exception {
        assertNotNull(domVC);
        try {
            new DOMValidateContext(TestUtils.getPublicKey("RSA"), null);
            fail("Should throw a NPE for null node");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should throw a NPE instead of " + ex + " for null node");
        }
    }

    @Test
    void testSetGetProperty() throws Exception {
        try {
            domVC.setProperty(null, "value");
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should throw a NPE instead of " + ex + " for null name");
        }
        try {
            domVC.getProperty(null);
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should throw a NPE instead of " + ex + " for null name");
        }
        String pname = "name";
        String pvalue1 = "value";
        String pvalue2 = "newvalue";
        assertNull(domVC.setProperty(pname, pvalue1));
        assertEquals(domVC.getProperty(pname), pvalue1);
        assertEquals(domVC.setProperty(pname, pvalue2), pvalue1);
        assertEquals(domVC.getProperty(pname), pvalue2);
    }

    @Test
    void testSetGetNode() throws Exception {
        try {
            domVC.setNode(null);
        } catch (NullPointerException npe) {
        } catch (Exception ex) {
            fail("Should throw a NPE instead of " + ex + " for null node");
        }
        assertNotNull(domVC.getNode());
    }

}