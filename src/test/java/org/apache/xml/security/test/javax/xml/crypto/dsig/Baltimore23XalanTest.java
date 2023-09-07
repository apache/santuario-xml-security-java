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
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;

import javax.xml.crypto.URIDereferencer;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This is a testcase to validate all "merlin-xmldsig-twenty-three"
 * testcases from Baltimore. These tests require Xalan for the here() function.
 *
 */
class Baltimore23XalanTest {

    private static final String CONFIG_FILE = "config-xalan.xml";

    private final File dir;
    private final URIDereferencer ud;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.resource.config", CONFIG_FILE);
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.resource.config");
    }

    public Baltimore23XalanTest() {
        dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples",
            "merlin-xmldsig-twenty-three");
        ud = new LocalHttpCacheURIDereferencer();
    }

    @Test
    void test_signature() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        String file = "signature.xml";
        File keystore = XmlSecTestEnvironment.resolveFile(dir.toPath(), "certs", "xmldsig.jks");
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystore), "changeit".toCharArray());

        SignatureValidator validator = new SignatureValidator(dir);
        boolean cv = validator.validate(file, new X509KeySelector(ks, false), ud);
        assertTrue(cv, "Signature failed core validation");
    }

}