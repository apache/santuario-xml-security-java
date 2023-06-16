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
import java.security.Security;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This is a testcase to validate all "phaos-xmldsig-three"
 * testcases from Phaos, that require Xalan for the here() function
 *
 */
class PhaosXMLDSig3XalanTest {

    private static final String CONFIG_FILE = "/config-xalan.xml";

    private final SignatureValidator validator;
    private final File base;

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

    public PhaosXMLDSig3XalanTest() {
        base = resolveFile("src", "test", "resources", "com", "phaos", "phaos-xmldsig-three");
        validator = new SignatureValidator(base);
    }

    @Test
    void test_signature_rsa_xpath_transform_enveloped() throws Exception {
        String file = "signature-rsa-xpath-transform-enveloped.xml";
        boolean coreValidity = validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }
}